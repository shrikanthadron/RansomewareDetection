"""Safe file quarantine and restoration service with path validation and SHA-256 verification."""

from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import shutil
import uuid
from typing import Optional
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.operations import AdminLog, QuarantineRecord

# Critical OS directories that must NEVER be quarantined
FORBIDDEN_PATH_PREFIXES_WIN = (
    "c:\\windows",
    "c:\\program files\\windows",
    "c:\\programdata\\microsoft\\windows",
)
FORBIDDEN_PATH_PREFIXES_POSIX = (
    "/bin",
    "/sbin",
    "/usr/bin",
    "/usr/sbin",
    "/lib",
    "/lib64",
    "/etc",
    "/boot",
    "/sys",
    "/proc",
)


def _sha256_of_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def is_critical_system_path(target: Path) -> bool:
    resolved = str(target.resolve())
    lower = resolved.lower()
    if os.name == "nt":
        return any(lower.startswith(prefix) for prefix in FORBIDDEN_PATH_PREFIXES_WIN)
    return any(lower == prefix or lower.startswith(prefix + "/") for prefix in FORBIDDEN_PATH_PREFIXES_POSIX)


def quarantine_file(
    db: Session,
    target_path_str: str,
    actor_user_id: uuid.UUID,
    scan_id: Optional[uuid.UUID] = None,
    expected_sha256: Optional[str] = None,
    ip_address: Optional[str] = None,
) -> QuarantineRecord:
    """Safely move a validated non-system file into the isolated quarantine directory."""
    if not target_path_str or ".." in Path(target_path_str).parts:
        raise ValueError("Invalid file path provided for quarantine.")

    target = Path(target_path_str).resolve()
    if not target.exists() or not target.is_file():
        raise FileNotFoundError("Target file does not exist or is not a regular file.")

    if is_critical_system_path(target):
        raise PermissionError("Quarantine blocked: critical operating system files cannot be quarantined.")

    actual_hash = _sha256_of_file(target)
    if expected_sha256 and actual_hash.lower() != expected_sha256.lower():
        raise ValueError("SHA-256 hash mismatch detected prior to quarantine; operation aborted.")

    settings.ensure_storage_dirs()
    quarantine_filename = f"{uuid.uuid4().hex}_{actual_hash[:12]}.qtn"
    dest = (settings.quarantine_dir / quarantine_filename).resolve()

    # Ensure destination strictly stays within quarantine_dir
    if settings.quarantine_dir.resolve() not in dest.parents:
        raise PermissionError("Path traversal prevented in quarantine destination.")

    shutil.move(str(target), str(dest))

    record = QuarantineRecord(
        scan_id=scan_id,
        original_path=str(target),
        quarantine_path=str(dest),
        sha256_hash=actual_hash,
        quarantine_status="QUARANTINED",
        created_by=actor_user_id,
    )
    db.add(record)
    db.add(
        AdminLog(
            admin_id=actor_user_id,
            action="FILE_QUARANTINED",
            details=f"Quarantined '{target}' -> '{dest}' (sha256={actual_hash})",
            ip_address=ip_address,
        )
    )
    db.commit()
    db.refresh(record)
    return record


def restore_quarantined_file(
    db: Session,
    record_id: uuid.UUID,
    actor_user_id: uuid.UUID,
    ip_address: Optional[str] = None,
) -> QuarantineRecord:
    """Verify SHA-256 integrity and restore a quarantined file to its original safe path."""
    record = db.get(QuarantineRecord, record_id)
    if not record:
        raise FileNotFoundError("Quarantine record not found.")
    if record.quarantine_status != "QUARANTINED":
        raise ValueError(f"Record cannot be restored from status '{record.quarantine_status}'.")

    q_path = Path(record.quarantine_path).resolve()
    orig_path = Path(record.original_path).resolve()

    if settings.quarantine_dir.resolve() not in q_path.parents or not q_path.exists():
        raise FileNotFoundError("Quarantined artifact file is missing from vault.")
    if is_critical_system_path(orig_path):
        raise PermissionError("Cannot restore directly into protected system directory.")

    actual_hash = _sha256_of_file(q_path)
    if actual_hash.lower() != record.sha256_hash.lower():
        raise ValueError("Integrity verification failed: quarantined file hash does not match record.")

    orig_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(q_path), str(orig_path))

    record.quarantine_status = "RESTORED"
    record.restored_at = datetime.now(timezone.utc)
    db.add(
        AdminLog(
            admin_id=actor_user_id,
            action="FILE_RESTORED",
            details=f"Restored quarantine record {record.id} to '{orig_path}'",
            ip_address=ip_address,
        )
    )
    db.commit()
    db.refresh(record)
    return record
