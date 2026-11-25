"""Safe quarantine and restoration endpoints."""

import uuid
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.api.deps import get_client_ip, get_current_user, require_admin
from app.core.database import get_db
from app.models.operations import QuarantineRecord
from app.models.scan import FileScan
from app.models.user import User
from app.schemas.common import QuarantineCreateRequest
from app.services.quarantine_service import quarantine_file, restore_quarantined_file

router = APIRouter(prefix="/api/quarantine", tags=["Quarantine"])


@router.get("")
def list_quarantine_records(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    q = db.query(QuarantineRecord)
    if current_user.role != "ADMIN":
        q = q.filter(QuarantineRecord.created_by == current_user.id)
    rows = q.order_by(QuarantineRecord.quarantined_at.desc()).all()
    return [
        {
            "id": str(r.id),
            "scan_id": str(r.scan_id) if r.scan_id else None,
            "original_path": r.original_path,
            "quarantine_path": r.quarantine_path,
            "sha256_hash": r.sha256_hash,
            "quarantine_status": r.quarantine_status,
            "quarantined_at": r.quarantined_at.isoformat(),
            "restored_at": r.restored_at.isoformat() if r.restored_at else None,
        }
        for r in rows
    ]


@router.post("/quarantine", status_code=status.HTTP_201_CREATED)
def quarantine_target(
    payload: QuarantineCreateRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    expected_sha = None
    target_path = payload.file_path
    if payload.scan_id:
        scan = db.get(FileScan, payload.scan_id)
        if not scan:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan record not found.")
        if current_user.role != "ADMIN" and scan.user_id != current_user.id:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied.")
        expected_sha = scan.sha256_hash
        if scan.file_path:
            target_path = scan.file_path

    try:
        rec = quarantine_file(
            db=db,
            target_path_str=target_path,
            actor_user_id=current_user.id,
            scan_id=payload.scan_id,
            expected_sha256=expected_sha,
            ip_address=get_client_ip(request),
        )
        return {
            "id": str(rec.id),
            "quarantine_status": rec.quarantine_status,
            "sha256_hash": rec.sha256_hash,
            "quarantined_at": rec.quarantined_at.isoformat(),
        }
    except FileNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.post("/{record_id}/restore")
def restore_target(
    record_id: uuid.UUID,
    request: Request,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    try:
        rec = restore_quarantined_file(
            db=db,
            record_id=record_id,
            actor_user_id=admin.id,
            ip_address=get_client_ip(request),
        )
        return {
            "id": str(rec.id),
            "quarantine_status": rec.quarantine_status,
            "restored_at": rec.restored_at.isoformat() if rec.restored_at else None,
        }
    except FileNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
