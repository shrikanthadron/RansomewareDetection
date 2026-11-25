"""Opt-in, read-only Windows-focused process monitoring service using psutil.

Transparency & Safety Guarantees:
- Never starts automatically; requires explicit user/admin activation.
- Never pretends psutil alone captures kernel API hooks, registry writes, or file-system I/O.
- Protects critical Windows/POSIX system processes from termination or quarantine.
"""

from datetime import datetime, timezone
import hashlib
import logging
import os
from pathlib import Path
import platform
import threading
import time
from typing import Any, Dict, List, Optional
import uuid

import psutil
from sqlalchemy.orm import Session

from app.core.database import SessionLocal
from app.models.operations import AdminLog, Alert, ProcessMonitoringLog
from app.services.pe_extractor import extract_static_pe_features
from app.services.quarantine_service import is_critical_system_path, quarantine_file
from app.services.risk_engine import classify_risk_level, classify_verdict
from app.services.ws_manager import ws_manager

logger = logging.getLogger(__name__)

PROTECTED_PROCESS_NAMES = {
    "system", "system idle process", "registry", "smss.exe", "csrss.exe",
    "wininit.exe", "services.exe", "lsass.exe", "svchost.exe", "winlogon.exe",
    "dwm.exe", "explorer.exe", "memory compression", "systemd", "init",
}

SUSPICIOUS_PATH_KEYWORDS = ("\\temp\\", "\\appdata\\local\\temp\\", "/tmp/", "/dev/shm/")


class ProcessMonitorManager:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._started_at: Optional[datetime] = None
        self._started_by: Optional[str] = None
        self._poll_interval_sec = 5.0
        self._latest_processes: List[Dict[str, Any]] = []
        self._hash_cache: Dict[str, tuple[float, str]] = {}
        self._pe_risk_cache: Dict[str, tuple[float, float, List[str]]] = {}

    def platform_info(self) -> Dict[str, Any]:
        sys_name = platform.system()
        is_windows = sys_name.lower() == "windows"
        is_container = Path("/.dockerenv").exists()
        limitations = [
            "psutil provides read-only user-space process metadata (PID, path, CPU/RAM, parent PID) and optional binary hashing.",
            "psutil alone cannot intercept kernel syscalls, API hooking, registry edits, or live file-encryption I/O (requires ETW/MiniFilter drivers).",
        ]
        if not is_windows:
            limitations.append(
                f"Currently running on {sys_name}"
                + (" inside a Docker container" if is_container else "")
                + ": monitoring observes container/host processes visible to this environment rather than native Windows host telemetry."
            )
        return {
            "platform": sys_name,
            "release": platform.release(),
            "is_windows": is_windows,
            "is_container": is_container,
            "supported": True,
            "limitations": limitations,
        }

    def status(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "is_running": self._running,
                "started_at": self._started_at.isoformat() if self._started_at else None,
                "started_by": self._started_by,
                "poll_interval_sec": self._poll_interval_sec,
                "observed_process_count": len(self._latest_processes),
                "platform": self.platform_info(),
            }

    def latest_snapshot(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._latest_processes)

    def start(self, user_email: str, poll_interval_sec: float = 5.0) -> Dict[str, Any]:
        with self._lock:
            if self._running:
                return self.status()
            self._stop_event.clear()
            self._running = True
            self._started_at = datetime.now(timezone.utc)
            self._started_by = user_email
            self._poll_interval_sec = max(2.0, min(30.0, poll_interval_sec))
            self._thread = threading.Thread(target=self._run_loop, daemon=True, name="RansomShieldMonitor")
            self._thread.start()
        return self.status()

    def stop(self) -> Dict[str, Any]:
        with self._lock:
            if not self._running:
                return self.status()
            self._stop_event.set()
            self._running = False
        return self.status()

    def _safe_sha256(self, exe_path: Optional[str]) -> Optional[str]:
        if not exe_path:
            return None
        p = Path(exe_path)
        try:
            if not p.is_file():
                return None
            stat = p.stat()
            if stat.st_size > 35 * 1024 * 1024:
                return None  # Avoid blocking monitor loop on huge binaries
            cached = self._hash_cache.get(exe_path)
            if cached and cached[0] == stat.st_mtime:
                return cached[1]
            h = hashlib.sha256()
            with open(p, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            digest = h.hexdigest()
            self._hash_cache[exe_path] = (stat.st_mtime, digest)
            return digest
        except (PermissionError, OSError):
            return None

    def _score_process(self, info: Dict[str, Any]) -> tuple[float, str, List[str]]:
        score = 0.0
        reasons: List[str] = []
        name_lower = (info.get("name") or "").lower()
        exe_lower = (info.get("exe") or "").lower()
        cpu = float(info.get("cpu_percent") or 0.0)

        if name_lower in PROTECTED_PROCESS_NAMES or info.get("pid") in (0, 4):
            return 0.0, "BENIGN", ["Protected operating system process"]

        if exe_lower and any(k in exe_lower for k in SUSPICIOUS_PATH_KEYWORDS):
            score += 42.0
            reasons.append("Executable launched from temporary/user-writable directory")

        if info.get("exe") and not is_critical_system_path(Path(info["exe"])):
            # Non-system binary with unusual high sustained CPU spike
            if cpu >= 75.0:
                score += 20.0
                reasons.append(f"Elevated CPU utilization ({cpu:.1f}%)")
            # Quick static check on PE if accessible & <= 10 MB (cached by mtime)
            try:
                p = Path(info["exe"])
                is_prog_files = "program files" in exe_lower
                if not is_prog_files and p.is_file() and p.suffix.lower() in (".exe", ".dll") and p.stat().st_size <= 10 * 1024 * 1024:
                    mtime = p.stat().st_mtime
                    cached_pe = self._pe_risk_cache.get(info["exe"])
                    if cached_pe and cached_pe[0] == mtime:
                        score += cached_pe[1]
                        reasons.extend(cached_pe[2])
                    else:
                        pe_score = 0.0
                        pe_reasons: List[str] = []
                        static = extract_static_pe_features(p)
                        ent = float(static["features"].get("file_entropy", 0.0))
                        wx = int(static["features"].get("wx_sections", 0))
                        crypto = int(static["features"].get("crypto_api_count", 0))
                        if ent >= 7.2:
                            pe_score += 22.0
                            pe_reasons.append(f"High binary entropy ({ent:.2f})")
                        if wx > 0:
                            pe_score += 18.0
                            pe_reasons.append(f"Contains {wx} W+X PE section(s)")
                        if crypto >= 2:
                            pe_score += 14.0
                            pe_reasons.append(f"Imports {crypto} cryptographic API(s)")
                        self._pe_risk_cache[info["exe"]] = (mtime, pe_score, pe_reasons)
                        score += pe_score
                        reasons.extend(pe_reasons)
            except Exception:
                pass
        elif not info.get("exe"):
            reasons.append("Executable path unavailable (insufficient privilege or kernel thread)")

        bounded = round(min(100.0, score), 2)
        verdict = classify_verdict(bounded)
        return bounded, verdict, reasons

    def collect_once(self, persist_notable: bool = True) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        now = datetime.now(timezone.utc)
        for proc in psutil.process_iter(attrs=["pid", "ppid", "name", "exe", "username", "create_time", "cpu_percent", "memory_percent"]):
            try:
                info = proc.info
                pid = int(info["pid"])
                name = str(info.get("name") or "unknown")
                exe = info.get("exe")
                sha256 = self._safe_sha256(exe)
                risk_score, classification, reasons = self._score_process(info)
                protected = (
                    pid in (0, 4)
                    or name.lower() in PROTECTED_PROCESS_NAMES
                    or (bool(exe) and is_critical_system_path(Path(exe)))
                )
                entry = {
                    "pid": pid,
                    "ppid": info.get("ppid"),
                    "process_name": name,
                    "executable_path": exe,
                    "username": info.get("username"),
                    "cpu_percent": round(float(info.get("cpu_percent") or 0.0), 2),
                    "memory_percent": round(float(info.get("memory_percent") or 0.0), 2),
                    "sha256_hash": sha256,
                    "risk_score": risk_score,
                    "risk_level": classify_risk_level(risk_score),
                    "classification": classification,
                    "reasons": reasons,
                    "is_protected": protected,
                    "timestamp": now.isoformat(),
                }
                results.append(entry)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        # Sort highest risk first, then CPU
        results.sort(key=lambda x: (x["risk_score"], x["cpu_percent"]), reverse=True)
        limited = results[:120]

        with self._lock:
            self._latest_processes = limited

        if persist_notable:
            notable = [r for r in limited if r["risk_score"] >= 35.0][:10]
            if notable:
                db = SessionLocal()
                try:
                    for item in notable:
                        action = "ALERT" if item["risk_score"] >= 68.0 else "FLAG"
                        db.add(
                            ProcessMonitoringLog(
                                process_name=item["process_name"],
                                process_id=item["pid"],
                                executable_path=item["executable_path"],
                                sha256_hash=item["sha256_hash"],
                                risk_score=item["risk_score"],
                                classification=item["classification"],
                                detection_source="PSUTIL_STATIC_TELEMETRY",
                                action_taken=action,
                                metadata_json={
                                    "ppid": item["ppid"],
                                    "cpu_percent": item["cpu_percent"],
                                    "memory_percent": item["memory_percent"],
                                    "reasons": item["reasons"],
                                },
                            )
                        )
                        if item["risk_score"] >= 68.0:
                            db.add(
                                Alert(
                                    alert_type="LIVE_PROCESS_ALERT",
                                    severity="HIGH",
                                    title=f"High-Risk Process Observed: {item['process_name']} (PID {item['pid']})",
                                    description="; ".join(item["reasons"]) or "Elevated static/path risk score.",
                                )
                            )
                    db.commit()
                except Exception as exc:
                    logger.warning("Failed persisting monitoring log: %s", exc)
                    db.rollback()
                finally:
                    db.close()

        ws_manager.broadcast_threadsafe({
            "type": "monitoring_snapshot",
            "timestamp": now.isoformat(),
            "processes": limited[:50],
        })
        return limited

    def _run_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                self.collect_once(persist_notable=True)
            except Exception as exc:
                logger.warning("Monitoring loop error: %s", exc)
            self._stop_event.wait(self._poll_interval_sec)

    def execute_process_action(
        self,
        db: Session,
        pid: int,
        action: str,
        actor_id: uuid.UUID,
        ip_address: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Execute user-confirmed action: FLAG, ALERT, TERMINATE, or QUARANTINE."""
        action_upper = action.upper()
        if action_upper not in {"FLAG", "ALERT", "TERMINATE", "QUARANTINE"}:
            raise ValueError("Unsupported process action.")

        try:
            proc = psutil.Process(pid)
            proc_name = proc.name()
            exe_path = proc.exe()
        except psutil.NoSuchProcess as exc:
            raise FileNotFoundError(f"Process PID {pid} is no longer running.") from exc
        except psutil.AccessDenied as exc:
            raise PermissionError(f"Access denied inspecting process PID {pid}.") from exc

        is_sys = (
            pid in (0, 4)
            or proc_name.lower() in PROTECTED_PROCESS_NAMES
            or (bool(exe_path) and is_critical_system_path(Path(exe_path)))
            or pid == os.getpid()
        )
        if action_upper in {"TERMINATE", "QUARANTINE"} and is_sys:
            raise PermissionError(
                f"Blocked: '{proc_name}' (PID {pid}) is a protected system or application process."
            )

        sha256 = self._safe_sha256(exe_path)
        detail_msg = f"Action {action_upper} performed on {proc_name} (PID {pid})"

        if action_upper == "TERMINATE":
            proc.terminate()
            proc.wait(timeout=3)
            detail_msg = f"User-approved termination of {proc_name} (PID {pid})"
        elif action_upper == "QUARANTINE":
            if not exe_path:
                raise ValueError("Cannot quarantine: executable path is unavailable.")
            # Terminate first if running so file lock on Windows is released
            proc.terminate()
            proc.wait(timeout=3)
            q_rec = quarantine_file(
                db=db,
                target_path_str=exe_path,
                actor_user_id=actor_id,
                expected_sha256=sha256,
                ip_address=ip_address,
            )
            detail_msg = f"Terminated PID {pid} and quarantined '{exe_path}' (record={q_rec.id})"

        db.add(
            ProcessMonitoringLog(
                process_name=proc_name,
                process_id=pid,
                executable_path=exe_path,
                sha256_hash=sha256,
                risk_score=75.0 if action_upper in {"TERMINATE", "QUARANTINE"} else 50.0,
                classification="SUSPICIOUS",
                detection_source="USER_ACTION",
                action_taken=action_upper,
            )
        )
        db.add(
            AdminLog(
                admin_id=actor_id,
                action=f"PROCESS_{action_upper}",
                details=detail_msg,
                ip_address=ip_address,
            )
        )
        db.commit()
        return {"status": "ok", "action": action_upper, "pid": pid, "detail": detail_msg}


process_monitor = ProcessMonitorManager()
