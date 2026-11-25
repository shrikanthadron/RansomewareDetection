"""Opt-in live process monitoring endpoints."""

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from app.api.deps import get_client_ip, get_current_user
from app.core.database import get_db
from app.models.operations import AdminLog, ProcessMonitoringLog
from app.models.user import User
from app.schemas.common import MonitoringStartRequest, ProcessActionRequest
from app.services.monitoring_service import process_monitor

router = APIRouter(prefix="/api/monitoring", tags=["Live Monitoring"])


@router.get("/status")
def get_monitoring_status(_user: User = Depends(get_current_user)):
    return process_monitor.status()


@router.post("/start")
def start_monitoring(
    payload: MonitoringStartRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    state = process_monitor.start(user_email=current_user.email, poll_interval_sec=payload.poll_interval_sec)
    db.add(
        AdminLog(
            admin_id=current_user.id,
            action="MONITORING_STARTED",
            details=f"Opt-in process monitoring started by {current_user.email} (interval={payload.poll_interval_sec}s).",
            ip_address=get_client_ip(request),
        )
    )
    db.commit()
    return state


@router.post("/stop")
def stop_monitoring(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    state = process_monitor.stop()
    db.add(
        AdminLog(
            admin_id=current_user.id,
            action="MONITORING_STOPPED",
            details=f"Process monitoring stopped by {current_user.email}.",
            ip_address=get_client_ip(request),
        )
    )
    db.commit()
    return state


@router.get("/processes")
def get_processes(
    refresh: bool = Query(False),
    _user: User = Depends(get_current_user),
):
    state = process_monitor.status()
    if refresh:
        procs = process_monitor.collect_once(persist_notable=state["is_running"])
    else:
        procs = process_monitor.latest_snapshot()
    return {"status": state, "processes": procs}


@router.get("/logs")
def get_monitoring_logs(
    limit: int = Query(50, ge=1, le=200),
    _user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    logs = (
        db.query(ProcessMonitoringLog)
        .order_by(ProcessMonitoringLog.timestamp.desc())
        .limit(limit)
        .all()
    )
    return [
        {
            "id": str(l.id),
            "process_name": l.process_name,
            "process_id": l.process_id,
            "executable_path": l.executable_path,
            "sha256_hash": l.sha256_hash,
            "risk_score": l.risk_score,
            "classification": l.classification,
            "detection_source": l.detection_source,
            "action_taken": l.action_taken,
            "metadata": l.metadata_json,
            "timestamp": l.timestamp.isoformat(),
        }
        for l in logs
    ]


@router.post("/processes/{pid}/action")
def act_on_process(
    pid: int,
    payload: ProcessActionRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if payload.action in ("TERMINATE", "QUARANTINE") and current_user.role != "ADMIN":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only administrators can terminate processes or quarantine process executables.",
        )
    try:
        return process_monitor.execute_process_action(
            db=db,
            pid=pid,
            action=payload.action,
            actor_id=current_user.id,
            ip_address=get_client_ip(request),
        )
    except FileNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
