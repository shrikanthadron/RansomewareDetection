"""Administrator management APIs: users, audit logs, and system metrics."""

import uuid
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from app.api.deps import get_client_ip, require_admin
from app.core.database import get_db
from app.models.ml import Dataset, ModelTraining
from app.models.operations import AdminLog, Alert, QuarantineRecord
from app.models.scan import FileScan, PredictionResult
from app.models.user import User
from app.schemas.common import AdminUserUpdateRequest, UserResponse

router = APIRouter(prefix="/api/admin", tags=["Admin Panel"])


@router.get("/metrics")
def get_admin_metrics(
    _admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    return {
        "total_users": db.query(User).count(),
        "active_users": db.query(User).filter(User.is_active.is_(True)).count(),
        "total_scans": db.query(FileScan).count(),
        "ransomware_detections": db.query(PredictionResult).filter(PredictionResult.prediction == "RANSOMWARE").count(),
        "total_datasets": db.query(Dataset).count(),
        "trained_models": db.query(ModelTraining).filter(ModelTraining.training_status == "COMPLETED").count(),
        "unread_alerts": db.query(Alert).filter(Alert.is_read.is_(False)).count(),
        "quarantined_files": db.query(QuarantineRecord).filter(QuarantineRecord.quarantine_status == "QUARANTINED").count(),
    }


@router.get("/users")
def list_users(
    search: str = Query(""),
    _admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    q = db.query(User)
    if search.strip():
        like = f"%{search.strip()}%"
        q = q.filter((User.email.ilike(like)) | (User.full_name.ilike(like)))
    users = q.order_by(User.created_at.desc()).all()
    return [UserResponse.model_validate(u) for u in users]


@router.patch("/users/{user_id}", response_model=UserResponse)
def update_user_account(
    user_id: uuid.UUID,
    payload: AdminUserUpdateRequest,
    request: Request,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    target = db.get(User, user_id)
    if not target:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
    if target.id == admin.id and payload.is_active is False:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Administrators cannot deactivate their own account.")
    if target.id == admin.id and payload.role == "USER":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Administrators cannot demote themselves.")

    changes = []
    if payload.role is not None and payload.role != target.role:
        changes.append(f"role {target.role}->{payload.role}")
        target.role = payload.role
    if payload.is_active is not None and payload.is_active != target.is_active:
        changes.append(f"is_active {target.is_active}->{payload.is_active}")
        target.is_active = payload.is_active
        if payload.is_active:
            target.failed_login_attempts = 0
            target.locked_until = None

    if changes:
        db.add(
            AdminLog(
                admin_id=admin.id,
                action="USER_UPDATED",
                details=f"Updated user {target.email}: {', '.join(changes)}",
                ip_address=get_client_ip(request),
            )
        )
    db.commit()
    db.refresh(target)
    return UserResponse.model_validate(target)


@router.get("/logs")
def get_admin_logs(
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    action: str = Query(""),
    _admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    q = db.query(AdminLog, User.email).outerjoin(User, AdminLog.admin_id == User.id)
    if action.strip():
        q = q.filter(AdminLog.action.ilike(f"%{action.strip()}%"))
    total = q.count()
    rows = q.order_by(AdminLog.created_at.desc()).offset((page - 1) * page_size).limit(page_size).all()
    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "items": [
            {
                "id": str(log.id),
                "admin_email": email or "SYSTEM",
                "action": log.action,
                "details": log.details,
                "ip_address": log.ip_address,
                "created_at": log.created_at.isoformat(),
            }
            for log, email in rows
        ],
    }
