"""Notifications and alerts endpoints."""

import uuid
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.database import get_db
from app.models.operations import Alert
from app.models.user import User

router = APIRouter(prefix="/api/alerts", tags=["Notifications & Alerts"])


@router.get("")
def list_alerts(
    unread_only: bool = Query(False),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    q = db.query(Alert)
    if current_user.role != "ADMIN":
        q = q.filter(Alert.user_id == current_user.id)
    else:
        q = q.filter(or_(Alert.user_id == current_user.id, Alert.user_id.is_(None)))

    unread_count = q.filter(Alert.is_read.is_(False)).count()
    if unread_only:
        q = q.filter(Alert.is_read.is_(False))

    rows = q.order_by(Alert.created_at.desc()).limit(100).all()
    return {
        "unread_count": unread_count,
        "items": [
            {
                "id": str(a.id),
                "scan_id": str(a.scan_id) if a.scan_id else None,
                "alert_type": a.alert_type,
                "severity": a.severity,
                "title": a.title,
                "description": a.description,
                "is_read": a.is_read,
                "created_at": a.created_at.isoformat(),
            }
            for a in rows
        ],
    }


@router.post("/{alert_id}/read")
def mark_alert_read(
    alert_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found.")
    if current_user.role != "ADMIN" and alert.user_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied.")
    alert.is_read = True
    db.commit()
    return {"id": str(alert.id), "is_read": True}


@router.post("/mark-all-read")
def mark_all_read(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    q = db.query(Alert).filter(Alert.is_read.is_(False))
    if current_user.role != "ADMIN":
        q = q.filter(Alert.user_id == current_user.id)
    updated = q.update({"is_read": True}, synchronize_session=False)
    db.commit()
    return {"marked_read": updated}


@router.delete("/{alert_id}")
def delete_alert(
    alert_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found.")
    if current_user.role != "ADMIN" and alert.user_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied.")
    db.delete(alert)
    db.commit()
    return {"deleted": str(alert_id)}
