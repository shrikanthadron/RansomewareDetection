"""User and system settings endpoints."""

import platform
from typing import List
from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from app.api.deps import get_client_ip, get_current_user, require_admin
from app.core.config import settings
from app.core.database import get_db
from app.models.operations import AdminLog, SystemSetting
from app.models.user import User
from app.schemas.common import SystemSettingUpdateItem
from app.services.pe_extractor import SCHEMA_VERSION

router = APIRouter(prefix="/api/settings", tags=["Settings"])


@router.get("/system-info")
def get_system_info(
    _user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    sys_settings = {s.setting_key: s.setting_value for s in db.query(SystemSetting).all()}
    return {
        "app_name": settings.APP_NAME,
        "app_version": settings.APP_VERSION,
        "environment": settings.ENVIRONMENT,
        "pe_schema_version": SCHEMA_VERSION,
        "default_max_upload_mb": int(sys_settings.get("max_upload_size_mb", settings.MAX_UPLOAD_SIZE_MB)),
        "platform": f"{platform.system()} {platform.release()}",
        "python_version": platform.python_version(),
        "database_engine": "PostgreSQL",
        "system_settings": sys_settings,
    }


@router.put("/system")
def update_system_settings(
    items: List[SystemSettingUpdateItem],
    request: Request,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    for item in items:
        existing = db.query(SystemSetting).filter(SystemSetting.setting_key == item.setting_key).first()
        if existing:
            existing.setting_value = item.setting_value
        else:
            db.add(SystemSetting(setting_key=item.setting_key, setting_value=item.setting_value))
    db.add(
        AdminLog(
            admin_id=admin.id,
            action="SYSTEM_SETTINGS_UPDATED",
            details=f"Updated settings keys: {[i.setting_key for i in items]}",
            ip_address=get_client_ip(request),
        )
    )
    db.commit()
    return {"message": "System settings updated."}
