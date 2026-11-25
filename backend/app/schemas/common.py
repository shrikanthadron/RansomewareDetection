"""Pydantic v2 request and response schemas for RansomShield AI."""

from datetime import datetime
from typing import Any, Dict, List, Optional
import uuid
from pydantic import BaseModel, EmailStr, Field


# --- Auth & Users ---
class UserRegisterRequest(BaseModel):
    full_name: str = Field(min_length=2, max_length=150)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class UserLoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


class ProfileUpdateRequest(BaseModel):
    full_name: str = Field(min_length=2, max_length=150)
    preferences: Optional[Dict[str, Any]] = None


class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str = Field(min_length=8, max_length=128)


class UserResponse(BaseModel):
    id: uuid.UUID
    full_name: str
    email: str
    role: str
    is_active: bool
    preferences: Optional[Dict[str, Any]] = None
    created_at: datetime
    last_login: Optional[datetime] = None

    model_config = {"from_attributes": True}


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in_minutes: int
    user: UserResponse


class AdminUserUpdateRequest(BaseModel):
    role: Optional[str] = Field(default=None, pattern="^(USER|ADMIN)$")
    is_active: Optional[bool] = None


# --- Datasets & ML ---
class TrainingStartRequest(BaseModel):
    dataset_id: uuid.UUID
    algorithm_id: uuid.UUID
    model_version: str = Field(default="1.0.0", min_length=1, max_length=64)
    test_size: float = Field(default=0.2, ge=0.1, le=0.4)
    feature_selection: str = Field(default="none", pattern="^(none|mutual_info|chi2)$")
    k_features: int = Field(default=20, ge=2, le=100)
    cv_folds: int = Field(default=0, ge=0, le=10)
    remove_duplicates: bool = True
    hyperparameters: Dict[str, Any] = Field(default_factory=dict)


# --- Monitoring & Quarantine ---
class MonitoringStartRequest(BaseModel):
    poll_interval_sec: float = Field(default=5.0, ge=2.0, le=30.0)


class ProcessActionRequest(BaseModel):
    action: str = Field(pattern="^(FLAG|ALERT|TERMINATE|QUARANTINE)$")


class QuarantineCreateRequest(BaseModel):
    scan_id: Optional[uuid.UUID] = None
    file_path: str = Field(min_length=1, max_length=1024)


# --- Settings ---
class SystemSettingUpdateItem(BaseModel):
    setting_key: str = Field(min_length=1, max_length=128)
    setting_value: str
