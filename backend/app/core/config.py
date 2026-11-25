"""Application configuration settings loaded from environment variables."""

from pathlib import Path
from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict


ROOT_ENV_FILE = Path(__file__).resolve().parents[3] / ".env"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(".env", str(ROOT_ENV_FILE)),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    APP_NAME: str = "RansomShield AI"
    APP_VERSION: str = "1.0.0"
    ENVIRONMENT: str = "development"

    # PostgreSQL database connection URL (no SQLite fallback)
    DATABASE_URL: str = (
        "postgresql+psycopg://ransomshield:ransomshield_dev_pass@localhost:5432/ransomshield"
    )

    # JWT Authentication
    JWT_SECRET_KEY: str = "dev-insecure-secret-change-before-production-deployment-9f2a4c"
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 120

    # Initial Admin Bootstrap (never hardcoded production secrets)
    INITIAL_ADMIN_EMAIL: str = ""
    INITIAL_ADMIN_PASSWORD: str = ""
    INITIAL_ADMIN_NAME: str = "System Administrator"

    # Auth protection
    MAX_FAILED_LOGIN_ATTEMPTS: int = 5
    ACCOUNT_LOCKOUT_MINUTES: int = 15

    # Upload & Storage limits
    MAX_UPLOAD_SIZE_MB: int = 50
    MAX_DATASET_SIZE_MB: int = 100
    STORAGE_DIR: str = "./storage"

    # CORS
    CORS_ORIGINS: str = "http://localhost:5173,http://localhost:3000,http://127.0.0.1:5173"

    @property
    def cors_origins_list(self) -> List[str]:
        return [origin.strip() for origin in self.CORS_ORIGINS.split(",") if origin.strip()]

    @property
    def storage_path(self) -> Path:
        return Path(self.STORAGE_DIR).resolve()

    @property
    def uploads_dir(self) -> Path:
        return self.storage_path / "uploads"

    @property
    def temp_dir(self) -> Path:
        return self.storage_path / "temp"

    @property
    def datasets_dir(self) -> Path:
        return self.storage_path / "datasets"

    @property
    def models_dir(self) -> Path:
        return self.storage_path / "models"

    @property
    def reports_dir(self) -> Path:
        return self.storage_path / "reports"

    @property
    def quarantine_dir(self) -> Path:
        return self.storage_path / "quarantine"

    def ensure_storage_dirs(self) -> None:
        for path in [
            self.storage_path,
            self.uploads_dir,
            self.temp_dir,
            self.datasets_dir,
            self.models_dir,
            self.reports_dir,
            self.quarantine_dir,
        ]:
            path.mkdir(parents=True, exist_ok=True)


settings = Settings()
