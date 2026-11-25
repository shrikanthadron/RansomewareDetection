"""FastAPI entrypoint for RansomShield AI."""

import asyncio
from contextlib import asynccontextmanager
import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import (
    admin,
    alerts,
    auth,
    dashboard,
    datasets,
    models_ml,
    monitoring,
    quarantine,
    reports,
    scans,
    settings as settings_api,
    threat_intel,
    ws,
)
from app.core.config import settings
from app.core.database import SessionLocal
from app.core.logging_config import setup_logging
from app.core.security import hash_password
from app.models.ml import Algorithm, ModelTraining
from app.models.operations import SystemSetting
from app.models.user import User
from app.services.ws_manager import ws_manager

setup_logging()
logger = logging.getLogger(__name__)

DEFAULT_ALGORITHMS = [
    ("Random Forest", "1.0.0", "Ensemble of decision trees with balanced class weights for static PE classification."),
    ("Decision Tree", "1.0.0", "Interpretable rule-based decision tree classifier for static PE features."),
    ("Support Vector Machine (SVM)", "1.0.0", "RBF-kernel SVM with StandardScaler preprocessing and Platt probability calibration."),
    ("XGBoost", "2.1.0", "Gradient boosted decision trees optimized for imbalanced ransomware detection."),
]


def bootstrap_database() -> None:
    """Seed required ML algorithm catalog, default settings, and env-configured admin user."""
    db = SessionLocal()
    try:
        for name, ver, desc in DEFAULT_ALGORITHMS:
            exists = db.query(Algorithm).filter(Algorithm.algorithm_name == name).first()
            if not exists:
                db.add(Algorithm(algorithm_name=name, model_version=ver, description=desc, is_active=True))

        if not db.query(SystemSetting).filter(SystemSetting.setting_key == "max_upload_size_mb").first():
            db.add(SystemSetting(setting_key="max_upload_size_mb", setting_value=str(settings.MAX_UPLOAD_SIZE_MB)))

        # Recover any training jobs left RUNNING across an unclean shutdown
        stale_jobs = db.query(ModelTraining).filter(ModelTraining.training_status.in_(["PENDING", "RUNNING"])).all()
        for job in stale_jobs:
            job.training_status = "FAILED"

        # Bootstrap initial admin only when explicitly configured via env vars and no admin exists yet
        if settings.INITIAL_ADMIN_EMAIL and settings.INITIAL_ADMIN_PASSWORD:
            admin_email = settings.INITIAL_ADMIN_EMAIL.lower().strip()
            existing_admin = db.query(User).filter(User.email == admin_email).first()
            if not existing_admin:
                db.add(
                    User(
                        full_name=settings.INITIAL_ADMIN_NAME,
                        email=admin_email,
                        password_hash=hash_password(settings.INITIAL_ADMIN_PASSWORD),
                        role="ADMIN",
                        is_active=True,
                        preferences={
                            "theme": "dark",
                            "max_upload_mb": settings.MAX_UPLOAD_SIZE_MB,
                            "notify_ransomware": True,
                            "notify_suspicious": True,
                            "notify_monitoring": True,
                            "monitoring_poll_sec": 5,
                        },
                    )
                )
                logger.info("Initial administrator account created for %s.", admin_email)

        db.commit()
    except Exception as exc:
        logger.warning("Database bootstrap skipped or incomplete (run migrations first if fresh DB): %s", exc)
        db.rollback()
    finally:
        db.close()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    settings.ensure_storage_dirs()
    ws_manager.set_loop(asyncio.get_running_loop())
    bootstrap_database()
    yield


app = FastAPI(
    title="RansomShield AI API",
    description="Ransomware Detection Using Supervised Machine Learning Algorithms & Static PE Analysis.",
    version=settings.APP_VERSION,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health", tags=["Health"])
def health_check():
    return {"status": "ok", "service": settings.APP_NAME, "version": settings.APP_VERSION}


app.include_router(auth.router)
app.include_router(dashboard.router)
app.include_router(scans.router)
app.include_router(datasets.router)
app.include_router(models_ml.router)
app.include_router(monitoring.router)
app.include_router(quarantine.router)
app.include_router(reports.router)
app.include_router(threat_intel.router)
app.include_router(alerts.router)
app.include_router(settings_api.router)
app.include_router(admin.router)
app.include_router(ws.router)
