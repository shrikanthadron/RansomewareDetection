"""Overview dashboard metrics, chart aggregations, and recent activity from PostgreSQL."""

from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends
from sqlalchemy import case, func
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.database import get_db
from app.models.ml import Algorithm, ModelTraining
from app.models.operations import Alert
from app.models.scan import FileScan, PredictionResult
from app.models.user import User
from app.services.monitoring_service import process_monitor

router = APIRouter(prefix="/api/dashboard", tags=["Dashboard"])


@router.get("/overview")
def get_dashboard_overview(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    now = datetime.now(timezone.utc)
    start_of_today = now.replace(hour=0, minute=0, second=0, microsecond=0)
    is_admin = current_user.role == "ADMIN"

    scan_query = db.query(FileScan)
    if not is_admin:
        scan_query = scan_query.filter(FileScan.user_id == current_user.id)

    total_scans = scan_query.count()
    scans_today = scan_query.filter(FileScan.upload_timestamp >= start_of_today).count()

    # Join PredictionResult for latest scan classification counts
    pred_query = (
        db.query(PredictionResult)
        .join(FileScan, FileScan.result_id == PredictionResult.id)
    )
    if not is_admin:
        pred_query = pred_query.filter(FileScan.user_id == current_user.id)

    ransomware_count = pred_query.filter(PredictionResult.prediction == "RANSOMWARE").count()
    suspicious_count = pred_query.filter(PredictionResult.prediction == "SUSPICIOUS").count()
    benign_count = pred_query.filter(PredictionResult.prediction == "BENIGN").count()

    detection_rate = round(
        ((ransomware_count + suspicious_count) / total_scans) * 100.0, 2
    ) if total_scans > 0 else 0.0

    # Trained model stats
    completed_models_q = db.query(ModelTraining).filter(ModelTraining.training_status == "COMPLETED")
    total_trained_models = completed_models_q.count()
    active_model = completed_models_q.filter(ModelTraining.is_active.is_(True)).first()
    latest_model = active_model or completed_models_q.order_by(ModelTraining.training_date.desc()).first()
    latest_model_accuracy = round(latest_model.accuracy * 100.0, 2) if latest_model and latest_model.accuracy is not None else None

    # Alerts
    alert_q = db.query(Alert)
    if not is_admin:
        alert_q = alert_q.filter(Alert.user_id == current_user.id)
    threat_alerts_count = alert_q.filter(Alert.is_read.is_(False)).count()

    # Chart 1 & 4: Scans & Detections over last 14 days
    cutoff = start_of_today - timedelta(days=13)
    day_expr = func.date_trunc("day", FileScan.upload_timestamp)
    trend_q = (
        db.query(
            day_expr.label("day"),
            func.count(FileScan.id).label("total"),
            func.sum(case((PredictionResult.prediction == "RANSOMWARE", 1), else_=0)).label("ransomware"),
            func.sum(case((PredictionResult.prediction == "SUSPICIOUS", 1), else_=0)).label("suspicious"),
            func.sum(case((PredictionResult.prediction == "BENIGN", 1), else_=0)).label("benign"),
        )
        .outerjoin(PredictionResult, FileScan.result_id == PredictionResult.id)
        .filter(FileScan.upload_timestamp >= cutoff)
    )
    if not is_admin:
        trend_q = trend_q.filter(FileScan.user_id == current_user.id)
    trend_rows = trend_q.group_by(day_expr).order_by(day_expr).all()

    by_day = {
        row.day.strftime("%Y-%m-%d"): {
            "date": row.day.strftime("%Y-%m-%d"),
            "total": int(row.total or 0),
            "ransomware": int(row.ransomware or 0),
            "suspicious": int(row.suspicious or 0),
            "benign": int(row.benign or 0),
        }
        for row in trend_rows
        if row.day is not None
    }
    scans_over_time = []
    if total_scans > 0:
        for i in range(14):
            d = (cutoff + timedelta(days=i)).strftime("%Y-%m-%d")
            scans_over_time.append(
                by_day.get(d, {"date": d, "total": 0, "ransomware": 0, "suspicious": 0, "benign": 0})
            )

    # Chart 3: Risk distribution buckets
    risk_rows = (
        db.query(PredictionResult.risk_level, func.count(PredictionResult.id))
        .join(FileScan, FileScan.result_id == PredictionResult.id)
    )
    if not is_admin:
        risk_rows = risk_rows.filter(FileScan.user_id == current_user.id)
    risk_map = {lvl: int(cnt) for lvl, cnt in risk_rows.group_by(PredictionResult.risk_level).all()}
    risk_distribution = [
        {"level": lvl, "count": risk_map.get(lvl, 0)}
        for lvl in ["LOW", "GUARDED", "MODERATE", "HIGH", "CRITICAL"]
    ] if total_scans > 0 else []

    # Chart 5: Model performance comparison
    models_comp_rows = (
        db.query(ModelTraining, Algorithm.algorithm_name)
        .join(Algorithm, ModelTraining.algorithm_id == Algorithm.id)
        .filter(ModelTraining.training_status == "COMPLETED")
        .order_by(ModelTraining.training_date.desc())
        .limit(8)
        .all()
    )
    model_comparison = [
        {
            "id": str(m.id),
            "name": f"{algo_name} ({m.model_version})",
            "accuracy": round((m.accuracy or 0.0) * 100.0, 2),
            "precision": round((m.precision or 0.0) * 100.0, 2),
            "recall": round((m.recall or 0.0) * 100.0, 2),
            "f1_score": round((m.f1_score or 0.0) * 100.0, 2),
            "is_active": m.is_active,
        }
        for m, algo_name in models_comp_rows
    ]

    # Chart 6: Threat severity distribution
    sev_rows = alert_q.with_entities(Alert.severity, func.count(Alert.id)).group_by(Alert.severity).all()
    sev_map = {s: int(c) for s, c in sev_rows}
    severity_distribution = [
        {"severity": s, "count": sev_map.get(s, 0)}
        for s in ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        if sev_map.get(s, 0) > 0
    ]

    # Recent activity (last 10 scans)
    recent_rows = (
        db.query(FileScan, PredictionResult)
        .outerjoin(PredictionResult, FileScan.result_id == PredictionResult.id)
    )
    if not is_admin:
        recent_rows = recent_rows.filter(FileScan.user_id == current_user.id)
    recent_rows = recent_rows.order_by(FileScan.upload_timestamp.desc()).limit(10).all()

    recent_activity = [
        {
            "scan_id": str(s.id),
            "file_name": s.original_file_name,
            "sha256_hash": s.sha256_hash,
            "upload_timestamp": s.upload_timestamp.isoformat(),
            "prediction": p.prediction if p else "PENDING",
            "risk_score": p.risk_score if p else 0.0,
            "risk_level": p.risk_level if p else "LOW",
            "scan_status": s.scan_status,
        }
        for s, p in recent_rows
    ]

    monitor_state = process_monitor.status()
    return {
        "metrics": {
            "total_scans": total_scans,
            "scans_today": scans_today,
            "ransomware_detections": ransomware_count,
            "suspicious_files": suspicious_count,
            "benign_files": benign_count,
            "detection_rate": detection_rate,
            "monitoring_active": monitor_state["is_running"],
            "total_trained_models": total_trained_models,
            "latest_model_accuracy": latest_model_accuracy,
            "active_model_name": (
                f"{db.get(Algorithm, active_model.algorithm_id).algorithm_name} v{active_model.model_version}"
                if active_model
                else None
            ),
            "threat_alerts": threat_alerts_count,
        },
        "charts": {
            "scans_over_time": scans_over_time,
            "classification_split": [
                {"name": "Benign", "value": benign_count},
                {"name": "Suspicious", "value": suspicious_count},
                {"name": "Ransomware", "value": ransomware_count},
            ] if total_scans > 0 else [],
            "risk_distribution": risk_distribution,
            "model_comparison": model_comparison,
            "severity_distribution": severity_distribution,
        },
        "recent_activity": recent_activity,
    }
