"""Internal Threat Intelligence derived exclusively from real scan and monitoring records."""

from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.database import get_db
from app.models.scan import FileScan, PredictionResult
from app.models.user import User

router = APIRouter(prefix="/api/threats", tags=["Threat Intelligence"])


@router.get("/overview")
def get_threat_intelligence(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    is_admin = current_user.role == "ADMIN"

    base_q = (
        db.query(FileScan, PredictionResult)
        .join(PredictionResult, FileScan.result_id == PredictionResult.id)
    )
    if not is_admin:
        base_q = base_q.filter(FileScan.user_id == current_user.id)

    # Frequent risky hashes observed internally
    hash_q = (
        db.query(
            FileScan.sha256_hash,
            func.max(FileScan.original_file_name).label("sample_name"),
            func.count(FileScan.id).label("sightings"),
            func.max(PredictionResult.risk_score).label("max_risk"),
            func.max(PredictionResult.prediction).label("latest_verdict"),
            func.max(FileScan.upload_timestamp).label("last_seen"),
        )
        .join(PredictionResult, FileScan.result_id == PredictionResult.id)
        .filter(PredictionResult.prediction.in_(["RANSOMWARE", "SUSPICIOUS"]))
    )
    if not is_admin:
        hash_q = hash_q.filter(FileScan.user_id == current_user.id)

    frequent_hashes = [
        {
            "sha256_hash": row.sha256_hash,
            "sample_name": row.sample_name,
            "sightings": int(row.sightings),
            "max_risk_score": float(row.max_risk),
            "verdict": row.latest_verdict,
            "last_seen": row.last_seen.isoformat() if row.last_seen else None,
        }
        for row in hash_q.group_by(FileScan.sha256_hash).order_by(func.count(FileScan.id).desc()).limit(15).all()
    ]

    # High-risk files list
    high_risk_rows = (
        base_q.filter(PredictionResult.risk_score >= 60.0)
        .order_by(PredictionResult.risk_score.desc(), FileScan.upload_timestamp.desc())
        .limit(20)
        .all()
    )
    high_risk_files = [
        {
            "scan_id": str(s.id),
            "file_name": s.original_file_name,
            "sha256_hash": s.sha256_hash,
            "prediction": p.prediction,
            "risk_score": p.risk_score,
            "risk_level": p.risk_level,
            "ml_used": p.ml_used,
            "upload_timestamp": s.upload_timestamp.isoformat(),
        }
        for s, p in high_risk_rows
    ]

    # User-reported suspicious files
    flagged_rows = (
        base_q.filter(FileScan.is_user_flagged.is_(True))
        .order_by(FileScan.upload_timestamp.desc())
        .limit(20)
        .all()
    )
    user_flagged = [
        {
            "scan_id": str(s.id),
            "file_name": s.original_file_name,
            "sha256_hash": s.sha256_hash,
            "prediction": p.prediction,
            "risk_score": p.risk_score,
            "upload_timestamp": s.upload_timestamp.isoformat(),
        }
        for s, p in flagged_rows
    ]

    # Detection categories breakdown
    cat_q = (
        db.query(PredictionResult.prediction, func.count(PredictionResult.id))
        .join(FileScan, FileScan.result_id == PredictionResult.id)
    )
    if not is_admin:
        cat_q = cat_q.filter(FileScan.user_id == current_user.id)
    categories = [{"category": cat, "count": int(cnt)} for cat, cnt in cat_q.group_by(PredictionResult.prediction).all()]

    return {
        "intelligence_source_notice": (
            "All intelligence shown here is derived strictly from internal RansomShield AI static scans "
            "and ML/heuristic evaluations. External threat intelligence feeds (e.g., VirusTotal/MISP) are not "
            "connected and are never fabricated."
        ),
        "frequent_suspicious_hashes": frequent_hashes,
        "high_risk_files": high_risk_files,
        "user_reported_suspicious": user_flagged,
        "detection_categories": categories,
    }
