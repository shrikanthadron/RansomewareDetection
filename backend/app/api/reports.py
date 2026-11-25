"""PDF report generation, listing, and secure file download endpoints."""

from datetime import datetime, timezone
from pathlib import Path
import uuid
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, require_admin
from app.core.database import get_db
from app.models.ml import Algorithm, Dataset, ModelTraining
from app.models.operations import Alert, QuarantineRecord, ScanReport
from app.models.scan import ExtractedFeature, FileScan, PredictionResult
from app.models.user import User
from app.services.report_service import (
    generate_admin_system_pdf_report,
    generate_scan_pdf_report,
)

router = APIRouter(prefix="/api/reports", tags=["PDF Reports"])


@router.get("")
def list_reports(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    q = db.query(ScanReport)
    if current_user.role != "ADMIN":
        q = q.filter(ScanReport.user_id == current_user.id, ScanReport.report_type == "SCAN_PDF")
    reports = q.order_by(ScanReport.generated_at.desc()).limit(100).all()

    items = []
    for r in reports:
        scan = db.get(FileScan, r.scan_id) if r.scan_id else None
        items.append({
            "id": str(r.id),
            "scan_id": str(r.scan_id) if r.scan_id else None,
            "file_name": scan.original_file_name if scan else "System Executive Summary",
            "report_type": r.report_type,
            "generated_at": r.generated_at.isoformat(),
            "exists": Path(r.report_path).exists(),
        })
    return items


@router.post("/scan/{scan_id}", status_code=status.HTTP_201_CREATED)
def create_scan_report(
    scan_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    scan = db.get(FileScan, scan_id)
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan record not found.")
    if current_user.role != "ADMIN" and scan.user_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied.")

    pred = db.get(PredictionResult, scan.result_id) if scan.result_id else None
    model_label = "Static Analysis Only (ML Model Not Trained)"
    model_version = "N/A"
    if pred and pred.ml_used and pred.model_training_id:
        mt = db.get(ModelTraining, pred.model_training_id)
        if mt:
            algo = db.get(Algorithm, mt.algorithm_id)
            model_label = algo.algorithm_name if algo else "Supervised ML"
            model_version = mt.model_version

    features = [
        {"feature_name": f.feature_name, "feature_type": f.feature_type, "feature_value": f.feature_value}
        for f in db.query(ExtractedFeature)
        .filter(ExtractedFeature.scan_id == scan.id)
        .order_by(ExtractedFeature.feature_name)
        .all()
    ]

    pdf_path = generate_scan_pdf_report(
        scan_data={
            "id": str(scan.id),
            "original_file_name": scan.original_file_name,
            "file_type": scan.file_type,
            "file_size": scan.file_size,
            "sha256_hash": scan.sha256_hash,
            "md5_hash": scan.md5_hash,
            "upload_timestamp": scan.upload_timestamp.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "scan_duration": scan.scan_duration or 0.0,
        },
        prediction_data={
            "prediction": pred.prediction if pred else "PENDING",
            "risk_score": pred.risk_score if pred else 0.0,
            "risk_level": pred.risk_level if pred else "LOW",
            "confidence": pred.confidence if pred else 0.0,
            "model_label": model_label,
            "model_version": model_version,
            "explanation": pred.explanation if pred else {},
        },
        features=features,
    )

    rep = ScanReport(
        user_id=current_user.id,
        scan_id=scan.id,
        report_path=str(pdf_path),
        report_type="SCAN_PDF",
    )
    db.add(rep)
    db.commit()
    db.refresh(rep)
    return {"id": str(rep.id), "report_type": rep.report_type, "generated_at": rep.generated_at.isoformat()}


@router.post("/admin/system", status_code=status.HTTP_201_CREATED)
def create_admin_system_report(
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    now = datetime.now(timezone.utc)
    start_today = now.replace(hour=0, minute=0, second=0, microsecond=0)

    total_scans = db.query(FileScan).count()
    scans_today = db.query(FileScan).filter(FileScan.upload_timestamp >= start_today).count()
    ransomware_cnt = db.query(PredictionResult).join(FileScan, FileScan.result_id == PredictionResult.id).filter(PredictionResult.prediction == "RANSOMWARE").count()
    suspicious_cnt = db.query(PredictionResult).join(FileScan, FileScan.result_id == PredictionResult.id).filter(PredictionResult.prediction == "SUSPICIOUS").count()
    benign_cnt = db.query(PredictionResult).join(FileScan, FileScan.result_id == PredictionResult.id).filter(PredictionResult.prediction == "BENIGN").count()
    detection_rate = ((ransomware_cnt + suspicious_cnt) / total_scans) * 100.0 if total_scans > 0 else 0.0

    model_rows = (
        db.query(ModelTraining, Algorithm.algorithm_name)
        .join(Algorithm, ModelTraining.algorithm_id == Algorithm.id)
        .order_by(ModelTraining.created_at.desc())
        .all()
    )
    models = [
        {
            "algorithm_name": algo_name,
            "model_version": mt.model_version,
            "training_status": mt.training_status,
            "is_active": mt.is_active,
            "accuracy": mt.accuracy,
            "precision": mt.precision,
            "recall": mt.recall,
            "f1_score": mt.f1_score,
        }
        for mt, algo_name in model_rows
    ]

    pdf_path = generate_admin_system_pdf_report({
        "total_scans": total_scans,
        "scans_today": scans_today,
        "ransomware_count": ransomware_cnt,
        "suspicious_count": suspicious_cnt,
        "benign_count": benign_cnt,
        "detection_rate": detection_rate,
        "total_datasets": db.query(Dataset).count(),
        "total_models": db.query(ModelTraining).filter(ModelTraining.training_status == "COMPLETED").count(),
        "total_alerts": db.query(Alert).count(),
        "quarantined_count": db.query(QuarantineRecord).filter(QuarantineRecord.quarantine_status == "QUARANTINED").count(),
        "models": models,
    })

    rep = ScanReport(
        user_id=admin.id,
        scan_id=None,
        report_path=str(pdf_path),
        report_type="ADMIN_SYSTEM_PDF",
    )
    db.add(rep)
    db.commit()
    db.refresh(rep)
    return {"id": str(rep.id), "report_type": rep.report_type, "generated_at": rep.generated_at.isoformat()}


@router.get("/{report_id}/download")
def download_report(
    report_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    rep = db.get(ScanReport, report_id)
    if not rep:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found.")
    if current_user.role != "ADMIN" and rep.user_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied.")
    p = Path(rep.report_path)
    if not p.exists():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="PDF file missing on disk.")
    return FileResponse(path=str(p), media_type="application/pdf", filename=p.name)
