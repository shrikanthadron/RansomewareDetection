"""File scanning, static PE feature persistence, rescanning, and scan history endpoints."""

from datetime import datetime, timezone
from pathlib import Path
import time
from typing import Optional
import uuid

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile, status
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.config import settings
from app.core.database import get_db
from app.core.rate_limit import rate_limit_scan
from app.models.ml import Algorithm, ModelTraining
from app.models.operations import Alert, SystemSetting
from app.models.scan import ExtractedFeature, FileScan, PredictionResult
from app.models.user import User
from app.services.ml_engine import predict_from_features
from app.services.pe_extractor import extract_static_pe_features
from app.services.risk_engine import evaluate_risk
from app.services.ws_manager import ws_manager

router = APIRouter(prefix="/api/scans", tags=["File Scanner & History"])

ALLOWED_EXTENSIONS = {".exe", ".dll", ".sys", ".bin", ".scr"}


def _get_max_upload_bytes(db: Session, user: User) -> int:
    setting = db.query(SystemSetting).filter(SystemSetting.setting_key == "max_upload_size_mb").first()
    sys_limit = int(setting.setting_value) if setting and setting.setting_value.isdigit() else settings.MAX_UPLOAD_SIZE_MB
    user_pref = (user.preferences or {}).get("max_upload_mb")
    effective_mb = min(sys_limit, int(user_pref)) if isinstance(user_pref, (int, float)) and user_pref > 0 else sys_limit
    return max(1, effective_mb) * 1024 * 1024


def _execute_scan_pipeline(
    db: Session,
    scan_record: FileScan,
    target_path: Path,
    user: User,
) -> PredictionResult:
    start = time.perf_counter()
    extraction = extract_static_pe_features(target_path)
    features_dict = extraction["features"]

    # Persist extracted static features
    db.query(ExtractedFeature).filter(ExtractedFeature.scan_id == scan_record.id).delete()
    for spec in extraction["feature_specs"]:
        db.add(
            ExtractedFeature(
                scan_id=scan_record.id,
                feature_name=spec["name"],
                feature_value=str(spec["value"]),
                feature_type=spec["type"],
            )
        )

    # Run active ML model if available
    ml_res = predict_from_features(db, features_dict)
    risk = evaluate_risk(features_dict, ml_res)

    explanation = dict(risk["explanation"])
    explanation["ml_notice"] = risk["ml_notice"]
    explanation["pe_metadata"] = extraction["metadata"]
    explanation["schema_version"] = extraction["schema_version"]

    pred_record = PredictionResult(
        scan_id=scan_record.id,
        algorithm_id=ml_res.get("algorithm_id") if ml_res.get("ml_used") else None,
        model_training_id=ml_res.get("model_training_id") if ml_res.get("ml_used") else None,
        prediction=risk["prediction"],
        risk_score=risk["risk_score"],
        risk_level=risk["risk_level"],
        confidence=risk["confidence"],
        ml_used=risk["ml_used"],
        explanation=explanation,
    )
    db.add(pred_record)
    db.flush()

    scan_record.file_type = extraction["file_type_detected"]
    scan_record.sha256_hash = extraction["hashes"]["sha256"]
    scan_record.md5_hash = extraction["hashes"]["md5"]
    scan_record.scan_status = "COMPLETED"
    scan_record.scan_duration = round(time.perf_counter() - start, 4)
    scan_record.result_id = pred_record.id

    # Generate alerts for SUSPICIOUS or RANSOMWARE detections
    if pred_record.prediction in ("RANSOMWARE", "SUSPICIOUS") or pred_record.risk_score >= 61.0:
        sev = "CRITICAL" if pred_record.risk_score >= 81.0 else ("HIGH" if pred_record.prediction == "RANSOMWARE" else "MEDIUM")
        alert = Alert(
            user_id=user.id,
            scan_id=scan_record.id,
            alert_type="FILE_THREAT_DETECTION",
            severity=sev,
            title=f"{pred_record.prediction} Detected: {scan_record.original_file_name}",
            description=(
                f"Risk Score {pred_record.risk_score:.1f}/100 ({pred_record.risk_level}). "
                f"SHA-256: {scan_record.sha256_hash[:16]}..."
            ),
        )
        db.add(alert)
        ws_manager.broadcast_threadsafe({
            "type": "threat_alert",
            "severity": sev,
            "title": alert.title,
            "scan_id": str(scan_record.id),
        })

    db.commit()
    db.refresh(scan_record)
    db.refresh(pred_record)
    return pred_record


@router.post("/upload", status_code=status.HTTP_201_CREATED, dependencies=[Depends(rate_limit_scan)])
async def upload_and_scan_file(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not file.filename:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Filename is required.")

    # Never trust user-provided filenames; sanitize & validate extension
    safe_original_name = Path(file.filename).name[:250]
    ext = Path(safe_original_name).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported file extension '{ext}'. Supported binary types: {', '.join(sorted(ALLOWED_EXTENSIONS))}.",
        )

    max_bytes = _get_max_upload_bytes(db, current_user)
    settings.ensure_storage_dirs()

    # Stream to secure temporary file while enforcing size cap
    temp_name = f"tmp_{uuid.uuid4().hex}.bin"
    temp_path = (settings.temp_dir / temp_name).resolve()
    total_size = 0
    try:
        with open(temp_path, "wb") as out:
            while True:
                chunk = await file.read(1024 * 256)
                if not chunk:
                    break
                total_size += len(chunk)
                if total_size > max_bytes:
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail=f"File exceeds maximum allowed limit of {max_bytes // (1024*1024)} MB.",
                    )
                out.write(chunk)

        if total_size < 64:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="File is too small (< 64 bytes) to be a valid executable binary.",
            )

        # Move to permanent server-controlled scan vault (non-executable extension .sample)
        server_filename = f"{uuid.uuid4().hex}.sample"
        stored_path = (settings.uploads_dir / server_filename).resolve()
        temp_path.replace(stored_path)

        scan_record = FileScan(
            user_id=current_user.id,
            file_name=server_filename,
            original_file_name=safe_original_name,
            file_path=str(stored_path),
            file_size=total_size,
            file_type="ANALYZING",
            sha256_hash="0" * 64,
            md5_hash="0" * 32,
            scan_status="SCANNING",
        )
        db.add(scan_record)
        db.commit()
        db.refresh(scan_record)

        pred = _execute_scan_pipeline(db, scan_record, stored_path, current_user)
        return _format_scan_detail(db, scan_record, pred)
    except HTTPException:
        if temp_path.exists():
            temp_path.unlink(missing_ok=True)
        raise
    except Exception as exc:
        if temp_path.exists():
            temp_path.unlink(missing_ok=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Scan failed: {exc}") from exc


def _format_scan_detail(db: Session, scan: FileScan, pred: Optional[PredictionResult]) -> dict:
    model_name = None
    model_version = None
    if pred and pred.model_training_id:
        mt = db.get(ModelTraining, pred.model_training_id)
        if mt:
            model_version = mt.model_version
            algo = db.get(Algorithm, mt.algorithm_id)
            model_name = algo.algorithm_name if algo else None

    features = [
        {"feature_name": f.feature_name, "feature_value": f.feature_value, "feature_type": f.feature_type}
        for f in db.query(ExtractedFeature)
        .filter(ExtractedFeature.scan_id == scan.id)
        .order_by(ExtractedFeature.feature_name)
        .all()
    ]

    return {
        "id": str(scan.id),
        "user_id": str(scan.user_id),
        "original_file_name": scan.original_file_name,
        "file_name": scan.file_name,
        "file_path": scan.file_path,
        "file_size": scan.file_size,
        "file_type": scan.file_type,
        "sha256_hash": scan.sha256_hash,
        "md5_hash": scan.md5_hash,
        "upload_timestamp": scan.upload_timestamp.isoformat(),
        "scan_status": scan.scan_status,
        "scan_duration": scan.scan_duration,
        "is_user_flagged": scan.is_user_flagged,
        "prediction": {
            "id": str(pred.id),
            "prediction": pred.prediction,
            "risk_score": pred.risk_score,
            "risk_level": pred.risk_level,
            "confidence": pred.confidence,
            "ml_used": pred.ml_used,
            "model_name": model_name,
            "model_version": model_version,
            "explanation": pred.explanation,
            "created_at": pred.created_at.isoformat(),
        } if pred else None,
        "features": features,
    }


@router.get("")
def list_scans(
    page: int = Query(1, ge=1),
    page_size: int = Query(15, ge=1, le=100),
    search: Optional[str] = None,
    prediction: Optional[str] = None,
    risk_level: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    sort_by: str = Query("upload_timestamp", pattern="^(upload_timestamp|risk_score|file_size|original_file_name)$"),
    sort_dir: str = Query("desc", pattern="^(asc|desc)$"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    q = (
        db.query(FileScan, PredictionResult, User.email)
        .outerjoin(PredictionResult, FileScan.result_id == PredictionResult.id)
        .join(User, FileScan.user_id == User.id)
    )
    if current_user.role != "ADMIN":
        q = q.filter(FileScan.user_id == current_user.id)

    if search:
        like = f"%{search.strip()}%"
        q = q.filter(
            or_(
                FileScan.original_file_name.ilike(like),
                FileScan.sha256_hash.ilike(like),
                FileScan.md5_hash.ilike(like),
                User.email.ilike(like),
            )
        )
    if prediction:
        q = q.filter(PredictionResult.prediction == prediction.upper())
    if risk_level:
        q = q.filter(PredictionResult.risk_level == risk_level.upper())
    if date_from:
        q = q.filter(FileScan.upload_timestamp >= datetime.fromisoformat(date_from))
    if date_to:
        q = q.filter(FileScan.upload_timestamp <= datetime.fromisoformat(date_to))

    sort_col = {
        "upload_timestamp": FileScan.upload_timestamp,
        "risk_score": PredictionResult.risk_score,
        "file_size": FileScan.file_size,
        "original_file_name": FileScan.original_file_name,
    }[sort_by]
    q = q.order_by(sort_col.desc() if sort_dir == "desc" else sort_col.asc())

    total = q.count()
    rows = q.offset((page - 1) * page_size).limit(page_size).all()

    items = []
    for scan, pred, user_email in rows:
        model_label = None
        if pred and pred.model_training_id:
            mt = db.get(ModelTraining, pred.model_training_id)
            if mt:
                algo = db.get(Algorithm, mt.algorithm_id)
                model_label = f"{algo.algorithm_name} v{mt.model_version}" if algo else mt.model_version
        items.append({
            "id": str(scan.id),
            "original_file_name": scan.original_file_name,
            "file_size": scan.file_size,
            "file_type": scan.file_type,
            "sha256_hash": scan.sha256_hash,
            "upload_timestamp": scan.upload_timestamp.isoformat(),
            "scan_status": scan.scan_status,
            "scan_duration": scan.scan_duration,
            "user_email": user_email,
            "is_user_flagged": scan.is_user_flagged,
            "prediction": pred.prediction if pred else "PENDING",
            "risk_score": pred.risk_score if pred else 0.0,
            "risk_level": pred.risk_level if pred else "LOW",
            "ml_used": pred.ml_used if pred else False,
            "model_label": model_label or "Static Heuristic",
        })

    return {"total": total, "page": page, "page_size": page_size, "items": items}


@router.get("/{scan_id}")
def get_scan_detail(
    scan_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    scan = db.get(FileScan, scan_id)
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan record not found.")
    if current_user.role != "ADMIN" and scan.user_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied to this scan record.")

    pred = db.get(PredictionResult, scan.result_id) if scan.result_id else None
    return _format_scan_detail(db, scan, pred)


@router.post("/{scan_id}/rescan")
def rescan_file(
    scan_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    scan = db.get(FileScan, scan_id)
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan record not found.")
    if current_user.role != "ADMIN" and scan.user_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied.")
    if not scan.file_path or not Path(scan.file_path).exists():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Stored sample file is no longer available (possibly quarantined).")

    pred = _execute_scan_pipeline(db, scan, Path(scan.file_path), current_user)
    return _format_scan_detail(db, scan, pred)


@router.post("/{scan_id}/flag")
def toggle_user_flag(
    scan_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    scan = db.get(FileScan, scan_id)
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan record not found.")
    if current_user.role != "ADMIN" and scan.user_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied.")

    scan.is_user_flagged = not scan.is_user_flagged
    db.commit()
    return {"id": str(scan.id), "is_user_flagged": scan.is_user_flagged}
