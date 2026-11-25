"""Admin-only CSV dataset management, validation, preview, and deletion endpoints."""

import json
from pathlib import Path
from typing import Optional
import uuid

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile, status
from sqlalchemy.orm import Session

from app.api.deps import get_client_ip, require_admin
from app.core.config import settings
from app.core.database import get_db
from app.models.ml import Dataset
from app.models.operations import AdminLog
from app.models.user import User
from app.services.ml_engine import validate_and_inspect_csv

router = APIRouter(prefix="/api/datasets", tags=["Datasets (Admin)"])


@router.get("")
def list_datasets(
    _admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    rows = db.query(Dataset).order_by(Dataset.created_at.desc()).all()
    return [
        {
            "id": str(d.id),
            "name": d.name,
            "description": d.description,
            "dataset_type": d.dataset_type,
            "sample_count": d.sample_count,
            "benign_count": d.benign_count,
            "ransomware_count": d.ransomware_count,
            "validation_status": d.validation_status,
            "metadata": d.metadata_json or {},
            "created_at": d.created_at.isoformat(),
        }
        for d in rows
    ]


@router.post("/upload", status_code=status.HTTP_201_CREATED)
async def upload_dataset(
    request: Request,
    name: str = Form(..., min_length=2, max_length=200),
    description: Optional[str] = Form(None),
    label_column: str = Form("label"),
    label_mapping_json: Optional[str] = Form(None),
    file: UploadFile = File(...),
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    if not file.filename or not file.filename.lower().endswith(".csv"):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Only CSV dataset files are supported.")

    custom_mapping = None
    if label_mapping_json and label_mapping_json.strip():
        try:
            raw_map = json.loads(label_mapping_json)
            custom_mapping = {str(k).strip().lower(): int(v) for k, v in raw_map.items()}
        except Exception as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid label_mapping_json: {exc}") from exc

    settings.ensure_storage_dirs()
    max_bytes = settings.MAX_DATASET_SIZE_MB * 1024 * 1024
    dest_name = f"dataset_{uuid.uuid4().hex}.csv"
    dest_path = (settings.datasets_dir / dest_name).resolve()

    total_size = 0
    try:
        with open(dest_path, "wb") as out:
            while True:
                chunk = await file.read(1024 * 512)
                if not chunk:
                    break
                total_size += len(chunk)
                if total_size > max_bytes:
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail=f"Dataset exceeds {settings.MAX_DATASET_SIZE_MB} MB limit.",
                    )
                out.write(chunk)

        info = validate_and_inspect_csv(dest_path, label_column=label_column, custom_mapping=custom_mapping)
        if custom_mapping:
            info["label_mapping"] = custom_mapping

        dataset = Dataset(
            uploaded_by=admin.id,
            name=name.strip(),
            description=description.strip() if description else None,
            dataset_type="PE_STATIC_CSV" if info["matches_pe_schema"] else "CUSTOM_FEATURE_CSV",
            file_path=str(dest_path),
            sample_count=info["row_count"],
            benign_count=info["benign_count"],
            ransomware_count=info["ransomware_count"],
            validation_status="VALIDATED",
            metadata_json=info,
        )
        db.add(dataset)
        db.add(
            AdminLog(
                admin_id=admin.id,
                action="DATASET_UPLOADED",
                details=f"Uploaded dataset '{dataset.name}' ({dataset.sample_count} rows, {len(info['feature_columns'])} features).",
                ip_address=get_client_ip(request),
            )
        )
        db.commit()
        db.refresh(dataset)
        return {
            "id": str(dataset.id),
            "name": dataset.name,
            "sample_count": dataset.sample_count,
            "benign_count": dataset.benign_count,
            "ransomware_count": dataset.ransomware_count,
            "validation_status": dataset.validation_status,
            "metadata": dataset.metadata_json,
        }
    except HTTPException:
        dest_path.unlink(missing_ok=True)
        raise
    except ValueError as exc:
        dest_path.unlink(missing_ok=True)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except Exception as exc:
        dest_path.unlink(missing_ok=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Dataset processing error: {exc}") from exc


@router.get("/{dataset_id}")
def get_dataset_detail(
    dataset_id: uuid.UUID,
    _admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    dataset = db.get(Dataset, dataset_id)
    if not dataset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Dataset not found.")
    return {
        "id": str(dataset.id),
        "name": dataset.name,
        "description": dataset.description,
        "dataset_type": dataset.dataset_type,
        "sample_count": dataset.sample_count,
        "benign_count": dataset.benign_count,
        "ransomware_count": dataset.ransomware_count,
        "validation_status": dataset.validation_status,
        "metadata": dataset.metadata_json or {},
        "created_at": dataset.created_at.isoformat(),
    }


@router.delete("/{dataset_id}")
def delete_dataset(
    dataset_id: uuid.UUID,
    request: Request,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    dataset = db.get(Dataset, dataset_id)
    if not dataset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Dataset not found.")

    fp = Path(dataset.file_path)
    name = dataset.name
    db.delete(dataset)
    db.add(
        AdminLog(
            admin_id=admin.id,
            action="DATASET_DELETED",
            details=f"Deleted dataset '{name}' (id={dataset_id}).",
            ip_address=get_client_ip(request),
        )
    )
    db.commit()
    if fp.exists():
        fp.unlink(missing_ok=True)
    return {"message": f"Dataset '{name}' deleted."}
