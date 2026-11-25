"""ML algorithms, model training jobs, analytics, and model lifecycle management."""

from pathlib import Path
import threading
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.api.deps import get_client_ip, get_current_user, require_admin
from app.core.database import get_db
from app.models.ml import Algorithm, Dataset, ModelTraining
from app.models.operations import AdminLog
from app.models.user import User
from app.schemas.common import TrainingStartRequest
from app.services.ml_engine import get_job_state, request_cancel_job, run_training_job

router = APIRouter(prefix="/api/ml", tags=["Machine Learning"])


@router.get("/algorithms")
def list_algorithms(
    _user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    algos = db.query(Algorithm).filter(Algorithm.is_active.is_(True)).order_by(Algorithm.algorithm_name).all()
    return [
        {
            "id": str(a.id),
            "algorithm_name": a.algorithm_name,
            "model_version": a.model_version,
            "description": a.description,
        }
        for a in algos
    ]


@router.get("/models")
def list_trained_models(
    _user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    rows = (
        db.query(ModelTraining, Algorithm.algorithm_name, Dataset.name)
        .join(Algorithm, ModelTraining.algorithm_id == Algorithm.id)
        .join(Dataset, ModelTraining.dataset_id == Dataset.id)
        .order_by(ModelTraining.created_at.desc())
        .all()
    )
    items = []
    for mt, algo_name, ds_name in rows:
        live = get_job_state(str(mt.id)) if mt.training_status in ("PENDING", "RUNNING") else None
        items.append({
            "id": str(mt.id),
            "dataset_id": str(mt.dataset_id),
            "dataset_name": ds_name,
            "algorithm_id": str(mt.algorithm_id),
            "algorithm_name": algo_name,
            "training_status": mt.training_status,
            "training_date": mt.training_date.isoformat(),
            "model_version": mt.model_version,
            "accuracy": mt.accuracy,
            "precision": mt.precision,
            "recall": mt.recall,
            "f1_score": mt.f1_score,
            "roc_auc": mt.roc_auc,
            "confusion_matrix": mt.confusion_matrix,
            "training_parameters": mt.training_parameters,
            "evaluation_details": mt.evaluation_details,
            "is_active": mt.is_active,
            "live_progress": live,
        })
    return items


@router.post("/train", status_code=status.HTTP_202_ACCEPTED)
def start_training(
    payload: TrainingStartRequest,
    request: Request,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    dataset = db.get(Dataset, payload.dataset_id)
    if not dataset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Dataset not found.")
    algorithm = db.get(Algorithm, payload.algorithm_id)
    if not algorithm:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Algorithm not found.")

    params = {
        "test_size": payload.test_size,
        "feature_selection": payload.feature_selection,
        "k_features": payload.k_features,
        "cv_folds": payload.cv_folds,
        "remove_duplicates": payload.remove_duplicates,
        **payload.hyperparameters,
    }
    record = ModelTraining(
        dataset_id=dataset.id,
        algorithm_id=algorithm.id,
        training_status="PENDING",
        model_version=payload.model_version.strip(),
        training_parameters=params,
        created_by=admin.id,
        is_active=False,
    )
    db.add(record)
    db.add(
        AdminLog(
            admin_id=admin.id,
            action="MODEL_TRAINING_STARTED",
            details=f"Started {algorithm.algorithm_name} v{record.model_version} on dataset '{dataset.name}'.",
            ip_address=get_client_ip(request),
        )
    )
    db.commit()
    db.refresh(record)

    t = threading.Thread(target=run_training_job, args=(record.id,), daemon=True)
    t.start()

    return {
        "training_id": str(record.id),
        "status": record.training_status,
        "message": "Training job started.",
    }


@router.get("/train/{training_id}/status")
def get_training_status(
    training_id: uuid.UUID,
    _user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    record = db.get(ModelTraining, training_id)
    if not record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Training record not found.")
    live = get_job_state(str(training_id))
    return {
        "id": str(record.id),
        "training_status": record.training_status,
        "live_progress": live,
        "accuracy": record.accuracy,
        "precision": record.precision,
        "recall": record.recall,
        "f1_score": record.f1_score,
        "roc_auc": record.roc_auc,
        "confusion_matrix": record.confusion_matrix,
        "evaluation_details": record.evaluation_details,
    }


@router.post("/train/{training_id}/cancel")
def cancel_training(
    training_id: uuid.UUID,
    request: Request,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    record = db.get(ModelTraining, training_id)
    if not record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Training job not found.")
    cancelled = request_cancel_job(str(training_id))
    db.add(
        AdminLog(
            admin_id=admin.id,
            action="MODEL_TRAINING_CANCEL_REQUESTED",
            details=f"Cancellation requested for training {training_id} (active={cancelled}).",
            ip_address=get_client_ip(request),
        )
    )
    db.commit()
    return {"cancelled_signal_sent": cancelled}


@router.post("/models/{training_id}/activate")
def activate_model(
    training_id: uuid.UUID,
    request: Request,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    model = db.get(ModelTraining, training_id)
    if not model:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Model not found.")
    if model.training_status != "COMPLETED" or not model.artifact_path or not Path(model.artifact_path).exists():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Only completed models with valid artifacts can be activated.")

    db.query(ModelTraining).filter(ModelTraining.id != model.id).update({"is_active": False})
    model.is_active = True
    algo = db.get(Algorithm, model.algorithm_id)
    db.add(
        AdminLog(
            admin_id=admin.id,
            action="MODEL_ACTIVATED",
            details=f"Activated model {algo.algorithm_name if algo else ''} v{model.model_version} (id={model.id}).",
            ip_address=get_client_ip(request),
        )
    )
    db.commit()
    return {"message": "Model activated for production inference.", "id": str(model.id)}


@router.post("/models/{training_id}/deactivate")
def deactivate_model(
    training_id: uuid.UUID,
    request: Request,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    model = db.get(ModelTraining, training_id)
    if not model:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Model not found.")
    model.is_active = False
    db.add(
        AdminLog(
            admin_id=admin.id,
            action="MODEL_DEACTIVATED",
            details=f"Deactivated model id={model.id}.",
            ip_address=get_client_ip(request),
        )
    )
    db.commit()
    return {"message": "Model deactivated.", "id": str(model.id)}


@router.get("/models/{training_id}/plot/{plot_type}")
def get_model_plot(
    training_id: uuid.UUID,
    plot_type: str,
    _user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    model = db.get(ModelTraining, training_id)
    if not model or not model.evaluation_details:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Model evaluation plots not found.")
    plots = model.evaluation_details.get("plots") or {}
    key = "confusion_matrix_plot" if plot_type == "confusion_matrix" else "roc_plot"
    path_str = plots.get(key)
    if not path_str or not Path(path_str).exists():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Plot image not found.")
    return FileResponse(path_str, media_type="image/png")
