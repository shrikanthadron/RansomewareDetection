"""Supervised Machine Learning Engine for RansomShield AI.

Supports Random Forest, Decision Tree, Support Vector Machine (SVM), and XGBoost.
Prevents data leakage by fitting all imputers, scalers, and feature selectors
strictly on the training split. Verifies model artifact SHA-256 integrity on load.
"""

from datetime import datetime, timezone
import hashlib
import logging
from pathlib import Path
import threading
import time
from typing import Any, Dict, List, Optional, Tuple
import uuid

import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_selection import SelectKBest, chi2, mutual_info_classif
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import MinMaxScaler, StandardScaler
from sklearn.svm import SVC
from sklearn.tree import DecisionTreeClassifier
from sqlalchemy.orm import Session
from xgboost import XGBClassifier

from app.core.config import settings
from app.core.database import SessionLocal
from app.models.ml import Algorithm, Dataset, ModelTraining
from app.models.operations import Alert
from app.services.pe_extractor import MODEL_FEATURE_NAMES, SCHEMA_VERSION
from app.services.ws_manager import ws_manager

logger = logging.getLogger(__name__)

# Active training job state tracking for live progress & safe cancellation
_JOB_LOCK = threading.Lock()
_JOB_STATES: Dict[str, Dict[str, Any]] = {}
_CANCEL_FLAGS: Dict[str, threading.Event] = {}

DEFAULT_BENIGN_VALUES = {"0", "benign", "legitimate", "clean", "safe", "normal", "false"}
DEFAULT_MALICIOUS_VALUES = {"1", "ransomware", "malware", "malicious", "threat", "infected", "true"}


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def get_job_state(training_id: str) -> Optional[Dict[str, Any]]:
    with _JOB_LOCK:
        state = _JOB_STATES.get(training_id)
        return dict(state) if state else None


def request_cancel_job(training_id: str) -> bool:
    with _JOB_LOCK:
        ev = _CANCEL_FLAGS.get(training_id)
        if ev:
            ev.set()
            return True
    return False


def _update_job_state(training_id: str, progress: int, stage: str, log_line: Optional[str] = None) -> None:
    with _JOB_LOCK:
        state = _JOB_STATES.setdefault(training_id, {"progress": 0, "stage": "INITIALIZING", "logs": []})
        state["progress"] = progress
        state["stage"] = stage
        if log_line:
            ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
            state["logs"].append(f"[{ts}] {log_line}")
        snapshot = dict(state)

    ws_manager.broadcast_threadsafe({
        "type": "training_progress",
        "training_id": training_id,
        "progress": snapshot["progress"],
        "stage": snapshot["stage"],
        "logs": snapshot["logs"][-20:],
    })


def map_labels(series: pd.Series, custom_mapping: Optional[Dict[str, int]] = None) -> pd.Series:
    """Normalize diverse dataset label values to binary 0 (BENIGN) and 1 (RANSOMWARE)."""
    mapped: List[int] = []
    for raw in series:
        if pd.isna(raw):
            raise ValueError("Label column contains missing values.")
        if isinstance(raw, (int, np.integer)):
            val = int(raw)
            if val in (0, 1):
                mapped.append(val)
                continue
        if isinstance(raw, (float, np.floating)) and raw in (0.0, 1.0):
            mapped.append(int(raw))
            continue

        s = str(raw).strip().lower()
        if custom_mapping and s in custom_mapping:
            mapped.append(int(custom_mapping[s]))
        elif s in DEFAULT_BENIGN_VALUES:
            mapped.append(0)
        elif s in DEFAULT_MALICIOUS_VALUES:
            mapped.append(1)
        else:
            raise ValueError(
                f"Unrecognized label value '{raw}'. Supported defaults: 0/1, benign/ransomware, legitimate/malware, "
                "or provide explicit label mapping."
            )
    return pd.Series(mapped, index=series.index, dtype="int64")


def validate_and_inspect_csv(
    csv_path: Path,
    label_column: str = "label",
    custom_mapping: Optional[Dict[str, int]] = None,
) -> Dict[str, Any]:
    """Safely inspect and validate an uploaded CSV dataset without executing anything."""
    df = pd.read_csv(csv_path)
    if df.empty:
        raise ValueError("Dataset CSV is empty.")
    if len(df) < 20:
        raise ValueError("Dataset must contain at least 20 rows for stratified train/test evaluation.")

    # Auto-detect common label column names if requested default isn't exact
    actual_label_col = label_column
    if actual_label_col not in df.columns:
        lower_map = {c.lower().strip(): c for c in df.columns}
        for candidate in [label_column.lower(), "label", "class", "target", "malware", "is_ransomware", "legitimate"]:
            if candidate in lower_map:
                actual_label_col = lower_map[candidate]
                break
        else:
            raise ValueError(f"Label column '{label_column}' not found. Available columns: {list(df.columns)}")

    y = map_labels(df[actual_label_col], custom_mapping)
    benign_count = int((y == 0).sum())
    ransomware_count = int((y == 1).sum())
    if benign_count < 5 or ransomware_count < 5:
        raise ValueError(
            f"Both classes require at least 5 samples (found benign={benign_count}, ransomware={ransomware_count})."
        )

    # Identify usable numeric feature columns (excluding label and obvious ID/hash text columns)
    drop_candidates = {actual_label_col, "sha256", "md5", "hash", "filename", "file_name", "id", "name"}
    feature_cols: List[str] = []
    for col in df.columns:
        if col == actual_label_col or col.lower() in drop_candidates:
            continue
        if pd.api.types.is_numeric_dtype(df[col]):
            feature_cols.append(col)
        else:
            # Check if coercible to numeric for mostly numeric columns
            coerced = pd.to_numeric(df[col], errors="coerce")
            if coerced.notna().mean() >= 0.8:
                feature_cols.append(col)

    if len(feature_cols) < 2:
        raise ValueError("Dataset must contain at least 2 numeric feature columns.")

    missing_by_col = {col: int(df[col].isna().sum()) for col in df.columns if int(df[col].isna().sum()) > 0}
    duplicate_rows = int(df.duplicated().sum())
    matches_pe_schema = all(col in df.columns for col in MODEL_FEATURE_NAMES)

    preview_df = df.head(15).fillna("")
    return {
        "row_count": int(len(df)),
        "column_count": int(len(df.columns)),
        "columns": [str(c) for c in df.columns],
        "label_column": actual_label_col,
        "feature_columns": feature_cols,
        "benign_count": benign_count,
        "ransomware_count": ransomware_count,
        "missing_values_total": int(df.isna().sum().sum()),
        "missing_by_column": missing_by_col,
        "duplicate_rows": duplicate_rows,
        "file_size_bytes": int(csv_path.stat().st_size),
        "matches_pe_schema": matches_pe_schema,
        "pe_schema_version": SCHEMA_VERSION if matches_pe_schema else "CUSTOM",
        "preview": preview_df.to_dict(orient="records"),
    }


def _build_estimator(algorithm_name: str, params: Dict[str, Any], pos_weight: float) -> Any:
    algo = algorithm_name.lower()
    if "random forest" in algo:
        return RandomForestClassifier(
            n_estimators=int(params.get("n_estimators", 200)),
            max_depth=params.get("max_depth", None),
            min_samples_split=int(params.get("min_samples_split", 2)),
            class_weight=params.get("class_weight", "balanced"),
            random_state=42,
            n_jobs=1,
        )
    if "decision tree" in algo:
        return DecisionTreeClassifier(
            max_depth=params.get("max_depth", 12),
            min_samples_split=int(params.get("min_samples_split", 4)),
            class_weight=params.get("class_weight", "balanced"),
            random_state=42,
        )
    if "support vector" in algo or "svm" in algo:
        return SVC(
            C=float(params.get("C", 1.5)),
            kernel=str(params.get("kernel", "rbf")),
            probability=True,
            class_weight="balanced",
            random_state=42,
        )
    if "xgboost" in algo:
        return XGBClassifier(
            n_estimators=int(params.get("n_estimators", 200)),
            max_depth=int(params.get("max_depth", 6)),
            learning_rate=float(params.get("learning_rate", 0.08)),
            scale_pos_weight=float(params.get("scale_pos_weight", pos_weight)),
            eval_metric="logloss",
            random_state=42,
            n_jobs=1,
        )
    raise ValueError(f"Unsupported algorithm: {algorithm_name}")


def _save_evaluation_plots(
    training_id: str,
    cm: np.ndarray,
    fpr_arr: np.ndarray,
    tpr_arr: np.ndarray,
    roc_auc_val: float,
    algo_name: str,
) -> Dict[str, str]:
    settings.ensure_storage_dirs()
    cm_path = settings.models_dir / f"cm_{training_id}.png"
    roc_path = settings.models_dir / f"roc_{training_id}.png"

    plt.style.use("dark_background")
    fig, ax = plt.subplots(figsize=(5, 4))
    sns.heatmap(
        cm,
        annot=True,
        fmt="d",
        cmap="Blues",
        xticklabels=["Benign (0)", "Ransomware (1)"],
        yticklabels=["Benign (0)", "Ransomware (1)"],
        ax=ax,
    )
    ax.set_title(f"Confusion Matrix — {algo_name}")
    ax.set_xlabel("Predicted Label")
    ax.set_ylabel("True Label")
    plt.tight_layout()
    fig.savefig(cm_path, dpi=130)
    plt.close(fig)

    fig2, ax2 = plt.subplots(figsize=(5, 4))
    ax2.plot(fpr_arr, tpr_arr, color="#22d3ee", lw=2, label=f"ROC Curve (AUC = {roc_auc_val:.4f})")
    ax2.plot([0, 1], [0, 1], color="#64748b", lw=1, linestyle="--")
    ax2.set_xlabel("False Positive Rate")
    ax2.set_ylabel("True Positive Rate (Recall)")
    ax2.set_title(f"ROC Curve — {algo_name}")
    ax2.legend(loc="lower right")
    plt.tight_layout()
    fig2.savefig(roc_path, dpi=130)
    plt.close(fig2)

    return {"confusion_matrix_plot": str(cm_path), "roc_plot": str(roc_path)}


def _downsample_curve(x_arr: np.ndarray, y_arr: np.ndarray, max_points: int = 40) -> List[Dict[str, float]]:
    if len(x_arr) <= max_points:
        indices = range(len(x_arr))
    else:
        indices = np.linspace(0, len(x_arr) - 1, max_points, dtype=int)
    return [{"x": round(float(x_arr[i]), 4), "y": round(float(y_arr[i]), 4)} for i in indices]


def run_training_job(training_id: uuid.UUID) -> None:
    """Execute ML training pipeline in background thread with zero data leakage."""
    tid = str(training_id)
    cancel_event = threading.Event()
    with _JOB_LOCK:
        _CANCEL_FLAGS[tid] = cancel_event

    db: Session = SessionLocal()
    try:
        record = db.get(ModelTraining, training_id)
        if not record:
            return
        dataset = db.get(Dataset, record.dataset_id)
        algorithm = db.get(Algorithm, record.algorithm_id)
        if not dataset or not algorithm:
            record.training_status = "FAILED"
            db.commit()
            return

        record.training_status = "RUNNING"
        db.commit()
        _update_job_state(tid, 5, "LOADING_DATASET", f"Loading dataset '{dataset.name}'...")

        if cancel_event.is_set():
            raise InterruptedError("Training cancelled by administrator.")

        params = record.training_parameters or {}
        df = pd.read_csv(dataset.file_path)

        meta = dataset.metadata_json or {}
        label_col = meta.get("label_column", "label")
        feature_cols: List[str] = meta.get("feature_columns") or []
        custom_map = meta.get("label_mapping")

        # Clean duplicates if requested
        remove_duplicates = bool(params.get("remove_duplicates", True))
        if remove_duplicates:
            before_n = len(df)
            df = df.drop_duplicates().reset_index(drop=True)
            _update_job_state(tid, 15, "CLEANING", f"Removed {before_n - len(df)} duplicate rows.")

        y = map_labels(df[label_col], custom_map)
        X_raw = df[feature_cols].apply(pd.to_numeric, errors="coerce")

        if cancel_event.is_set():
            raise InterruptedError("Training cancelled by administrator.")

        test_size = float(params.get("test_size", 0.2))
        test_size = min(0.4, max(0.1, test_size))
        _update_job_state(
            tid, 25, "SPLITTING",
            f"Performing stratified {int((1-test_size)*100)}/{int(test_size*100)} train/test split..."
        )
        X_train, X_test, y_train, y_test = train_test_split(
            X_raw, y, test_size=test_size, random_state=42, stratify=y
        )

        # Build preprocessing steps fit STRICTLY on X_train
        steps: List[Tuple[str, Any]] = []
        steps.append(("imputer", SimpleImputer(strategy="median")))

        fs_method = str(params.get("feature_selection", "none")).lower()
        k_features = int(params.get("k_features", min(20, len(feature_cols))))
        k_features = max(2, min(k_features, len(feature_cols)))

        algo_lower = algorithm.algorithm_name.lower()
        if fs_method == "chi2":
            # Chi-square requires non-negative features
            steps.append(("scaler", MinMaxScaler()))
            steps.append(("selector", SelectKBest(score_func=chi2, k=k_features)))
        elif fs_method == "mutual_info":
            if "svm" in algo_lower or "support vector" in algo_lower:
                steps.append(("scaler", StandardScaler()))
            steps.append(("selector", SelectKBest(score_func=mutual_info_classif, k=k_features)))
        elif "svm" in algo_lower or "support vector" in algo_lower:
            steps.append(("scaler", StandardScaler()))

        neg_cnt = int((y_train == 0).sum())
        pos_cnt = max(int((y_train == 1).sum()), 1)
        pos_weight = neg_cnt / pos_cnt

        estimator = _build_estimator(algorithm.algorithm_name, params, pos_weight)
        steps.append(("model", estimator))
        pipeline = Pipeline(steps)

        if cancel_event.is_set():
            raise InterruptedError("Training cancelled by administrator.")

        _update_job_state(tid, 45, "TRAINING", f"Training {algorithm.algorithm_name} on {len(X_train)} samples...")
        t_start = time.perf_counter()
        pipeline.fit(X_train, y_train)
        train_duration = round(time.perf_counter() - t_start, 4)

        if cancel_event.is_set():
            raise InterruptedError("Training cancelled by administrator.")

        # Optional cross-validation on training set only
        cv_folds = int(params.get("cv_folds", 0))
        cv_scores_summary = None
        if cv_folds in (3, 5, 10) and len(X_train) >= cv_folds * 4:
            _update_job_state(tid, 65, "CROSS_VALIDATION", f"Running {cv_folds}-fold stratified cross-validation...")
            cv = StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=42)
            cv_f1 = cross_val_score(pipeline, X_train, y_train, cv=cv, scoring="f1")
            cv_scores_summary = {
                "folds": cv_folds,
                "mean_f1": round(float(cv_f1.mean()), 4),
                "std_f1": round(float(cv_f1.std()), 4),
            }

        _update_job_state(tid, 80, "EVALUATING", f"Evaluating on {len(X_test)} holdout test samples...")
        p_start = time.perf_counter()
        y_pred = pipeline.predict(X_test)
        y_prob = pipeline.predict_proba(X_test)[:, 1]
        pred_duration = round(time.perf_counter() - p_start, 4)

        acc = float(accuracy_score(y_test, y_pred))
        prec = float(precision_score(y_test, y_pred, zero_division=0))
        rec = float(recall_score(y_test, y_pred, zero_division=0))
        f1 = float(f1_score(y_test, y_pred, zero_division=0))
        roc_auc_val = float(roc_auc_score(y_test, y_prob))
        cm = confusion_matrix(y_test, y_pred, labels=[0, 1])
        tn, fp, fn, tp = int(cm[0, 0]), int(cm[0, 1]), int(cm[1, 0]), int(cm[1, 1])
        fpr_rate = round(fp / max(fp + tn, 1), 4)
        fnr_rate = round(fn / max(fn + tp, 1), 4)

        fpr_arr, tpr_arr, _ = roc_curve(y_test, y_prob)
        pr_prec, pr_rec, _ = precision_recall_curve(y_test, y_prob)

        # Extract selected features & feature importances if supported
        selected_features = list(feature_cols)
        if "selector" in pipeline.named_steps:
            mask = pipeline.named_steps["selector"].get_support()
            selected_features = [f for f, keep in zip(feature_cols, mask) if keep]

        top_features: List[Dict[str, Any]] = []
        fitted_model = pipeline.named_steps["model"]
        if hasattr(fitted_model, "feature_importances_"):
            imps = fitted_model.feature_importances_
            paired = sorted(zip(selected_features, imps), key=lambda x: x[1], reverse=True)
            top_features = [
                {"feature": name, "importance": round(float(val), 5)}
                for name, val in paired[:15]
            ]

        plot_paths = _save_evaluation_plots(tid, cm, fpr_arr, tpr_arr, roc_auc_val, algorithm.algorithm_name)

        # Persist versioned model bundle with metadata & integrity checksum
        settings.ensure_storage_dirs()
        artifact_path = settings.models_dir / f"model_{tid}.joblib"
        bundle = {
            "pipeline": pipeline,
            "feature_columns": feature_cols,
            "selected_features": selected_features,
            "schema_version": SCHEMA_VERSION if all(c in feature_cols for c in MODEL_FEATURE_NAMES) else "CUSTOM",
            "algorithm_name": algorithm.algorithm_name,
            "model_version": record.model_version,
            "training_id": tid,
        }
        joblib.dump(bundle, artifact_path)
        artifact_sha256 = _sha256_file(artifact_path)

        with _JOB_LOCK:
            job_logs = list(_JOB_STATES.get(tid, {}).get("logs", []))

        record.training_status = "COMPLETED"
        record.training_date = datetime.now(timezone.utc)
        record.accuracy = round(acc, 4)
        record.precision = round(prec, 4)
        record.recall = round(rec, 4)
        record.f1_score = round(f1, 4)
        record.roc_auc = round(roc_auc_val, 4)
        record.confusion_matrix = {"tn": tn, "fp": fp, "fn": fn, "tp": tp, "matrix": cm.tolist()}
        record.artifact_path = str(artifact_path)
        record.evaluation_details = {
            "fpr": fpr_rate,
            "fnr": fnr_rate,
            "training_duration_sec": train_duration,
            "prediction_duration_sec": pred_duration,
            "train_samples": int(len(X_train)),
            "test_samples": int(len(X_test)),
            "feature_columns": feature_cols,
            "selected_features": selected_features,
            "top_features": top_features,
            "roc_curve": _downsample_curve(fpr_arr, tpr_arr),
            "pr_curve": _downsample_curve(pr_rec, pr_prec),
            "cv_summary": cv_scores_summary,
            "plots": plot_paths,
            "artifact_sha256": artifact_sha256,
            "logs": job_logs,
        }

        # Auto-activate if no active model currently exists
        existing_active = db.query(ModelTraining).filter(ModelTraining.is_active.is_(True)).first()
        if not existing_active:
            record.is_active = True

        # Notify admin user who triggered training
        if record.created_by:
            db.add(
                Alert(
                    user_id=record.created_by,
                    alert_type="TRAINING_COMPLETE",
                    severity="INFO",
                    title=f"Model Training Completed: {algorithm.algorithm_name} ({record.model_version})",
                    description=(
                        f"Training completed in {train_duration:.2f}s. "
                        f"Accuracy: {acc*100:.2f}%, Recall: {rec*100:.2f}%, F1: {f1*100:.2f}%."
                    ),
                )
            )

        db.commit()
        _update_job_state(
            tid,
            100,
            "COMPLETED",
            f"Completed! Accuracy={acc*100:.2f}%, Recall={rec*100:.2f}%, ROC-AUC={roc_auc_val:.4f}",
        )
    except InterruptedError as exc:
        logger.info("Training job %s cancelled: %s", tid, exc)
        rec_obj = db.get(ModelTraining, training_id)
        if rec_obj:
            rec_obj.training_status = "CANCELLED"
            db.commit()
        _update_job_state(tid, 0, "CANCELLED", str(exc))
    except Exception as exc:
        logger.exception("Training job %s failed", tid)
        rec_obj = db.get(ModelTraining, training_id)
        if rec_obj:
            rec_obj.training_status = "FAILED"
            rec_obj.evaluation_details = {"error": str(exc)}
            if rec_obj.created_by:
                db.add(
                    Alert(
                        user_id=rec_obj.created_by,
                        alert_type="TRAINING_FAILED",
                        severity="HIGH",
                        title="Model Training Failed",
                        description=f"Training job {tid} failed: {exc}",
                    )
                )
            db.commit()
        _update_job_state(tid, 0, "FAILED", f"Error: {exc}")
    finally:
        with _JOB_LOCK:
            _CANCEL_FLAGS.pop(tid, None)
        db.close()


def predict_from_features(db: Session, features: Dict[str, Any]) -> Dict[str, Any]:
    """Run inference using the currently active verified ML model if compatible & available."""
    active_model = (
        db.query(ModelTraining)
        .filter(ModelTraining.is_active.is_(True), ModelTraining.training_status == "COMPLETED")
        .first()
    )
    if not active_model or not active_model.artifact_path:
        return {"ml_used": False, "reason": "No active trained ML model configured."}

    artifact_path = Path(active_model.artifact_path)
    if not artifact_path.exists():
        return {"ml_used": False, "reason": "Active model artifact file is missing."}

    # Integrity verification before deserializing joblib artifact
    expected_sha = (active_model.evaluation_details or {}).get("artifact_sha256")
    if expected_sha:
        actual_sha = _sha256_file(artifact_path)
        if actual_sha.lower() != expected_sha.lower():
            logger.error("Model artifact SHA-256 mismatch for %s!", active_model.id)
            return {"ml_used": False, "reason": "Active model artifact failed SHA-256 integrity verification."}

    bundle = joblib.load(artifact_path)
    pipeline = bundle["pipeline"]
    feature_columns: List[str] = bundle["feature_columns"]

    # Build aligned single-row DataFrame preserving exact training column order
    row_data: Dict[str, float] = {}
    missing_cols = 0
    for col in feature_columns:
        if col in features:
            row_data[col] = float(features[col])
        else:
            row_data[col] = np.nan
            missing_cols += 1

    # If the model was trained on a totally incompatible custom CSV (e.g. <50% PE feature overlap)
    if len(feature_columns) > 0 and (missing_cols / len(feature_columns)) > 0.5:
        return {
            "ml_used": False,
            "reason": "Active ML model feature schema does not match static PE features.",
        }

    X_df = pd.DataFrame([row_data], columns=feature_columns)
    prob = float(pipeline.predict_proba(X_df)[0][1])

    algorithm = db.get(Algorithm, active_model.algorithm_id)
    top_feats = (active_model.evaluation_details or {}).get("top_features", [])[:5]
    return {
        "ml_used": True,
        "algorithm_id": active_model.algorithm_id,
        "algorithm_name": algorithm.algorithm_name if algorithm else "Unknown",
        "model_training_id": active_model.id,
        "model_version": active_model.model_version,
        "malicious_probability": prob,
        "top_features": top_feats,
    }
