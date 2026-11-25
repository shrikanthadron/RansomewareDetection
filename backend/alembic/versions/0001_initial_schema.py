"""Initial PostgreSQL schema for RansomShield AI.

Revision ID: 0001_initial_schema
Revises:
Create Date: 2026-11-25 14:15:00
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "0001_initial_schema"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("full_name", sa.String(150), nullable=False),
        sa.Column("email", sa.String(255), nullable=False, unique=True),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("role", sa.String(20), nullable=False, server_default="USER"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("failed_login_attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("preferences", postgresql.JSONB(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_login", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_users_email", "users", ["email"], unique=True)
    op.create_index("ix_users_role_active", "users", ["role", "is_active"])

    op.create_table(
        "algorithms",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("algorithm_name", sa.String(100), nullable=False, unique=True),
        sa.Column("model_version", sa.String(50), nullable=False, server_default="1.0.0"),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "datasets",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("uploaded_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("dataset_type", sa.String(50), nullable=False, server_default="PE_STATIC_CSV"),
        sa.Column("file_path", sa.String(512), nullable=False),
        sa.Column("sample_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("benign_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("ransomware_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("validation_status", sa.String(32), nullable=False, server_default="VALIDATED"),
        sa.Column("metadata_json", postgresql.JSONB(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "model_training",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("dataset_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("datasets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("algorithm_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("algorithms.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("training_status", sa.String(32), nullable=False, server_default="PENDING"),
        sa.Column("training_date", sa.DateTime(timezone=True), nullable=False),
        sa.Column("model_version", sa.String(64), nullable=False),
        sa.Column("accuracy", sa.Float(), nullable=True),
        sa.Column("precision", sa.Float(), nullable=True),
        sa.Column("recall", sa.Float(), nullable=True),
        sa.Column("f1_score", sa.Float(), nullable=True),
        sa.Column("roc_auc", sa.Float(), nullable=True),
        sa.Column("confusion_matrix", postgresql.JSONB(), nullable=True),
        sa.Column("training_parameters", postgresql.JSONB(), nullable=True),
        sa.Column("evaluation_details", postgresql.JSONB(), nullable=True),
        sa.Column("artifact_path", sa.String(512), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_model_training_dataset_id", "model_training", ["dataset_id"])
    op.create_index("ix_model_training_algorithm_id", "model_training", ["algorithm_id"])
    op.create_index("ix_model_training_training_status", "model_training", ["training_status"])
    op.create_index("ix_model_training_is_active", "model_training", ["is_active"])
    op.create_index("ix_model_training_active", "model_training", ["is_active", "training_status"])

    op.create_table(
        "file_scans",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("file_name", sa.String(255), nullable=False),
        sa.Column("original_file_name", sa.String(255), nullable=False),
        sa.Column("file_path", sa.String(512), nullable=True),
        sa.Column("file_size", sa.BigInteger(), nullable=False),
        sa.Column("file_type", sa.String(64), nullable=False),
        sa.Column("sha256_hash", sa.String(64), nullable=False),
        sa.Column("md5_hash", sa.String(32), nullable=False),
        sa.Column("upload_timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("scan_status", sa.String(32), nullable=False, server_default="PENDING"),
        sa.Column("scan_duration", sa.Float(), nullable=True),
        sa.Column("is_user_flagged", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("result_id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.create_index("ix_file_scans_user_id", "file_scans", ["user_id"])
    op.create_index("ix_file_scans_sha256_hash", "file_scans", ["sha256_hash"])
    op.create_index("ix_file_scans_md5_hash", "file_scans", ["md5_hash"])
    op.create_index("ix_file_scans_upload_timestamp", "file_scans", ["upload_timestamp"])
    op.create_index("ix_file_scans_user_timestamp", "file_scans", ["user_id", "upload_timestamp"])
    op.create_index("ix_file_scans_status", "file_scans", ["scan_status"])

    op.create_table(
        "prediction_results",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("file_scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("algorithm_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("algorithms.id", ondelete="SET NULL"), nullable=True),
        sa.Column("model_training_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("model_training.id", ondelete="SET NULL"), nullable=True),
        sa.Column("prediction", sa.String(32), nullable=False),
        sa.Column("risk_score", sa.Float(), nullable=False),
        sa.Column("risk_level", sa.String(32), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("ml_used", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("explanation", postgresql.JSONB(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_prediction_results_scan_id", "prediction_results", ["scan_id"])
    op.create_index("ix_prediction_results_prediction", "prediction_results", ["prediction"])
    op.create_index("ix_prediction_results_risk_score", "prediction_results", ["risk_score"])
    op.create_index("ix_prediction_results_risk_level", "prediction_results", ["risk_level"])
    op.create_index("ix_prediction_results_created_at", "prediction_results", ["created_at"])

    op.create_foreign_key(
        "fk_file_scans_result_id",
        "file_scans",
        "prediction_results",
        ["result_id"],
        ["id"],
        ondelete="SET NULL",
    )

    op.create_table(
        "extracted_features",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("file_scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("feature_name", sa.String(128), nullable=False),
        sa.Column("feature_value", sa.Text(), nullable=False),
        sa.Column("feature_type", sa.String(32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_extracted_features_scan_id", "extracted_features", ["scan_id"])
    op.create_index("ix_extracted_features_scan_name", "extracted_features", ["scan_id", "feature_name"])

    op.create_table(
        "scan_reports",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("file_scans.id", ondelete="SET NULL"), nullable=True),
        sa.Column("report_path", sa.String(512), nullable=False),
        sa.Column("report_type", sa.String(50), nullable=False),
        sa.Column("generated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_scan_reports_user_id", "scan_reports", ["user_id"])
    op.create_index("ix_scan_reports_scan_id", "scan_reports", ["scan_id"])

    op.create_table(
        "alerts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=True),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("file_scans.id", ondelete="CASCADE"), nullable=True),
        sa.Column("alert_type", sa.String(64), nullable=False),
        sa.Column("severity", sa.String(32), nullable=False),
        sa.Column("title", sa.String(200), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("is_read", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_alerts_user_id", "alerts", ["user_id"])
    op.create_index("ix_alerts_severity", "alerts", ["severity"])
    op.create_index("ix_alerts_is_read", "alerts", ["is_read"])
    op.create_index("ix_alerts_created_at", "alerts", ["created_at"])

    op.create_table(
        "process_monitoring_logs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("process_name", sa.String(255), nullable=False),
        sa.Column("process_id", sa.Integer(), nullable=False),
        sa.Column("executable_path", sa.String(1024), nullable=True),
        sa.Column("sha256_hash", sa.String(64), nullable=True),
        sa.Column("risk_score", sa.Float(), nullable=False, server_default="0"),
        sa.Column("classification", sa.String(32), nullable=False, server_default="BENIGN"),
        sa.Column("detection_source", sa.String(64), nullable=False, server_default="PSUTIL_METADATA"),
        sa.Column("action_taken", sa.String(64), nullable=False, server_default="LOG"),
        sa.Column("metadata_json", postgresql.JSONB(), nullable=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_process_monitoring_logs_process_name", "process_monitoring_logs", ["process_name"])
    op.create_index("ix_process_monitoring_logs_process_id", "process_monitoring_logs", ["process_id"])
    op.create_index("ix_process_monitoring_logs_sha256_hash", "process_monitoring_logs", ["sha256_hash"])
    op.create_index("ix_process_monitoring_logs_timestamp", "process_monitoring_logs", ["timestamp"])

    op.create_table(
        "admin_logs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("admin_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("action", sa.String(128), nullable=False),
        sa.Column("details", sa.Text(), nullable=True),
        sa.Column("ip_address", sa.String(64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_admin_logs_admin_id", "admin_logs", ["admin_id"])
    op.create_index("ix_admin_logs_action", "admin_logs", ["action"])
    op.create_index("ix_admin_logs_created_at", "admin_logs", ["created_at"])

    op.create_table(
        "system_settings",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("setting_key", sa.String(128), nullable=False, unique=True),
        sa.Column("setting_value", sa.Text(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_system_settings_setting_key", "system_settings", ["setting_key"], unique=True)

    op.create_table(
        "quarantine_records",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("file_scans.id", ondelete="SET NULL"), nullable=True),
        sa.Column("original_path", sa.String(1024), nullable=False),
        sa.Column("quarantine_path", sa.String(1024), nullable=False),
        sa.Column("sha256_hash", sa.String(64), nullable=False),
        sa.Column("quarantine_status", sa.String(32), nullable=False, server_default="QUARANTINED"),
        sa.Column("quarantined_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("restored_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
    )
    op.create_index("ix_quarantine_records_sha256_hash", "quarantine_records", ["sha256_hash"])
    op.create_index("ix_quarantine_records_quarantine_status", "quarantine_records", ["quarantine_status"])
    op.create_index("ix_quarantine_status_time", "quarantine_records", ["quarantine_status", "quarantined_at"])


def downgrade() -> None:
    op.drop_table("quarantine_records")
    op.drop_table("system_settings")
    op.drop_table("admin_logs")
    op.drop_table("process_monitoring_logs")
    op.drop_table("alerts")
    op.drop_table("scan_reports")
    op.drop_table("extracted_features")
    op.drop_constraint("fk_file_scans_result_id", "file_scans", type_="foreignkey")
    op.drop_table("prediction_results")
    op.drop_table("file_scans")
    op.drop_table("model_training")
    op.drop_table("datasets")
    op.drop_table("algorithms")
    op.drop_table("users")
