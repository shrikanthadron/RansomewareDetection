"""File scans, extracted static PE features, and prediction results ORM models."""

import uuid
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.core.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class FileScan(Base):
    __tablename__ = "file_scans"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    file_name: Mapped[str] = mapped_column(String(255), nullable=False)
    original_file_name: Mapped[str] = mapped_column(String(255), nullable=False)
    file_path: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    file_size: Mapped[int] = mapped_column(BigInteger, nullable=False)
    file_type: Mapped[str] = mapped_column(String(64), nullable=False)
    sha256_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    md5_hash: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    upload_timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, index=True
    )
    scan_status: Mapped[str] = mapped_column(String(32), nullable=False, default="PENDING")
    scan_duration: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    is_user_flagged: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    result_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("prediction_results.id", ondelete="SET NULL", use_alter=True, name="fk_file_scans_result_id"),
        nullable=True,
    )

    user = relationship("User", back_populates="file_scans")
    features = relationship("ExtractedFeature", back_populates="scan", cascade="all, delete-orphan")
    predictions = relationship(
        "PredictionResult",
        back_populates="scan",
        foreign_keys="PredictionResult.scan_id",
        cascade="all, delete-orphan",
    )
    alerts = relationship("Alert", back_populates="scan", cascade="all, delete-orphan")
    reports = relationship("ScanReport", back_populates="scan")
    quarantine_records = relationship("QuarantineRecord", back_populates="scan")

    __table_args__ = (
        Index("ix_file_scans_user_timestamp", "user_id", "upload_timestamp"),
        Index("ix_file_scans_status", "scan_status"),
    )


class ExtractedFeature(Base):
    __tablename__ = "extracted_features"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("file_scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    feature_name: Mapped[str] = mapped_column(String(128), nullable=False)
    feature_value: Mapped[str] = mapped_column(Text, nullable=False)
    feature_type: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)

    scan = relationship("FileScan", back_populates="features")

    __table_args__ = (Index("ix_extracted_features_scan_name", "scan_id", "feature_name"),)


class PredictionResult(Base):
    __tablename__ = "prediction_results"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("file_scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    algorithm_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("algorithms.id", ondelete="SET NULL"), nullable=True
    )
    model_training_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("model_training.id", ondelete="SET NULL"), nullable=True
    )
    prediction: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False, index=True)
    risk_level: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    ml_used: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    explanation: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow, index=True)

    scan = relationship("FileScan", back_populates="predictions", foreign_keys=[scan_id])
    algorithm = relationship("Algorithm", back_populates="predictions")
    model_training = relationship("ModelTraining", back_populates="predictions")
