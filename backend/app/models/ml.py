"""ML algorithms, datasets, and model training ORM models."""

import uuid
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.core.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Algorithm(Base):
    __tablename__ = "algorithms"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    algorithm_name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    model_version: Mapped[str] = mapped_column(String(50), nullable=False, default="1.0.0")
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)

    trainings = relationship("ModelTraining", back_populates="algorithm")
    predictions = relationship("PredictionResult", back_populates="algorithm")


class Dataset(Base):
    __tablename__ = "datasets"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    uploaded_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    dataset_type: Mapped[str] = mapped_column(String(50), nullable=False, default="PE_STATIC_CSV")
    file_path: Mapped[str] = mapped_column(String(512), nullable=False)
    sample_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    benign_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    ransomware_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    validation_status: Mapped[str] = mapped_column(String(32), nullable=False, default="VALIDATED")
    metadata_json: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)

    uploader = relationship("User", back_populates="datasets")
    trainings = relationship("ModelTraining", back_populates="dataset", cascade="all, delete-orphan")


class ModelTraining(Base):
    __tablename__ = "model_training"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    dataset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("datasets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    algorithm_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("algorithms.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    training_status: Mapped[str] = mapped_column(String(32), nullable=False, default="PENDING", index=True)
    training_date: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    model_version: Mapped[str] = mapped_column(String(64), nullable=False)
    accuracy: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    precision: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    recall: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    f1_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    roc_auc: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    confusion_matrix: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    training_parameters: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    evaluation_details: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    artifact_path: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, index=True)
    created_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)

    dataset = relationship("Dataset", back_populates="trainings")
    algorithm = relationship("Algorithm", back_populates="trainings")
    predictions = relationship("PredictionResult", back_populates="model_training")

    __table_args__ = (Index("ix_model_training_active", "is_active", "training_status"),)
