"""Dynamic PDF report generation using ReportLab from PostgreSQL records."""

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List
import uuid

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from app.core.config import settings


def _risk_color(risk_level: str) -> colors.Color:
    mapping = {
        "LOW": colors.HexColor("#10b981"),
        "GUARDED": colors.HexColor("#eab308"),
        "MODERATE": colors.HexColor("#f97316"),
        "HIGH": colors.HexColor("#ef4444"),
        "CRITICAL": colors.HexColor("#dc2626"),
    }
    return mapping.get(risk_level, colors.HexColor("#06b6d4"))


def generate_scan_pdf_report(
    scan_data: Dict[str, Any],
    prediction_data: Dict[str, Any],
    features: List[Dict[str, Any]],
) -> Path:
    """Create a formatted individual scan PDF report from real database records."""
    settings.ensure_storage_dirs()
    filename = f"scan_report_{scan_data['id']}_{uuid.uuid4().hex[:8]}.pdf"
    output_path = settings.reports_dir / filename

    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=letter,
        rightMargin=0.65 * inch,
        leftMargin=0.65 * inch,
        topMargin=0.65 * inch,
        bottomMargin=0.65 * inch,
    )
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "RSTitle", parent=styles["Heading1"], fontSize=18, textColor=colors.HexColor("#0f172a"), spaceAfter=6
    )
    sub_style = ParagraphStyle(
        "RSSub", parent=styles["Normal"], fontSize=9.5, textColor=colors.HexColor("#475569"), spaceAfter=14
    )
    section_style = ParagraphStyle(
        "RSSection", parent=styles["Heading2"], fontSize=12.5, textColor=colors.HexColor("#0e7490"), spaceBefore=12, spaceAfter=6
    )
    body_style = ParagraphStyle("RSBody", parent=styles["Normal"], fontSize=9.5, leading=13)

    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    elements = [
        Paragraph("RansomShield AI — Static File Threat Analysis Report", title_style),
        Paragraph(f"Generated: {now_str} | Scan ID: {scan_data['id']}", sub_style),
    ]

    # File Summary Table
    elements.append(Paragraph("1. File & Scan Metadata", section_style))
    meta_rows = [
        ["Original File Name", str(scan_data.get("original_file_name", ""))],
        ["File Type / Size", f"{scan_data.get('file_type', '')} ({scan_data.get('file_size', 0):,} bytes)"],
        ["SHA-256", str(scan_data.get("sha256_hash", ""))],
        ["MD5", str(scan_data.get("md5_hash", ""))],
        ["Scan Timestamp", str(scan_data.get("upload_timestamp", ""))],
        ["Scan Duration", f"{scan_data.get('scan_duration', 0):.3f} sec"],
    ]
    meta_table = Table(meta_rows, colWidths=[1.8 * inch, 5.3 * inch])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f1f5f9")),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8.5),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("PADDING", (0, 0), (-1, -1), 5),
    ]))
    elements.append(meta_table)

    # Prediction & Risk Score
    elements.append(Paragraph("2. Classification & Risk Assessment", section_style))
    risk_level = str(prediction_data.get("risk_level", "LOW"))
    pred_rows = [
        ["Verdict", str(prediction_data.get("prediction", "UNKNOWN"))],
        ["Risk Score", f"{prediction_data.get('risk_score', 0):.2f} / 100 ({risk_level})"],
        ["Confidence", f"{prediction_data.get('confidence', 0):.2f}%"],
        ["ML Model Used", prediction_data.get("model_label", "Static Analysis Only (ML Model Not Trained)")],
        ["Model Version", str(prediction_data.get("model_version", "N/A"))],
    ]
    pred_table = Table(pred_rows, colWidths=[1.8 * inch, 5.3 * inch])
    pred_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f1f5f9")),
        ("TEXTCOLOR", (1, 1), (1, 1), _risk_color(risk_level)),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME", (1, 0), (1, 1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("PADDING", (0, 0), (-1, -1), 5),
    ]))
    elements.append(pred_table)
    elements.append(Spacer(1, 8))

    explanation = prediction_data.get("explanation") or {}
    elements.append(Paragraph(f"<b>Analysis Summary:</b> {explanation.get('summary', 'N/A')}", body_style))

    signals = explanation.get("signals") or []
    if signals:
        elements.append(Spacer(1, 6))
        elements.append(Paragraph("<b>Key Static Indicators:</b>", body_style))
        for sig in signals[:10]:
            elements.append(
                Paragraph(
                    f"• [{sig.get('severity', 'INFO')}] {sig.get('indicator')}: {sig.get('detail')}",
                    body_style,
                )
            )

    # Extracted Features Summary
    elements.append(Paragraph("3. Extracted Static PE Features", section_style))
    feat_rows = [["Feature Name", "Type", "Value"]]
    for f in features[:35]:
        feat_rows.append([str(f["feature_name"]), str(f["feature_type"]), str(f["feature_value"])])
    feat_table = Table(feat_rows, colWidths=[2.7 * inch, 1.0 * inch, 3.4 * inch])
    feat_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
        ("PADDING", (0, 0), (-1, -1), 4),
    ]))
    elements.append(feat_table)

    elements.append(Spacer(1, 14))
    elements.append(
        Paragraph(
            "<i>Disclaimer: RansomShield AI performs static Portable Executable analysis and supervised machine "
            "learning inference without executing scanned files. Risk scores are probabilistic decision-support "
            "indicators and do not guarantee detection of all threats or absence of false positives.</i>",
            ParagraphStyle("Disc", parent=styles["Normal"], fontSize=8, textColor=colors.HexColor("#64748b")),
        )
    )
    doc.build(elements)
    return output_path


def generate_admin_system_pdf_report(summary_data: Dict[str, Any]) -> Path:
    """Generate an executive admin system PDF report from live PostgreSQL metrics."""
    settings.ensure_storage_dirs()
    filename = f"admin_system_report_{uuid.uuid4().hex[:8]}.pdf"
    output_path = settings.reports_dir / filename

    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=letter,
        rightMargin=0.65 * inch,
        leftMargin=0.65 * inch,
        topMargin=0.65 * inch,
        bottomMargin=0.65 * inch,
    )
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "ASTitle", parent=styles["Heading1"], fontSize=18, textColor=colors.HexColor("#0f172a"), spaceAfter=6
    )
    section_style = ParagraphStyle(
        "ASSection", parent=styles["Heading2"], fontSize=12.5, textColor=colors.HexColor("#0e7490"), spaceBefore=12, spaceAfter=6
    )
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    elements = [
        Paragraph("RansomShield AI — System Security & ML Executive Report", title_style),
        Paragraph(f"Generated: {now_str}", styles["Normal"]),
        Spacer(1, 10),
        Paragraph("1. Platform Detection Statistics", section_style),
    ]

    stats_rows = [
        ["Metric", "Value"],
        ["Total File Scans", str(summary_data.get("total_scans", 0))],
        ["Files Scanned Today", str(summary_data.get("scans_today", 0))],
        ["Ransomware Detections", str(summary_data.get("ransomware_count", 0))],
        ["Suspicious Detections", str(summary_data.get("suspicious_count", 0))],
        ["Benign Files", str(summary_data.get("benign_count", 0))],
        ["Detection Rate (%)", f"{summary_data.get('detection_rate', 0):.2f}%"],
        ["Total Datasets", str(summary_data.get("total_datasets", 0))],
        ["Total Trained Models", str(summary_data.get("total_models", 0))],
        ["Active Alerts", str(summary_data.get("total_alerts", 0))],
        ["Quarantined Files", str(summary_data.get("quarantined_count", 0))],
    ]
    t = Table(stats_rows, colWidths=[3.2 * inch, 3.9 * inch])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("PADDING", (0, 0), (-1, -1), 5),
    ]))
    elements.append(t)

    models = summary_data.get("models", [])
    elements.append(Paragraph("2. Trained ML Models Summary", section_style))
    if models:
        m_rows = [["Algorithm", "Version", "Status", "Accuracy", "Precision", "Recall", "F1"]]
        for m in models[:15]:
            m_rows.append([
                str(m.get("algorithm_name", "")),
                str(m.get("model_version", "")),
                "ACTIVE" if m.get("is_active") else str(m.get("training_status", "")),
                f"{(m.get('accuracy') or 0)*100:.1f}%",
                f"{(m.get('precision') or 0)*100:.1f}%",
                f"{(m.get('recall') or 0)*100:.1f}%",
                f"{(m.get('f1_score') or 0)*100:.1f}%",
            ])
        mt = Table(m_rows, colWidths=[1.6 * inch, 0.9 * inch, 0.9 * inch, 0.9 * inch, 0.9 * inch, 0.9 * inch, 0.9 * inch])
        mt.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0e7490")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
            ("PADDING", (0, 0), (-1, -1), 4),
        ]))
        elements.append(mt)
    else:
        elements.append(Paragraph("No trained ML models recorded in database.", styles["Normal"]))

    doc.build(elements)
    return output_path
