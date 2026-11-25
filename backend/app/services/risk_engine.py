"""Consistent Risk Score Engine (0-100) combining ML output and static PE indicators."""

from typing import Any, Dict, List, Optional


def classify_risk_level(score: float) -> str:
    if score <= 20:
        return "LOW"
    if score <= 40:
        return "GUARDED"
    if score <= 60:
        return "MODERATE"
    if score <= 80:
        return "HIGH"
    return "CRITICAL"


def classify_verdict(score: float) -> str:
    if score >= 68:
        return "RANSOMWARE"
    if score >= 35:
        return "SUSPICIOUS"
    return "BENIGN"


def compute_static_signals(features: Dict[str, Any]) -> Dict[str, Any]:
    """Compute transparent, documented heuristic risk signals from static PE features."""
    signals: List[Dict[str, Any]] = []
    score = 0.0

    file_entropy = float(features.get("file_entropy", 0.0) or 0.0)
    max_sec_ent = float(features.get("max_section_entropy", 0.0) or 0.0)
    wx_sections = int(features.get("wx_sections", 0) or 0)
    high_ent_secs = int(features.get("high_entropy_sections", 0) or 0)
    crypto_apis = int(features.get("crypto_api_count", 0) or 0)
    injection_apis = int(features.get("injection_api_count", 0) or 0)
    file_enum_apis = int(features.get("file_enum_api_count", 0) or 0)
    persist_apis = int(features.get("persist_exec_api_count", 0) or 0)
    anti_apis = int(features.get("anti_analysis_api_count", 0) or 0)
    is_valid_pe = int(features.get("is_valid_pe", 0) or 0)
    num_imports = int(features.get("num_imports", 0) or 0)

    if is_valid_pe == 0:
        score += 18.0
        signals.append({
            "indicator": "Invalid or Malformed PE Header",
            "severity": "MEDIUM",
            "contribution": 18.0,
            "detail": "File does not parse as a standard PE executable despite executable submission.",
        })

    if file_entropy >= 7.2 or max_sec_ent >= 7.4:
        pts = 22.0 if file_entropy >= 7.4 else 15.0
        score += pts
        signals.append({
            "indicator": "High Shannon Entropy (Packed / Encrypted Payload)",
            "severity": "HIGH",
            "contribution": pts,
            "detail": f"File entropy={file_entropy:.2f}, max section entropy={max_sec_ent:.2f} (>=7.0 indicates packing or encryption).",
        })

    if wx_sections > 0:
        pts = min(20.0, 12.0 + (wx_sections - 1) * 4.0)
        score += pts
        signals.append({
            "indicator": "Writable + Executable (W+X) PE Sections",
            "severity": "HIGH",
            "contribution": pts,
            "detail": f"{wx_sections} section(s) marked both writable and executable (common in unpackers/self-modifying code).",
        })

    if high_ent_secs >= 2:
        score += 8.0
        signals.append({
            "indicator": "Multiple High-Entropy Sections",
            "severity": "MEDIUM",
            "contribution": 8.0,
            "detail": f"{high_ent_secs} sections exhibit entropy >= 7.0.",
        })

    if crypto_apis > 0 and file_enum_apis > 0:
        pts = min(22.0, 10.0 + crypto_apis * 3.0 + file_enum_apis * 2.0)
        score += pts
        signals.append({
            "indicator": "Cryptographic + File Enumeration API Combination",
            "severity": "HIGH",
            "contribution": pts,
            "detail": f"Imports {crypto_apis} crypto API(s) alongside {file_enum_apis} file enumeration/modification API(s).",
        })
    elif crypto_apis >= 2:
        pts = min(12.0, crypto_apis * 4.0)
        score += pts
        signals.append({
            "indicator": "Elevated Cryptographic API Usage",
            "severity": "MEDIUM",
            "contribution": pts,
            "detail": f"Detected {crypto_apis} cryptographic API imports.",
        })

    if injection_apis >= 2:
        pts = min(18.0, injection_apis * 4.5)
        score += pts
        signals.append({
            "indicator": "Process / Memory Injection API Imports",
            "severity": "HIGH",
            "contribution": pts,
            "detail": f"Detected {injection_apis} memory allocation/injection API imports.",
        })

    if persist_apis >= 2 or anti_apis >= 1:
        pts = min(12.0, persist_apis * 3.0 + anti_apis * 4.0)
        score += pts
        signals.append({
            "indicator": "Persistence / Anti-Analysis APIs",
            "severity": "MEDIUM",
            "contribution": pts,
            "detail": f"Execution/persistence APIs={persist_apis}, anti-debugging APIs={anti_apis}.",
        })

    if is_valid_pe == 1 and num_imports <= 3 and file_entropy >= 6.5:
        score += 10.0
        signals.append({
            "indicator": "Minimal Import Table with Elevated Entropy",
            "severity": "MEDIUM",
            "contribution": 10.0,
            "detail": f"Only {num_imports} static imports detected; suggests dynamic API resolution or packer stub.",
        })

    bounded_score = round(min(100.0, max(0.0, score)), 2)
    return {
        "static_score": bounded_score,
        "signals": signals,
    }


def evaluate_risk(
    features: Dict[str, Any],
    ml_result: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Calculate final risk score (0-100), risk level, classification, confidence, and explanation."""
    static_analysis = compute_static_signals(features)
    static_score = static_analysis["static_score"]
    signals = static_analysis["signals"]

    if ml_result and ml_result.get("ml_used"):
        malicious_prob = float(ml_result["malicious_probability"])  # 0.0 - 1.0
        ml_score = malicious_prob * 100.0
        # Weighted combination: 75% supervised ML probability, 25% documented static heuristics
        final_score = round(min(100.0, max(0.0, 0.75 * ml_score + 0.25 * static_score)), 2)
        confidence = round(max(malicious_prob, 1.0 - malicious_prob) * 100.0, 2)
        prediction = classify_verdict(final_score)
        risk_level = classify_risk_level(final_score)

        summary = (
            f"Supervised model ({ml_result.get('algorithm_name')} v{ml_result.get('model_version')}) "
            f"estimated {malicious_prob * 100:.1f}% malicious probability, combined with "
            f"{len(signals)} static PE indicator(s) (static score {static_score:.1f}/100). "
            "Predictions are probabilistic indicators and not a guarantee of safety or malice."
        )
        return {
            "prediction": prediction,
            "risk_score": final_score,
            "risk_level": risk_level,
            "confidence": confidence,
            "ml_used": True,
            "ml_notice": None,
            "explanation": {
                "summary": summary,
                "ml_probability": round(malicious_prob, 4),
                "static_heuristic_score": static_score,
                "signals": signals,
                "top_model_features": ml_result.get("top_features", []),
            },
        }

    # No active trained ML model available: static heuristic only, explicitly disclosed
    final_score = static_score
    prediction = classify_verdict(final_score)
    risk_level = classify_risk_level(final_score)
    confidence = round(50.0 + abs(final_score - 50.0) * 0.6, 2)
    notice = "ML model not trained. Static analysis is available, but ML prediction is unavailable."
    summary = (
        f"{notice} Heuristic risk score ({final_score:.1f}/100) derived strictly from "
        f"{len(signals)} static PE indicator(s)."
    )
    return {
        "prediction": prediction,
        "risk_score": final_score,
        "risk_level": risk_level,
        "confidence": confidence,
        "ml_used": False,
        "ml_notice": notice,
        "explanation": {
            "summary": summary,
            "ml_probability": None,
            "static_heuristic_score": static_score,
            "signals": signals,
            "top_model_features": [],
        },
    }
