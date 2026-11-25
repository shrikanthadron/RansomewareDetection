"""Comprehensive end-to-end integration tests for RansomShield AI against PostgreSQL."""

import os
from pathlib import Path
import struct
import time
from fastapi.testclient import TestClient
import pytest

from app.main import app, bootstrap_database


def build_minimal_valid_pe() -> bytes:
    """Construct a harmless, minimal valid 64-bit PE header binary for static testing."""
    dos_header = bytearray(0x80)
    dos_header[0:2] = b"MZ"
    struct.pack_into("<I", dos_header, 0x3C, 0x80)

    pe_sig = b"PE\x00\x00"
    # COFF FileHeader: Machine=0x8664 (AMD64), NumberOfSections=1, TimeDateStamp, SizeOfOptionalHeader=240, Characteristics=0x0022
    coff = struct.pack("<HHIIIHH", 0x8664, 1, 1700000000, 0, 0, 240, 0x0022)

    # OptionalHeader (PE32+ = 0x20B, 240 bytes)
    opt = bytearray(240)
    struct.pack_into("<H", opt, 0, 0x20B)
    struct.pack_into("<I", opt, 4, 512)       # SizeOfCode
    struct.pack_into("<I", opt, 16, 0x1000)   # AddressOfEntryPoint
    struct.pack_into("<Q", opt, 24, 0x140000000)  # ImageBase
    struct.pack_into("<I", opt, 32, 0x1000)   # SectionAlignment
    struct.pack_into("<I", opt, 36, 0x200)    # FileAlignment
    struct.pack_into("<I", opt, 56, 0x2000)   # SizeOfImage
    struct.pack_into("<I", opt, 60, 0x200)    # SizeOfHeaders
    struct.pack_into("<H", opt, 68, 3)        # Subsystem CUI
    struct.pack_into("<I", opt, 108, 16)      # NumberOfRvaAndSizes

    # 1 Section header: .text (40 bytes)
    sec_hdr = bytearray(40)
    sec_hdr[0:5] = b".text"
    struct.pack_into("<I", sec_hdr, 8, 512)     # VirtualSize
    struct.pack_into("<I", sec_hdr, 12, 0x1000) # VirtualAddress
    struct.pack_into("<I", sec_hdr, 16, 512)    # SizeOfRawData
    struct.pack_into("<I", sec_hdr, 20, 0x200)  # PointerToRawData
    struct.pack_into("<I", sec_hdr, 36, 0x60000020)  # CODE | EXECUTE | READ

    headers = bytes(dos_header) + pe_sig + coff + bytes(opt) + bytes(sec_hdr)
    padded_headers = headers.ljust(0x200, b"\x00")
    text_section = b"\x90" * 512
    return padded_headers + text_section


@pytest.fixture(scope="module")
def client():
    bootstrap_database()
    with TestClient(app) as c:
        yield c


def test_full_platform_workflow(client: TestClient, tmp_path: Path):
    # 1. Health check
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"

    # 2. Register standard user & verify RBAC blocks admin endpoints
    user_email = f"analyst_{int(time.time())}@example.com"
    r = client.post(
        "/api/auth/register",
        json={"full_name": "Test Analyst", "email": user_email, "password": "StrongPassword!123"},
    )
    assert r.status_code == 201
    user_token = r.json()["access_token"]
    user_headers = {"Authorization": f"Bearer {user_token}"}

    assert client.get("/api/admin/metrics", headers=user_headers).status_code == 403
    assert client.get("/api/datasets", headers=user_headers).status_code == 403

    # 3. Login as bootstrapped admin
    admin_email = os.environ["INITIAL_ADMIN_EMAIL"]
    admin_pass = os.environ["INITIAL_ADMIN_PASSWORD"]
    r = client.post("/api/auth/login", json={"email": admin_email, "password": admin_pass})
    assert r.status_code == 200
    admin_token = r.json()["access_token"]
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    # Ensure no active ML model is enabled initially (verifies deactivation endpoint too)
    existing_models = client.get("/api/ml/models", headers=admin_headers).json()
    for em in existing_models:
        if em["is_active"]:
            assert client.post(f"/api/ml/models/{em['id']}/deactivate", headers=admin_headers).status_code == 200

    # 4. Scan minimal PE BEFORE any ML model is active -> explicit ML unavailable notice
    pe_bytes = build_minimal_valid_pe()
    r = client.post(
        "/api/scans/upload",
        headers=user_headers,
        files={"file": ("benign_test.exe", pe_bytes, "application/octet-stream")},
    )
    assert r.status_code == 201
    scan_data = r.json()
    scan_id = scan_data["id"]
    assert scan_data["file_type"] == "PE_EXE"
    assert scan_data["prediction"]["ml_used"] is False
    assert "ML model not trained" in scan_data["prediction"]["explanation"]["ml_notice"]
    assert len(scan_data["features"]) >= 30

    # 5. Scan corrupted PE gracefully without crashing
    r = client.post(
        "/api/scans/upload",
        headers=user_headers,
        files={"file": ("corrupted.exe", b"NOT_A_VALID_PE_" * 20, "application/octet-stream")},
    )
    assert r.status_code == 201
    assert r.json()["file_type"] == "CORRUPTED_OR_NON_PE"

    # 6. Generate Scan PDF Report
    r = client.post(f"/api/reports/scan/{scan_id}", headers=user_headers)
    assert r.status_code == 201
    rep_id = r.json()["id"]
    pdf_resp = client.get(f"/api/reports/{rep_id}/download", headers=user_headers)
    assert pdf_resp.status_code == 200
    assert pdf_resp.content.startswith(b"%PDF")

    # 7. Upload dataset CSV (Admin) & Train Random Forest ML model
    sample_csv = Path(__file__).resolve().parents[2] / "sample_data" / "ransomshield_sample_dataset.csv"
    with open(sample_csv, "rb") as f:
        r = client.post(
            "/api/datasets/upload",
            headers=admin_headers,
            data={"name": "Test PE Dataset", "label_column": "label"},
            files={"file": ("ransomshield_sample_dataset.csv", f, "text/csv")},
        )
    assert r.status_code == 201
    dataset_id = r.json()["id"]
    assert r.json()["sample_count"] == 300

    algos = client.get("/api/ml/algorithms", headers=admin_headers).json()
    rf_algo = next(a for a in algos if "Random Forest" in a["algorithm_name"])

    r = client.post(
        "/api/ml/train",
        headers=admin_headers,
        json={
            "dataset_id": dataset_id,
            "algorithm_id": rf_algo["id"],
            "model_version": "1.0.0-test",
            "test_size": 0.2,
            "feature_selection": "mutual_info",
            "k_features": 20,
            "cv_folds": 3,
            "hyperparameters": {"n_estimators": 60},
        },
    )
    assert r.status_code == 202
    training_id = r.json()["training_id"]

    # Wait for background training completion
    for _ in range(40):
        st = client.get(f"/api/ml/train/{training_id}/status", headers=admin_headers).json()
        if st["training_status"] == "COMPLETED":
            break
        assert st["training_status"] != "FAILED"
        time.sleep(0.5)
    assert st["training_status"] == "COMPLETED"
    assert st["accuracy"] > 0.8
    assert client.post(f"/api/ml/models/{training_id}/activate", headers=admin_headers).status_code == 200

    # 8. Rescan PE file now with active ML model
    r = client.post(f"/api/scans/{scan_id}/rescan", headers=user_headers)
    assert r.status_code == 200
    rescanned = r.json()
    assert rescanned["prediction"]["ml_used"] is True
    assert rescanned["prediction"]["model_name"] == "Random Forest"

    # 9. Quarantine & Restore verification
    dummy_file = tmp_path / "suspicious_sample.exe"
    dummy_file.write_bytes(pe_bytes)
    r = client.post(
        "/api/quarantine/quarantine",
        headers=admin_headers,
        json={"file_path": str(dummy_file)},
    )
    assert r.status_code == 201
    q_id = r.json()["id"]
    assert not dummy_file.exists()

    r = client.post(f"/api/quarantine/{q_id}/restore", headers=admin_headers)
    assert r.status_code == 200
    assert dummy_file.exists()

    # 10. Live Monitoring (off by default, opt-in start/snapshot/stop, PID 4 blocked)
    assert client.get("/api/monitoring/status", headers=user_headers).json()["is_running"] is False
    assert client.post("/api/monitoring/start", headers=user_headers, json={"poll_interval_sec": 5}).json()["is_running"] is True
    snap = client.get("/api/monitoring/processes?refresh=true", headers=user_headers).json()
    assert len(snap["processes"]) > 0
    assert client.post("/api/monitoring/stop", headers=user_headers).json()["is_running"] is False

    # 11. Dashboard overview & Admin System PDF Report & Audit Logs
    dash = client.get("/api/dashboard/overview", headers=admin_headers).json()
    assert dash["metrics"]["total_scans"] >= 2
    assert dash["metrics"]["total_trained_models"] >= 1

    sys_rep = client.post("/api/reports/admin/system", headers=admin_headers)
    assert sys_rep.status_code == 201
    logs = client.get("/api/admin/logs", headers=admin_headers).json()
    assert logs["total"] >= 3
