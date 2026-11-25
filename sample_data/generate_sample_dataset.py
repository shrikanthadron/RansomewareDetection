"""Generate a safe synthetic PE static feature CSV dataset for ML testing."""

from pathlib import Path
import random
import pandas as pd

# Exact feature order matching backend/app/services/pe_extractor.py MODEL_FEATURE_NAMES
COLUMNS = [
    "file_size", "file_entropy", "is_valid_pe", "machine_type", "num_sections",
    "num_imports", "num_dll_imports", "num_exports", "entry_point", "image_size",
    "subsystem", "characteristics", "dll_characteristics", "pe_timestamp",
    "mean_section_entropy", "max_section_entropy", "min_section_entropy",
    "mean_section_size", "max_section_size", "executable_sections",
    "writable_sections", "wx_sections", "high_entropy_sections",
    "crypto_api_count", "injection_api_count", "file_enum_api_count",
    "persist_exec_api_count", "anti_analysis_api_count", "has_debug_dir",
    "has_tls_dir", "has_resources", "code_to_file_ratio", "label",
]


def generate_dataset(output_csv: Path, rows: int = 300) -> None:
    rng = random.Random(42)
    records = []
    for i in range(rows):
        is_ransomware = 1 if i >= rows // 2 else 0
        if is_ransomware:
            file_entropy = round(rng.uniform(6.8, 7.95), 4)
            max_sec_ent = round(min(7.99, file_entropy + rng.uniform(0.05, 0.35)), 4)
            mean_sec_ent = round(rng.uniform(6.2, max_sec_ent), 4)
            min_sec_ent = round(rng.uniform(3.5, 6.2), 4)
            wx_sections = rng.choice([0, 1, 1, 2])
            high_ent_secs = rng.choice([1, 2, 3])
            crypto_api = rng.randint(2, 8)
            inj_api = rng.randint(1, 6)
            file_enum = rng.randint(3, 10)
            persist_api = rng.randint(1, 5)
            anti_api = rng.randint(1, 4)
            has_debug = rng.choice([0, 0, 0, 1])
            num_imports = rng.randint(8, 65)
            num_dlls = rng.randint(2, 8)
            file_size = rng.randint(45000, 1800000)
        else:
            file_entropy = round(rng.uniform(4.2, 6.55), 4)
            max_sec_ent = round(rng.uniform(5.0, 6.85), 4)
            mean_sec_ent = round(rng.uniform(3.8, 6.1), 4)
            min_sec_ent = round(rng.uniform(0.5, 4.2), 4)
            wx_sections = 0
            high_ent_secs = 0
            crypto_api = rng.choice([0, 0, 1])
            inj_api = rng.choice([0, 0, 1])
            file_enum = rng.randint(0, 3)
            persist_api = rng.choice([0, 0, 1])
            anti_api = 0
            has_debug = rng.choice([0, 1, 1, 1])
            num_imports = rng.randint(35, 240)
            num_dlls = rng.randint(5, 18)
            file_size = rng.randint(20000, 4500000)

        num_sections = rng.randint(3, 8)
        records.append([
            file_size, file_entropy, 1, 34404, num_sections,
            num_imports, num_dlls, rng.randint(0, 20), rng.randint(4096, 65536),
            file_size + rng.randint(4096, 65536), rng.choice([2, 3]), 258, 33088,
            rng.randint(1550000000, 1750000000),
            mean_sec_ent, max_sec_ent, min_sec_ent,
            round(file_size / num_sections, 2), round(file_size * 0.55, 2),
            rng.randint(1, 2), rng.randint(1, 3), wx_sections, high_ent_secs,
            crypto_api, inj_api, file_enum, persist_api, anti_api,
            has_debug, rng.choice([0, 1]), 1, round(rng.uniform(0.15, 0.72), 4),
            is_ransomware,
        ])

    df = pd.DataFrame(records, columns=COLUMNS)
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output_csv, index=False)


if __name__ == "__main__":
    out = Path(__file__).resolve().parent / "ransomshield_sample_dataset.csv"
    generate_dataset(out)
    print(f"Generated {out}")
