"""Modular, versioned static PE feature extraction engine using pefile.

Never executes uploaded files. Safely handles missing PE headers or corrupted files.
Maintains a deterministic, versioned feature schema shared between training and inference.
"""

from dataclasses import dataclass
import hashlib
import math
from pathlib import Path
from typing import Any, Dict, List
import pefile

SCHEMA_VERSION = "1.0.0"

# Suspicious API keyword categories commonly associated with ransomware or packing
CRYPTO_APIS = {
    "cryptencrypt", "cryptdecrypt", "cryptgenkey", "cryptimportkey", "cryptacquirecontext",
    "cryptderivekey", "bcryptencrypt", "bcryptdecrypt", "bcryptgeneratekeypair",
    "rtlencryptmemory", "cryptcreatehash", "crypthashdata",
}
INJECTION_APIS = {
    "virtualalloc", "virtualallocex", "virtualprotect", "virtualprotectex",
    "writeprocessmemory", "createremotethread", "ntcreatethreadex", "queueuserapc",
    "setthreadcontext", "openprocess", "loadlibrary", "getprocaddress",
}
FILE_ENUM_APIS = {
    "findfirstfile", "findnextfile", "deletefile", "movefile", "movefileex",
    "copyfile", "createfile", "writefile", "setfileattributes", "getlogicaldrives",
    "getdrivetype",
}
SHADOW_PERSIST_APIS = {
    "shellexecute", "createprocess", "winexec", "regsetvalue", "regcreatekey",
    "openscmanager", "createservice", "startservice", "vssapi",
}
ANTI_ANALYSIS_APIS = {
    "isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess",
    "gettickcount", "queryperformancecounter", "outputdebugstring",
}


@dataclass(frozen=True)
class FeatureSpec:
    name: str
    feature_type: str
    description: str


FEATURE_SCHEMA: List[FeatureSpec] = [
    FeatureSpec("file_size", "float", "Total file size in bytes."),
    FeatureSpec("file_entropy", "float", "Shannon entropy of the entire file (0.0 - 8.0)."),
    FeatureSpec("is_valid_pe", "int", "1 if valid PE structure parsed by pefile, else 0."),
    FeatureSpec("machine_type", "int", "PE COFF Machine architecture identifier."),
    FeatureSpec("num_sections", "int", "Number of PE sections in section table."),
    FeatureSpec("num_imports", "int", "Total imported function count across all DLLs."),
    FeatureSpec("num_dll_imports", "int", "Number of distinct imported DLLs."),
    FeatureSpec("num_exports", "int", "Number of exported functions."),
    FeatureSpec("entry_point", "int", "Relative virtual address of the entry point."),
    FeatureSpec("image_size", "int", "Size of image in memory from OptionalHeader."),
    FeatureSpec("subsystem", "int", "Windows subsystem identifier (GUI, CUI, Native, etc.)."),
    FeatureSpec("characteristics", "int", "COFF FileHeader Characteristics bitmask."),
    FeatureSpec("dll_characteristics", "int", "OptionalHeader DllCharacteristics bitmask."),
    FeatureSpec("pe_timestamp", "int", "COFF FileHeader TimeDateStamp epoch value."),
    FeatureSpec("mean_section_entropy", "float", "Average Shannon entropy across PE sections."),
    FeatureSpec("max_section_entropy", "float", "Maximum Shannon entropy observed in any section."),
    FeatureSpec("min_section_entropy", "float", "Minimum Shannon entropy observed in any section."),
    FeatureSpec("mean_section_size", "float", "Average raw data size of PE sections."),
    FeatureSpec("max_section_size", "float", "Maximum raw data size of PE sections."),
    FeatureSpec("executable_sections", "int", "Count of sections with IMAGE_SCN_MEM_EXECUTE."),
    FeatureSpec("writable_sections", "int", "Count of sections with IMAGE_SCN_MEM_WRITE."),
    FeatureSpec("wx_sections", "int", "Count of sections marked both writable and executable (W+X)."),
    FeatureSpec("high_entropy_sections", "int", "Count of sections with entropy >= 7.0."),
    FeatureSpec("crypto_api_count", "int", "Count of imported cryptographic APIs."),
    FeatureSpec("injection_api_count", "int", "Count of imported memory/process injection APIs."),
    FeatureSpec("file_enum_api_count", "int", "Count of imported file enumeration/modification APIs."),
    FeatureSpec("persist_exec_api_count", "int", "Count of imported execution/registry/service APIs."),
    FeatureSpec("anti_analysis_api_count", "int", "Count of imported anti-debug/timing APIs."),
    FeatureSpec("has_debug_dir", "int", "1 if PE includes IMAGE_DIRECTORY_ENTRY_DEBUG."),
    FeatureSpec("has_tls_dir", "int", "1 if PE includes IMAGE_DIRECTORY_ENTRY_TLS."),
    FeatureSpec("has_resources", "int", "1 if PE includes IMAGE_DIRECTORY_ENTRY_RESOURCE."),
    FeatureSpec("code_to_file_ratio", "float", "Ratio of SizeOfCode to total file size."),
]

MODEL_FEATURE_NAMES: List[str] = [f.name for f in FEATURE_SCHEMA]


def calculate_shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    length = len(data)
    entropy = 0.0
    for count in counts:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return round(entropy, 6)


def compute_hashes(file_path: Path) -> Dict[str, str]:
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha256.update(chunk)
            md5.update(chunk)
    return {"sha256": sha256.hexdigest(), "md5": md5.hexdigest()}


def _classify_api(api_name: str, counts: Dict[str, int]) -> None:
    lower = api_name.lower()
    # Strip trailing A/W ANSI/Wide suffix for matching
    base = lower[:-1] if len(lower) > 3 and lower[-1] in ("a", "w") else lower
    if any(k in lower or k in base for k in CRYPTO_APIS):
        counts["crypto_api_count"] += 1
    if any(k in lower or k in base for k in INJECTION_APIS):
        counts["injection_api_count"] += 1
    if any(k in lower or k in base for k in FILE_ENUM_APIS):
        counts["file_enum_api_count"] += 1
    if any(k in lower or k in base for k in SHADOW_PERSIST_APIS):
        counts["persist_exec_api_count"] += 1
    if any(k in lower or k in base for k in ANTI_ANALYSIS_APIS):
        counts["anti_analysis_api_count"] += 1


def extract_static_pe_features(file_path: Path) -> Dict[str, Any]:
    """Extract static PE features safely without executing the target file.

    Returns a dictionary containing:
      - schema_version
      - hashes (sha256, md5)
      - file_type_detected
      - features (exact ordered numeric dict matching MODEL_FEATURE_NAMES)
      - metadata (sections detail, imported DLLs, parse errors if any)
    """
    raw_bytes = file_path.read_bytes()
    file_size = len(raw_bytes)
    file_entropy = calculate_shannon_entropy(raw_bytes)
    hashes = compute_hashes(file_path)

    features: Dict[str, float | int] = {spec.name: 0 for spec in FEATURE_SCHEMA}
    features["file_size"] = float(file_size)
    features["file_entropy"] = float(file_entropy)

    metadata: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "sections": [],
        "imported_dlls": [],
        "parse_warnings": [],
        "has_mz_header": raw_bytes[:2] == b"MZ",
    }

    pe = None
    try:
        pe = pefile.PE(data=raw_bytes, fast_load=False)
        features["is_valid_pe"] = 1

        fh = getattr(pe, "FILE_HEADER", None)
        if fh:
            features["machine_type"] = int(getattr(fh, "Machine", 0) or 0)
            features["num_sections"] = int(getattr(fh, "NumberOfSections", 0) or 0)
            features["characteristics"] = int(getattr(fh, "Characteristics", 0) or 0)
            features["pe_timestamp"] = int(getattr(fh, "TimeDateStamp", 0) or 0)

        oh = getattr(pe, "OPTIONAL_HEADER", None)
        if oh:
            features["entry_point"] = int(getattr(oh, "AddressOfEntryPoint", 0) or 0)
            features["image_size"] = int(getattr(oh, "SizeOfImage", 0) or 0)
            features["subsystem"] = int(getattr(oh, "Subsystem", 0) or 0)
            features["dll_characteristics"] = int(getattr(oh, "DllCharacteristics", 0) or 0)
            size_of_code = int(getattr(oh, "SizeOfCode", 0) or 0)
            features["code_to_file_ratio"] = round(size_of_code / max(file_size, 1), 6)

            data_dirs = getattr(oh, "DATA_DIRECTORY", []) or []
            if len(data_dirs) > 2 and getattr(data_dirs[2], "VirtualAddress", 0):
                features["has_resources"] = 1
            if len(data_dirs) > 6 and getattr(data_dirs[6], "VirtualAddress", 0):
                features["has_debug_dir"] = 1
            if len(data_dirs) > 9 and getattr(data_dirs[9], "VirtualAddress", 0):
                features["has_tls_dir"] = 1

        # Sections
        section_entropies: List[float] = []
        section_sizes: List[int] = []
        exec_count = 0
        write_count = 0
        wx_count = 0
        high_ent_count = 0

        for sec in getattr(pe, "sections", []) or []:
            sec_data = sec.get_data() or b""
            sec_entropy = calculate_shannon_entropy(sec_data)
            sec_size = int(getattr(sec, "SizeOfRawData", 0) or 0)
            chars = int(getattr(sec, "Characteristics", 0) or 0)
            is_exec = bool(chars & 0x20000000)
            is_write = bool(chars & 0x80000000)
            is_wx = is_exec and is_write

            if is_exec:
                exec_count += 1
            if is_write:
                write_count += 1
            if is_wx:
                wx_count += 1
            if sec_entropy >= 7.0:
                high_ent_count += 1

            section_entropies.append(sec_entropy)
            section_sizes.append(sec_size)

            sec_name = (
                getattr(sec, "Name", b"")
                .rstrip(b"\x00")
                .decode("utf-8", errors="replace")
            )
            metadata["sections"].append(
                {
                    "name": sec_name or "<unnamed>",
                    "virtual_size": int(getattr(sec, "Misc_VirtualSize", 0) or 0),
                    "raw_size": sec_size,
                    "entropy": sec_entropy,
                    "executable": is_exec,
                    "writable": is_write,
                    "wx": is_wx,
                }
            )

        if section_entropies:
            features["mean_section_entropy"] = round(sum(section_entropies) / len(section_entropies), 6)
            features["max_section_entropy"] = round(max(section_entropies), 6)
            features["min_section_entropy"] = round(min(section_entropies), 6)
        if section_sizes:
            features["mean_section_size"] = round(sum(section_sizes) / len(section_sizes), 2)
            features["max_section_size"] = float(max(section_sizes))

        features["executable_sections"] = exec_count
        features["writable_sections"] = write_count
        features["wx_sections"] = wx_count
        features["high_entropy_sections"] = high_ent_count

        # Imports
        api_counts = {
            "crypto_api_count": 0,
            "injection_api_count": 0,
            "file_enum_api_count": 0,
            "persist_exec_api_count": 0,
            "anti_analysis_api_count": 0,
        }
        dlls: List[str] = []
        total_imports = 0

        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = (
                    entry.dll.decode("utf-8", errors="replace")
                    if getattr(entry, "dll", None)
                    else "unknown.dll"
                )
                dlls.append(dll_name)
                for imp in getattr(entry, "imports", []) or []:
                    total_imports += 1
                    if getattr(imp, "name", None):
                        api_name = imp.name.decode("utf-8", errors="replace")
                        _classify_api(api_name, api_counts)

        features["num_dll_imports"] = len(dlls)
        features["num_imports"] = total_imports
        features.update(api_counts)
        metadata["imported_dlls"] = dlls[:50]

        # Exports
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            symbols = getattr(pe.DIRECTORY_ENTRY_EXPORT, "symbols", []) or []
            features["num_exports"] = len(symbols)

        is_dll = bool(features["characteristics"] & 0x2000)
        file_type_detected = "PE_DLL" if is_dll else "PE_EXE"

    except pefile.PEFormatError as exc:
        features["is_valid_pe"] = 0
        metadata["parse_warnings"].append(f"Invalid or corrupted PE structure: {exc}")
        file_type_detected = "CORRUPTED_OR_NON_PE"
    except Exception as exc:
        features["is_valid_pe"] = 0
        metadata["parse_warnings"].append(f"Static PE parse warning: {exc}")
        file_type_detected = "UNKNOWN_BINARY"
    finally:
        if pe is not None:
            try:
                pe.close()
            except Exception:
                pass

    return {
        "schema_version": SCHEMA_VERSION,
        "hashes": hashes,
        "file_type_detected": file_type_detected,
        "features": features,
        "feature_specs": [
            {
                "name": spec.name,
                "type": spec.feature_type,
                "value": features[spec.name],
                "description": spec.description,
            }
            for spec in FEATURE_SCHEMA
        ],
        "metadata": metadata,
    }
