import os
import re
from typing import Tuple

MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024  # 5 MB
ALLOWED_EXTENSIONS = {".sol"}

def sanitize_filename(filename: str) -> str:
    """Removes path traversals and invalid characters from filename."""
    base = os.path.basename(filename)
    clean = re.sub(r"[^a-zA-Z0-9_\-\.]", "_", base)
    if not clean.endswith(".sol"):
        clean += ".sol"
    return clean

def validate_solidity_file(filename: str, content: str) -> Tuple[bool, str]:
    """Validates that a file is a valid Solidity source file."""
    _, ext = os.path.splitext(filename)
    if ext.lower() not in ALLOWED_EXTENSIONS:
        return False, f"Invalid file extension '{ext}'. Only .sol files are supported."

    if len(content.encode("utf-8")) > MAX_FILE_SIZE_BYTES:
        return False, f"File exceeds maximum allowed size of {MAX_FILE_SIZE_BYTES / (1024 * 1024)}MB."

    if not content.strip():
        return False, "File content is empty."

    # Look for contract, interface, library, or pragma statements
    patterns = [
        r"pragma\s+solidity",
        r"\bcontract\s+[a-zA-Z0-9_]+",
        r"\binterface\s+[a-zA-Z0-9_]+",
        r"\blibrary\s+[a-zA-Z0-9_]+"
    ]
    if not any(re.search(pat, content) for pat in patterns):
        return False, "Uploaded file does not appear to contain valid Solidity code (missing pragma, contract, interface, or library declaration)."

    return True, "Valid Solidity source code."

def extract_contract_name(content: str, default: str = "SmartContract") -> str:
    """Extracts the primary contract name from Solidity content."""
    match = re.search(r"\bcontract\s+([a-zA-Z0-9_]+)", content)
    if match:
        return match.group(1)
    match_iface = re.search(r"\binterface\s+([a-zA-Z0-9_]+)", content)
    if match_iface:
        return match_iface.group(1)
    return default

def extract_compiler_version(content: str) -> str:
    """Extracts pragma solidity version."""
    match = re.search(r"pragma\s+solidity\s+([^;]+);", content)
    if match:
        return match.group(1).strip()
    return "^0.8.20"
