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

def extract_contract_name(content: str, default: str = "SmartContract", filename: str = "") -> str:
    """
    Extracts the primary contract name from Solidity content.
    Strips single and multi-line comments and string literals to prevent matching
    contract declarations mentioned in docstrings / NatSpec comments.
    If filename is provided, matches declared contracts against filename stem first.
    Falls back to concrete contracts, abstract contracts, interfaces, or filename stem.
    """
    if not content:
        if filename:
            stem = os.path.splitext(os.path.basename(filename))[0]
            if re.match(r"^[a-f0-9]{8}_", stem):
                stem = stem[9:]
            return stem or default
        return default

    # Strip multi-line comments, single-line comments, and string literals
    cleaned = re.sub(r"/\*[\s\S]*?\*/", "", content)
    cleaned = re.sub(r"//.*$", "", cleaned, flags=re.MULTILINE)
    cleaned = re.sub(r'"(?:\\.|[^"\\])*"', '""', cleaned)
    cleaned = re.sub(r"'(?:\\.|[^'\\])*'", "''", cleaned)

    stem = ""
    if filename:
        clean_base = os.path.basename(filename)
        stem = os.path.splitext(clean_base)[0]
        # Strip internal uuid prefix if present (e.g. 12345678_Contract.sol)
        if re.match(r"^[a-f0-9]{8}_", stem):
            stem = stem[9:]

    # Match all contract declarations (concrete and abstract), interfaces, libraries
    matches = re.findall(
        r"\b(abstract\s+contract|contract|interface|library)\s+([a-zA-Z0-9_]+)",
        cleaned
    )

    # 1. If filename stem matches one of the declared names, prioritize it
    if stem and matches:
        for decl, name in matches:
            if name.lower() == stem.lower():
                return name

    # 2. Prefer concrete (non-abstract) contract definitions
    concrete_contracts = [name for decl, name in matches if decl == "contract"]
    if concrete_contracts:
        return concrete_contracts[-1]

    # 3. Next prefer abstract contract
    abstract_contracts = [name for decl, name in matches if "abstract" in decl]
    if abstract_contracts:
        return abstract_contracts[-1]

    # 4. Next prefer interface or library
    other_decls = [name for decl, name in matches]
    if other_decls:
        return other_decls[0]

    # 5. Fallback to filename stem without extension if available
    if stem:
        return stem

    return default

def extract_compiler_version(content: str) -> str:
    """Extracts pragma solidity version."""
    match = re.search(r"pragma\s+solidity\s+([^;]+);", content)
    if match:
        return match.group(1).strip()
    return "^0.8.20"

