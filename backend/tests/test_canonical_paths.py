import os
import shutil
import hashlib
from pathlib import Path
import pytest
from app.config import (
    Settings,
    BASE_DIR,
    BACKEND_DIR,
    CANONICAL_STORAGE_DIR,
    CANONICAL_DATABASE_PATH,
    CANONICAL_DATABASE_URL
)

def test_canonical_paths_from_root_and_backend_directories(tmp_path):
    """
    Automated test verifying that Settings resolves identical, absolute canonical paths
    regardless of whether the process CWD is the repository root, backend directory,
    or any arbitrary subdirectory.
    """
    orig_cwd = os.getcwd()
    try:
        # 1. Test from repository root
        os.chdir(str(BASE_DIR))
        settings_root = Settings()

        # 2. Test from backend directory
        os.chdir(str(BACKEND_DIR))
        settings_backend = Settings()

        # 3. Test from an arbitrary outside directory
        os.chdir(str(tmp_path))
        settings_other = Settings()

        # Verify all three instances resolve identically
        for s in [settings_root, settings_backend, settings_other]:
            assert s.DATABASE_URL == CANONICAL_DATABASE_URL
            assert s.STORAGE_DIR == str(CANONICAL_STORAGE_DIR)
            assert s.UPLOADS_DIR == str(CANONICAL_STORAGE_DIR / "uploads")
            assert s.REPORTS_DIR == str(CANONICAL_STORAGE_DIR / "reports")
            assert s.TEMP_DIR == str(CANONICAL_STORAGE_DIR / "temp")
            assert s.CONTRACTS_DIR == str(BASE_DIR / "contracts")

            # Verify all paths are strictly absolute
            assert os.path.isabs(s.STORAGE_DIR)
            assert os.path.isabs(s.UPLOADS_DIR)
            assert os.path.isabs(s.REPORTS_DIR)
            assert os.path.isabs(s.TEMP_DIR)
            assert os.path.isabs(s.CONTRACTS_DIR)

            # Verify canonical database file is specifically backend/storage/securechain.db
            db_path_str = s.DATABASE_URL.replace("sqlite+aiosqlite:///", "")
            db_path = Path(db_path_str)
            assert db_path == CANONICAL_DATABASE_PATH
            assert db_path.name == "securechain.db"
            assert db_path.parent.name == "storage"
            assert db_path.parent.parent.name == "backend"

    finally:
        os.chdir(orig_cwd)

def test_active_database_scan_counts_and_pair_integrity():
    """
    Verifies that the canonical active database backend/storage/securechain.db
    preserves existing audit history, specifically SCA-000006 and SCA-000008.
    """
    import sqlite3
    conn = sqlite3.connect(str(CANONICAL_DATABASE_PATH))
    c = conn.cursor()

    # Verify total scan count
    c.execute("SELECT COUNT(*) FROM scans")
    scan_count = c.fetchone()[0]
    assert scan_count >= 8, f"Expected at least 8 scans, found {scan_count}"

    # Verify Scan 6 is ReentrancyVulnerable
    c.execute("""
        SELECT s.id, c.name, c.filename, s.risk_score, s.risk_level
        FROM scans s JOIN contracts c ON s.contract_id = c.id
        WHERE s.id = 6
    """)
    s6 = c.fetchone()
    assert s6 is not None, "Scan 6 not found in active database"
    assert s6[1] == "ReentrancyVulnerable"
    assert s6[2] == "ReentrancyVulnerable.sol"
    assert s6[3] == 100.0
    assert s6[4] == "CRITICAL"

    # Verify Scan 8 is ReentrancyFixed
    c.execute("""
        SELECT s.id, c.name, c.filename, s.risk_score, s.risk_level
        FROM scans s JOIN contracts c ON s.contract_id = c.id
        WHERE s.id = 8
    """)
    s8 = c.fetchone()
    assert s8 is not None, "Scan 8 not found in active database"
    assert s8[1] == "ReentrancyFixed"
    assert s8[2] == "ReentrancyFixed.sol"
    assert s8[3] == 0.0
    assert s8[4] == "SECURE"

    conn.close()

def test_active_database_backup_exists():
    """
    Verifies that the pre-canonical-fix database backup exists and is valid.
    """
    backup_path = CANONICAL_STORAGE_DIR / "backups" / "securechain_backup_pre_canonical_fix.db"
    assert backup_path.exists(), f"Backup file {backup_path} does not exist"
    assert backup_path.stat().st_size > 0, "Backup file is empty"

