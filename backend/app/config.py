import os
from pathlib import Path
from typing import List, Union
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Canonical Base and Backend Paths (independent of CWD)
BASE_DIR = Path(__file__).resolve().parent.parent.parent  # Repository Root
BACKEND_DIR = Path(__file__).resolve().parent.parent      # Backend Root
CANONICAL_STORAGE_DIR = BACKEND_DIR / "storage"
CANONICAL_DATABASE_PATH = CANONICAL_STORAGE_DIR / "securechain.db"
CANONICAL_DATABASE_URL = f"sqlite+aiosqlite:///{CANONICAL_DATABASE_PATH}"

class Settings(BaseSettings):
    APP_NAME: str = "SecureChain Auditor"
    APP_ENV: str = "development"
    DEBUG: bool = True
    PORT: int = 8000
    HOST: str = "0.0.0.0"

    # Base and Backend Directories
    BASE_DIR: Path = BASE_DIR
    BACKEND_DIR: Path = BACKEND_DIR
    CONTRACTS_DIR: str = str(BASE_DIR / "contracts")

    # Database: Active Canonical Database in backend/storage/securechain.db
    DATABASE_URL: str = CANONICAL_DATABASE_URL

    # CORS
    ALLOWED_ORIGINS: Union[List[str], str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]

    @field_validator("DATABASE_URL", mode="after")
    @classmethod
    def resolve_database_url(cls, v: str) -> str:
        # If empty, relative, or pointing to legacy root storage or relative sqlite URL
        if not v or ("sqlite" in v and (
            "///./storage" in v or 
            "///./backend/storage" in v or 
            "///storage" in v or 
            not os.path.isabs(v.split("///")[-1]) or 
            v.endswith("/Project SecureChain Auditor/storage/securechain.db")
        )):
            return CANONICAL_DATABASE_URL
        return v

    @field_validator("STORAGE_DIR", mode="after")
    @classmethod
    def resolve_storage_dir(cls, v: str) -> str:
        if not v or v.startswith("./") or not os.path.isabs(v) or v.endswith("/Project SecureChain Auditor/storage"):
            return str(CANONICAL_STORAGE_DIR)
        return v

    @field_validator("UPLOADS_DIR", mode="after")
    @classmethod
    def resolve_uploads_dir(cls, v: str) -> str:
        if not v or v.startswith("./") or not os.path.isabs(v) or ("/storage/uploads" in v and "/backend/storage/uploads" not in v):
            return str(CANONICAL_STORAGE_DIR / "uploads")
        return v

    @field_validator("REPORTS_DIR", mode="after")
    @classmethod
    def resolve_reports_dir(cls, v: str) -> str:
        if not v or v.startswith("./") or not os.path.isabs(v) or ("/storage/reports" in v and "/backend/storage/reports" not in v):
            return str(CANONICAL_STORAGE_DIR / "reports")
        return v

    @field_validator("TEMP_DIR", mode="after")
    @classmethod
    def resolve_temp_dir(cls, v: str) -> str:
        if not v or v.startswith("./") or not os.path.isabs(v) or ("/storage/temp" in v and "/backend/storage/temp" not in v):
            return str(CANONICAL_STORAGE_DIR / "temp")
        return v

    @field_validator("CONTRACTS_DIR", mode="after")
    @classmethod
    def resolve_contracts_dir(cls, v: str) -> str:
        if not v or v.startswith("./") or not os.path.isabs(v):
            return str(BASE_DIR / "contracts")
        return v

    @field_validator("ALLOWED_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str):
            if v.startswith("[") and v.endswith("]"):
                import json
                try:
                    return json.loads(v)
                except Exception:
                    pass
            return [i.strip() for i in v.split(",") if i.strip()]
        elif isinstance(v, list):
            return v
        return ["*"]

    # Security
    SECRET_KEY: str = "securechain-auditor-development-secret-key-2026"

    # External Tools (prioritize local venv binaries if present)
    VENV_BIN_DIR: str = str(BASE_DIR / ".venv" / "bin")
    SLITHER_PATH: str = str(BASE_DIR / ".venv" / "bin" / "slither") if (BASE_DIR / ".venv" / "bin" / "slither").exists() else "slither"
    MYTHRIL_PATH: str = str(BASE_DIR / ".venv" / "bin" / "myth") if (BASE_DIR / ".venv" / "bin" / "myth").exists() else "myth"
    FOUNDRY_FORGE_PATH: str = str(BASE_DIR / ".venv" / "bin" / "forge") if (BASE_DIR / ".venv" / "bin" / "forge").exists() else "forge"
    SOLC_PATH: str = str(BASE_DIR / ".venv" / "bin" / "solc") if (BASE_DIR / ".venv" / "bin" / "solc").exists() else "solc"
    SCANNER_TIMEOUT_SECONDS: int = 180

    # Storage Paths (Canonical active storage in backend/storage/)
    STORAGE_DIR: str = str(CANONICAL_STORAGE_DIR)
    UPLOADS_DIR: str = str(CANONICAL_STORAGE_DIR / "uploads")
    REPORTS_DIR: str = str(CANONICAL_STORAGE_DIR / "reports")
    TEMP_DIR: str = str(CANONICAL_STORAGE_DIR / "temp")

    # Blockchain Explorers
    ETHERSCAN_API_KEY: str = ""
    BSCSCAN_API_KEY: str = ""
    POLYGONSCAN_API_KEY: str = ""

    model_config = SettingsConfigDict(
        env_file=str(BASE_DIR / ".env"),
        env_file_encoding="utf-8",
        extra="ignore"
    )

settings = Settings()

# Ensure storage directories exist
for path_dir in [settings.STORAGE_DIR, settings.UPLOADS_DIR, settings.REPORTS_DIR, settings.TEMP_DIR]:
    os.makedirs(path_dir, exist_ok=True)
