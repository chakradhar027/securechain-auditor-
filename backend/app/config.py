import os
from pathlib import Path
from typing import List, Union
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent.parent

class Settings(BaseSettings):
    APP_NAME: str = "SecureChain Auditor"
    APP_ENV: str = "development"
    DEBUG: bool = True
    PORT: int = 8000
    HOST: str = "0.0.0.0"

    # Database
    DATABASE_URL: str = f"sqlite+aiosqlite:///{BASE_DIR}/storage/securechain.db"

    # CORS
    ALLOWED_ORIGINS: Union[List[str], str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]

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

    # External Tools
    SLITHER_PATH: str = "slither"
    MYTHRIL_PATH: str = "myth"
    FOUNDRY_FORGE_PATH: str = "forge"
    SCANNER_TIMEOUT_SECONDS: int = 180

    # Storage
    STORAGE_DIR: str = str(BASE_DIR / "storage")
    UPLOADS_DIR: str = str(BASE_DIR / "storage" / "uploads")
    REPORTS_DIR: str = str(BASE_DIR / "storage" / "reports")
    TEMP_DIR: str = str(BASE_DIR / "storage" / "temp")

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
