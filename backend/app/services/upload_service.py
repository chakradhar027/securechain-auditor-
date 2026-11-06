import os
import uuid
from typing import Tuple
from app.config import settings
from app.utils.file_validator import sanitize_filename, validate_solidity_file, extract_contract_name, extract_compiler_version

class UploadService:
    @staticmethod
    def save_contract_source(filename: str, content: str) -> Tuple[bool, str, dict]:
        """
        Validates and saves uploaded Solidity source code to the uploads directory.
        Returns: (success, message, metadata_dict)
        """
        is_valid, msg = validate_solidity_file(filename, content)
        if not is_valid:
            return False, msg, {}

        clean_name = sanitize_filename(filename)
        unique_prefix = uuid.uuid4().hex[:8]
        stored_filename = f"{unique_prefix}_{clean_name}"
        file_path = os.path.join(settings.UPLOADS_DIR, stored_filename)

        with open(file_path, "w", encoding="utf-8") as f:
            f.write(content)

        fallback_name = os.path.splitext(clean_name)[0]
        contract_name = extract_contract_name(content, default=fallback_name, filename=clean_name)
        compiler_version = extract_compiler_version(content)
        byte_size = len(content.encode("utf-8"))

        metadata = {
            "name": contract_name,
            "filename": clean_name,
            "file_path": file_path,
            "source_code": content,
            "compiler_version": compiler_version,
            "byte_size": byte_size
        }

        return True, "Solidity contract saved successfully.", metadata

