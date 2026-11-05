from typing import Dict, Any, Optional

class JobService:
    def __init__(self):
        # scan_id -> dict with progress, current_step, status
        self._jobs: Dict[int, Dict[str, Any]] = {}

    def start_job(self, scan_id: int):
        self._jobs[scan_id] = {
            "scan_id": scan_id,
            "status": "RUNNING",
            "progress_percent": 10,
            "current_step": "Initializing static & dynamic engines",
            "message": "Scan job initialized"
        }

    def update_progress(self, scan_id: int, percent: int, current_step: str, message: str = ""):
        if scan_id in self._jobs:
            self._jobs[scan_id]["progress_percent"] = percent
            self._jobs[scan_id]["current_step"] = current_step
            if message:
                self._jobs[scan_id]["message"] = message

    def complete_job(self, scan_id: int):
        if scan_id in self._jobs:
            self._jobs[scan_id]["status"] = "COMPLETED"
            self._jobs[scan_id]["progress_percent"] = 100
            self._jobs[scan_id]["current_step"] = "Audit report and analysis generated"
            self._jobs[scan_id]["message"] = "Scan finished successfully"

    def fail_job(self, scan_id: int, error_message: str):
        if scan_id in self._jobs:
            self._jobs[scan_id]["status"] = "FAILED"
            self._jobs[scan_id]["current_step"] = "Scan terminated on error"
            self._jobs[scan_id]["message"] = error_message

    def get_status(self, scan_id: int) -> Optional[Dict[str, Any]]:
        return self._jobs.get(scan_id)

job_service = JobService()
