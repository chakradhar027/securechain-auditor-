import asyncio
from typing import List, Dict, Any, Tuple
from app.detectors.base_detector import RawFinding
from app.detectors.reentrancy import ReentrancyDetector
from app.detectors.access_control import AccessControlDetector
from app.detectors.unchecked_calls import UncheckedCallsDetector
from app.detectors.oracle_manipulation import OracleManipulationDetector
from app.scanners.slither_scanner import SlitherScanner
from app.scanners.mythril_scanner import MythrilScanner
from app.scanners.foundry_scanner import FoundryScanner
from app.utils.logger import logger

class ScannerManager:
    def __init__(self):
        self.custom_detectors = [
            ReentrancyDetector(),
            AccessControlDetector(),
            UncheckedCallsDetector(),
            OracleManipulationDetector()
        ]
        self.slither_scanner = SlitherScanner()
        self.mythril_scanner = MythrilScanner()
        self.foundry_scanner = FoundryScanner()
        self.last_executed_engines: List[str] = []

    async def run_scanners(
        self,
        file_path: str,
        source_code: str,
        enabled_engines: List[str]
    ) -> Tuple[List[RawFinding], Dict[str, Any]]:
        """
        Runs all requested engines on the provided contract source.
        Returns: (all_raw_findings, fuzz_metadata)
        """
        all_findings: List[RawFinding] = []
        fuzz_meta: Dict[str, Any] = {"total": 0, "passed": 0, "failed": 0, "tests": []}
        executed_engines: List[str] = []

        logger.info(f"Initiating scan with engines: {enabled_engines}")

        # 1. Custom Detectors
        if "custom" in enabled_engines:
            logger.info("Executing Custom Detection Engine...")
            custom_ok = True
            for detector in self.custom_detectors:
                try:
                    res = detector.detect(source_code, file_path)
                    all_findings.extend(res)
                except Exception as e:
                    custom_ok = False
                    logger.error(f"Custom detector {detector.name} error: {e}")
            if custom_ok:
                executed_engines.append("custom")

        # 2. Slither Static Analysis
        if "slither" in enabled_engines:
            logger.info("Executing Slither Static Analysis...")
            try:
                slither_res = await self.slither_scanner.scan(file_path, source_code)
                all_findings.extend(slither_res)
                executed_engines.append("slither")
            except Exception as e:
                logger.error(f"Slither scanner error: {e}")

        # 3. Mythril Symbolic Execution
        if "mythril" in enabled_engines:
            logger.info("Executing Mythril Symbolic Engine...")
            try:
                myth_res = await self.mythril_scanner.scan(file_path, source_code)
                all_findings.extend(myth_res)
                from app.utils.process_runner import is_mythril_operational
                if is_mythril_operational():
                    executed_engines.append("mythril")
                else:
                    logger.info("Mythril execution unverified (Docker daemon unavailable). Excluded from executed engines.")
            except Exception as e:
                logger.error(f"Mythril scanner error: {e}")

        # 4. Foundry Fuzz Testing
        if "foundry" in enabled_engines:
            logger.info("Executing Foundry Fuzz Testing Suite...")
            try:
                foundry_res, f_meta = await self.foundry_scanner.run_fuzz_tests(file_path, source_code)
                all_findings.extend(foundry_res)
                fuzz_meta = f_meta
                executed_engines.append("foundry")
            except Exception as e:
                logger.error(f"Foundry scanner error: {e}")

        self.last_executed_engines = executed_engines
        logger.info(f"Scan complete. Executed engines: {executed_engines}. Collected {len(all_findings)} raw findings across engines.")
        return all_findings, fuzz_meta

