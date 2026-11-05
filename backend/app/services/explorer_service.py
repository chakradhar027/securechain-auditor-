import json
import re
from typing import Tuple, Dict, Any
import httpx
from app.config import settings
from app.utils.logger import logger

EXPLORER_ENDPOINTS = {
    "ethereum": "https://api.etherscan.io/api",
    "sepolia": "https://api-sepolia.etherscan.io/api",
    "bsc": "https://api.bscscan.com/api",
    "polygon": "https://api.polygonscan.com/api",
    "arbitrum": "https://api.arbiscan.io/api",
    "optimism": "https://api-optimistic.etherscan.io/api",
}

class ExplorerService:
    @staticmethod
    async def fetch_verified_contract(address: str, network: str = "ethereum") -> Tuple[bool, str, Dict[str, Any]]:
        """
        Retrieves verified smart contract source code from blockchain explorer API.
        Returns: (success, message, contract_details)
        """
        # Validate Ethereum address format
        if not re.match(r"^0x[a-fA-F0-9]{40}$", address):
            return False, "Invalid Ethereum contract address format (must be 0x followed by 40 hex characters).", {}

        net = network.lower()
        endpoint = EXPLORER_ENDPOINTS.get(net)
        if not endpoint:
            return False, f"Unsupported network '{network}'. Supported: {', '.join(EXPLORER_ENDPOINTS.keys())}", {}

        api_key = settings.ETHERSCAN_API_KEY
        if "bsc" in net:
            api_key = settings.BSCSCAN_API_KEY or api_key
        elif "polygon" in net:
            api_key = settings.POLYGONSCAN_API_KEY or api_key

        params = {
            "module": "contract",
            "action": "getsourcecode",
            "address": address,
        }
        if api_key:
            params["apikey"] = api_key

        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                res = await client.get(endpoint, params=params)
                if res.status_code != 200:
                    return False, f"Explorer API returned HTTP {res.status_code}.", {}

                data = res.json()
                if data.get("status") != "1" or not data.get("result"):
                    msg = data.get("message", "Contract not verified or not found on-chain.")
                    return False, f"Explorer lookup failed: {msg}", {}

                result_item = data["result"][0]
                raw_source = result_item.get("SourceCode", "")
                contract_name = result_item.get("ContractName", "VerifiedContract")
                compiler_version = result_item.get("CompilerVersion", "^0.8.20")

                if not raw_source:
                    return False, "Contract has no verified source code on this network.", {}

                # Handle multi-file or standard-json input from Etherscan
                clean_source = ExplorerService._parse_source_payload(raw_source)

                return True, "Verified contract fetched successfully.", {
                    "name": contract_name,
                    "address": address,
                    "network": net,
                    "compiler_version": compiler_version,
                    "source_code": clean_source
                }
        except Exception as e:
            logger.error(f"Error fetching contract {address} from {network}: {e}")
            return False, f"Network communication error: {str(e)}", {}

    @staticmethod
    def _parse_source_payload(raw: str) -> str:
        """Handles single source string or JSON-wrapped multi-file Etherscan bundles."""
        if raw.startswith("{{") and raw.endswith("}}"):
            raw = raw[1:-1]
        if raw.startswith("{") and raw.endswith("}"):
            try:
                data = json.loads(raw)
                sources = data.get("sources", {})
                combined = []
                for file_path, file_obj in sources.items():
                    combined.append(f"// File: {file_path}\n" + file_obj.get("content", ""))
                if combined:
                    return "\n\n".join(combined)
            except Exception:
                pass
        return raw
