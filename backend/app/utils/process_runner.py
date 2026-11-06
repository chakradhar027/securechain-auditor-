import asyncio
import os
import shutil
from typing import Tuple, List, Optional
from app.utils.logger import logger

async def run_command_async(
    cmd: List[str],
    cwd: Optional[str] = None,
    timeout: int = 120,
    env: Optional[dict] = None
) -> Tuple[int, str, str]:
    """
    Executes a shell command asynchronously with a timeout.
    Returns: (return_code, stdout, stderr)
    """
    cmd_str = " ".join(cmd)
    logger.info(f"Running command: {cmd_str}")

    full_env = os.environ.copy()
    if env:
        full_env.update(env)

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=cwd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=full_env
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        rc = proc.returncode if proc.returncode is not None else 1
        return rc, stdout.decode("utf-8", errors="replace"), stderr.decode("utf-8", errors="replace")
    except asyncio.TimeoutError:
        logger.warning(f"Command timed out after {timeout}s: {cmd_str}")
        try:
            proc.kill()
        except Exception:
            pass
        return -1, "", f"Execution timed out after {timeout} seconds."
    except Exception as e:
        logger.error(f"Failed to execute command '{cmd_str}': {str(e)}")
        return 1, "", str(e)

def is_tool_available(tool_name: str) -> bool:
    """Checks if a binary is present on PATH."""
    return shutil.which(tool_name) is not None

def is_mythril_operational() -> bool:
    """
    Checks if a real Mythril execution environment is active and operational.
    Requires either Docker or a functioning native myth binary (not broken Python 3.13 shim).
    """
    if is_tool_available("docker"):
        return True
    if is_tool_available("myth"):
        try:
            import subprocess
            rc = subprocess.run(["myth", "version"], capture_output=True, timeout=2).returncode
            return rc == 0
        except Exception:
            return False
    return False

