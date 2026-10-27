import json
import shutil
import subprocess

def prowler_available():
    return shutil.which("prowler") is not None

def run_prowler(compliance="cis_5.0_1.5.0"):
    if not prowler_available():
        raise RuntimeError("Prowler is not installed or is not available in PATH.")

    cmd = ["prowler", "aws", "--compliance", compliance, "-M", "json"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    if result.returncode not in (0, 1):
        raise RuntimeError(result.stderr.strip() or "Prowler execution failed.")

    return {
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }
