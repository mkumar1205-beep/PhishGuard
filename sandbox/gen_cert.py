"""
gen_cert.py
-----------
Run once at Docker build time to generate the mitmproxy CA certificate.
Tries the clean API approach first, falls back to starting mitmdump briefly.
"""
import subprocess
import sys
import time
from pathlib import Path

CERT_DIR = Path("/root/.mitmproxy")
CERT_FILE = CERT_DIR / "mitmproxy-ca-cert.pem"


def try_api():
    """Try generating cert via mitmproxy's Python API (mitmproxy 9+)."""
    try:
        from mitmproxy.certs import CertStore
        CERT_DIR.mkdir(parents=True, exist_ok=True)
        CertStore.from_store(str(CERT_DIR), "mitmproxy", 2048, b"mitmproxy")
        return CERT_FILE.exists()
    except Exception as e:
        print(f"API method failed: {e}")
        return False


def try_subprocess():
    """Fallback: start mitmdump on a temp port, wait for cert, kill it."""
    CERT_DIR.mkdir(parents=True, exist_ok=True)
    proc = subprocess.Popen(
        [sys.executable, "-m", "mitmdump", "--listen-port", "18080"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    # Poll until cert appears (up to 10 seconds)
    for _ in range(20):
        time.sleep(0.5)
        if CERT_FILE.exists():
            break
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except Exception:
        proc.kill()
    return CERT_FILE.exists()


if __name__ == "__main__":
    print("Generating mitmproxy CA certificate...")

    if try_api():
        print(f"Certificate generated via API at {CERT_FILE}")
        sys.exit(0)

    print("API method failed, trying subprocess method...")
    if try_subprocess():
        print(f"Certificate generated via subprocess at {CERT_FILE}")
        sys.exit(0)

    print("ERROR: Could not generate mitmproxy CA certificate")
    sys.exit(1)