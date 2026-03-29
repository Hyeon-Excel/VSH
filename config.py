import os
from pathlib import Path

# Base directory for Mock DB
MOCK_DB_DIR = os.path.join(os.path.dirname(__file__), "mock_db")

# Paths for read-only repositories
KNOWLEDGE_PATH = os.path.join(MOCK_DB_DIR, "knowledge.json")
FIX_PATH = os.path.join(MOCK_DB_DIR, "kisa_fix.json")

# Project Root
PROJECT_ROOT = Path(__file__).parent

# Vulnerable Packages for SBOM Scanner
VULNERABLE_PACKAGES = {
    "requests": {"vulnerable_below": "2.20.0", "cve": "CVE-2018-18074"},
    "flask": {"vulnerable_below": "1.0.0", "cve": "CVE-2018-1000656"},
    "django": {"vulnerable_below": "3.2.0", "cve": "CVE-2021-33203"},
    "pyyaml": {"vulnerable_below": "6.0.0", "cve": "CVE-2022-1471"},
    "pillow": {"vulnerable_below": "9.0.0", "cve": "CVE-2022-22817"}
}
