from pathlib import Path

# Project root (VSH_Project_MVP)
BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR

# Storage directories (absolute, cwd-independent)
MOCK_DB_DIR = BASE_DIR / "mock_db"
CHROMA_DB_DIR = BASE_DIR / ".chroma_db"
CHROMA_CACHE_DIR = BASE_DIR / ".cache" / "chroma"
CHROMA_COLLECTION = "vsh_kisa_guide"

# Optional sqlite path used by local components/tools
SQLITE_DB_PATH = MOCK_DB_DIR / "vsh.db"

# Paths for read-only repositories
KNOWLEDGE_PATH = MOCK_DB_DIR / "knowledge.json"
FIX_PATH = MOCK_DB_DIR / "kisa_fix.json"
LOG_PATH = MOCK_DB_DIR / "log.json"


def ensure_runtime_paths() -> None:
    """Ensure runtime paths exist regardless of launch cwd."""
    MOCK_DB_DIR.mkdir(parents=True, exist_ok=True)
    CHROMA_DB_DIR.mkdir(parents=True, exist_ok=True)
    CHROMA_CACHE_DIR.mkdir(parents=True, exist_ok=True)

    for file_path in (KNOWLEDGE_PATH, FIX_PATH, LOG_PATH):
        if not file_path.exists():
            file_path.write_text("[]", encoding="utf-8")

    if not SQLITE_DB_PATH.exists():
        SQLITE_DB_PATH.touch()


ensure_runtime_paths()

# Convert to strings for legacy modules that expect str constants
KNOWLEDGE_PATH = str(KNOWLEDGE_PATH)
FIX_PATH = str(FIX_PATH)
LOG_PATH = str(LOG_PATH)
SQLITE_DB_PATH = str(SQLITE_DB_PATH)

# Vulnerable Packages for SBOM Scanner
VULNERABLE_PACKAGES = {
    "requests": {"vulnerable_below": "2.20.0", "cve": "CVE-2018-18074"},
    "flask": {"vulnerable_below": "1.0.0", "cve": "CVE-2018-1000656"},
    "django": {"vulnerable_below": "3.2.0", "cve": "CVE-2021-33203"},
    "pyyaml": {"vulnerable_below": "6.0.0", "cve": "CVE-2022-1471"},
    "pillow": {"vulnerable_below": "9.0.0", "cve": "CVE-2022-22817"}
}
