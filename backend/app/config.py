import os


def _bool(name: str, default: str = "false") -> bool:
    return os.getenv(name, default).strip().lower() in {"1", "true", "yes", "on"}


class Settings:
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./secaudit.db")
    CORS_ORIGINS: list[str] = [
        o.strip()
        for o in os.getenv("CORS_ORIGINS", "http://localhost:5173,http://localhost:8080").split(",")
        if o.strip()
    ]
    # Safety: block scanning of private / internal IPs (SSRF protection).
    ALLOW_PRIVATE_TARGETS: bool = _bool("ALLOW_PRIVATE_TARGETS")
    # Development only: lets you scan without proving ownership. Keep false in production.
    SKIP_VERIFICATION: bool = _bool("SKIP_VERIFICATION")
    REQUEST_TIMEOUT: float = float(os.getenv("REQUEST_TIMEOUT", "10"))
    # Minimum seconds between two scans of the same target.
    SCAN_COOLDOWN_SECONDS: int = int(os.getenv("SCAN_COOLDOWN_SECONDS", "30"))
    USER_AGENT: str = os.getenv("SCANNER_USER_AGENT", "SecAuditDashboard/1.0 (authorized security audit)")
    VERIFY_FILE_PATH: str = "/.well-known/secaudit-verification.txt"
    VERIFY_DNS_PREFIX: str = "_secaudit"


settings = Settings()
