"""Central configuration, read from environment variables."""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


class Settings:
    database_url = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR / 'forensics.db'}")
    secret_key = os.getenv("SECRET_KEY", "dev-only-change-me")
    token_minutes = int(os.getenv("TOKEN_MINUTES", "60"))

    storage_backend = os.getenv("STORAGE_BACKEND", "local")  # "local" or "s3"
    evidence_dir = Path(os.getenv("EVIDENCE_DIR", str(BASE_DIR / "evidence_store")))
    s3_bucket = os.getenv("S3_BUCKET", "")
    s3_region = os.getenv("S3_REGION", "")
    s3_endpoint = os.getenv("S3_ENDPOINT_URL", "")
    s3_sse = os.getenv("S3_SSE", "true").lower() == "true"  # server-side encryption

    max_upload_mb = int(os.getenv("MAX_UPLOAD_MB", "50"))
    allowed_extensions = {
        ".txt", ".log", ".csv", ".json", ".pdf", ".docx", ".xlsx",
        ".png", ".jpg", ".jpeg", ".zip", ".eml",
    }

    admin_username = os.getenv("ADMIN_USERNAME", "admin")
    admin_password = os.getenv("ADMIN_PASSWORD", "")


settings = Settings()
