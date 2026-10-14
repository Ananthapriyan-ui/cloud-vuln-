import os
import json
from typing import List, Any
from pydantic_settings import BaseSettings  # type: ignore[import-untyped]


class Settings(BaseSettings):
    PROJECT_NAME: str = "CloudVuln Security Engine"
    API_V1_STR: str = "/api"

    # JWT Auth
    SECRET_KEY: str = "cloudvuln-secops-super-secret-jwt-key-2026-prod-grade-change-me"
    REFRESH_SECRET_KEY: str = "cloudvuln-secops-super-secret-refresh-key-2026-prod-grade-change-me"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # CORS — accepts a comma-separated string, a JSON array string, or a list
    ALLOWED_ORIGINS: Any = [
        "https://cloud-vuln.vercel.app",
        "https://cloudvulner.vercel.app",
        "https://github.com/Ananthapriyan-ui/cloud-vuln-.git",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ]

    # Rate Limiting
    RATE_LIMIT_REQUESTS: int = 100
    RATE_LIMIT_WINDOW_SECONDS: int = 60

    # Database & Supabase
    DATABASE_URL: str = ""
    SUPABASE_URL: str = ""
    SUPABASE_SERVICE_ROLE_KEY: str = ""
    SUPABASE_STORAGE_BUCKET: str = "reports"
    NVD_API_KEY: str = ""

    # App
    APP_ENV: str = "development"
    LOG_LEVEL: str = "INFO"

    @property
    def cors_origins(self) -> List[str]:
        if isinstance(self.ALLOWED_ORIGINS, list):
            return [str(o).strip() for o in self.ALLOWED_ORIGINS if str(o).strip()]
        if isinstance(self.ALLOWED_ORIGINS, str):
            raw = self.ALLOWED_ORIGINS.strip()
            # Handle JSON array format: ["url1", "url2"]
            if raw.startswith("["):
                try:
                    parsed = json.loads(raw)
                    if isinstance(parsed, list):
                        return [str(o).strip() for o in parsed if str(o).strip()]
                except (json.JSONDecodeError, ValueError):
                    pass
            # Handle comma-separated format: url1,url2
            return [origin.strip() for origin in raw.split(",") if origin.strip()]
        return ["http://localhost:3000", "http://127.0.0.1:3000"]

    def model_post_init(self, __context: Any) -> None:
        if self.SUPABASE_URL:
            url = self.SUPABASE_URL.strip()
            if url.endswith("/rest/v1/"):
                url = url[:-9]
            elif url.endswith("/rest/v1"):
                url = url[:-8]
            self.SUPABASE_URL = url.rstrip("/")

        is_prod = self.APP_ENV.lower() in ("production", "prod")
        insecure_defaults = {
            "cloudvuln-secops-super-secret-jwt-key-2026-prod-grade-change-me",
            "cloudvuln-secops-super-secret-refresh-key-2026-prod-grade-change-me",
            "change-this-to-a-secure-random-64-character-secret-key-in-production",
            "change-this-to-a-secure-random-64-character-refresh-key-in-production",
            "secret",
            "changeme",
        }
        if is_prod:
            if not self.SECRET_KEY or self.SECRET_KEY in insecure_defaults or len(self.SECRET_KEY) < 32:
                raise ValueError(
                    "CRITICAL SECURITY CONFIGURATION ERROR: In production mode (APP_ENV=production), "
                    "SECRET_KEY must be a strong, unique secret (minimum 32 characters) provided via environment variables. "
                    "Default or known placeholder secrets are strictly forbidden."
                )
            if not self.REFRESH_SECRET_KEY or self.REFRESH_SECRET_KEY in insecure_defaults or len(self.REFRESH_SECRET_KEY) < 32:
                raise ValueError(
                    "CRITICAL SECURITY CONFIGURATION ERROR: In production mode (APP_ENV=production), "
                    "REFRESH_SECRET_KEY must be a strong, unique secret (minimum 32 characters) provided via environment variables. "
                    "Default or known placeholder secrets are strictly forbidden."
                )

    class Config:
        env_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
        env_file_encoding = "utf-8"
        case_sensitive = False
        extra = "ignore"


settings = Settings()
