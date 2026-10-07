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
        "https://github.com/Ananthapriyan-ui/cloud-vuln-.git",
        "https://miniproject.vercel.app",
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

    class Config:
        env_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
        env_file_encoding = "utf-8"
        case_sensitive = False
        extra = "ignore"


settings = Settings()
