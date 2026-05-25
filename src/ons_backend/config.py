from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _read_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _read_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    return int(raw)


@dataclass(frozen=True)
class AppConfig:
    host: str
    port: int
    public_base_url: str
    data_dir: Path
    log_level: str
    timezone: str
    default_login_url: str
    sync_interval_minutes: int
    sms_timeout_seconds: int
    login_timeout_seconds: int
    setup_secret: str
    debug_token: str
    admin_token: str
    storage_key: str
    fcm_project_id: str
    fcm_service_account_file: Path | None
    fcm_service_account_json: str
    playwright_headless: bool
    post_login_url: str
    roster_url: str

    @property
    def state_file(self) -> Path:
        return self.data_dir / "state.json"

    @property
    def secret_key_file(self) -> Path:
        return self.data_dir / "secret.key"

    @property
    def snapshot_file(self) -> Path:
        return self.data_dir / "last-auth.html"

    @property
    def ics_file(self) -> Path:
        return self.data_dir / "rooster.ics"

    @property
    def managed_fcm_service_account_file(self) -> Path:
        return self.data_dir / "firebase-adminsdk.json.enc"

    @property
    def managed_fcm_upload_enabled(self) -> bool:
        return not self.fcm_service_account_json and self.fcm_service_account_file is None

    @classmethod
    def from_env(cls) -> "AppConfig":
        data_dir = Path(os.getenv("DATA_DIR", "./data")).resolve()
        fcm_service_account_file = os.getenv("FCM_SERVICE_ACCOUNT_FILE", "").strip()
        public_base_url = os.getenv(
            "PUBLIC_BASE_URL",
            "https://onsrooster.stefhermans.nl",
        ).rstrip("/")

        return cls(
            host=os.getenv("APP_HOST", "0.0.0.0"),
            port=_read_int("APP_PORT", 8080),
            public_base_url=public_base_url,
            data_dir=data_dir,
            log_level=os.getenv("LOG_LEVEL", "INFO").upper(),
            timezone=os.getenv("TZ", "Europe/Amsterdam"),
            default_login_url=os.getenv(
                "DEFAULT_LOGIN_URL",
                "https://landvanhorne.hasmoves.com",
            ).strip(),
            sync_interval_minutes=_read_int("SYNC_INTERVAL_MINUTES", 360),
            sms_timeout_seconds=_read_int("SMS_TIMEOUT_SECONDS", 150),
            login_timeout_seconds=_read_int("LOGIN_TIMEOUT_SECONDS", 30),
            setup_secret=os.getenv("SETUP_SECRET", "").strip(),
            debug_token=os.getenv("DEBUG_TOKEN", "").strip(),
            admin_token=os.getenv("ADMIN_TOKEN", "").strip(),
            storage_key=os.getenv("STORAGE_KEY", "").strip(),
            fcm_project_id=os.getenv("FCM_PROJECT_ID", "").strip(),
            fcm_service_account_file=Path(fcm_service_account_file) if fcm_service_account_file else None,
            fcm_service_account_json=os.getenv("FCM_SERVICE_ACCOUNT_JSON", "").strip(),
            playwright_headless=_read_bool("PLAYWRIGHT_HEADLESS", True),
            post_login_url=os.getenv("POST_LOGIN_URL", "").strip(),
            roster_url=os.getenv("ROSTER_URL", "").strip(),
        )
