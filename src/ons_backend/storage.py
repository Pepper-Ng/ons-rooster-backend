from __future__ import annotations

import json
from pathlib import Path
from tempfile import NamedTemporaryFile

from cryptography.fernet import Fernet

from .config import AppConfig
from .models import AppState, LoginCredentials


class StateStore:
    def __init__(self, config: AppConfig) -> None:
        self.config = config
        self.config.data_dir.mkdir(parents=True, exist_ok=True)
        # The same key is reused from the persistent data volume so encrypted credentials survive redeploys.
        self._fernet = Fernet(self._resolve_key())

    def load(self) -> tuple[AppState, LoginCredentials | None]:
        if not self.config.state_file.exists():
            return AppState(), None

        raw = json.loads(self.config.state_file.read_text(encoding="utf-8"))
        state = AppState.from_dict(raw.get("state", {}))
        encrypted_credentials = raw.get("encrypted_credentials")
        credentials = None

        if encrypted_credentials:
            decrypted = self._fernet.decrypt(encrypted_credentials.encode("utf-8")).decode("utf-8")
            credentials = LoginCredentials.from_dict(json.loads(decrypted))

        return state, credentials

    def save(self, state: AppState, credentials: LoginCredentials | None) -> None:
        payload = {
            "version": 1,
            "state": state.to_dict(),
            "encrypted_credentials": None,
        }

        if credentials is not None:
            serialized = json.dumps(credentials.to_dict(), ensure_ascii=True)
            payload["encrypted_credentials"] = self._fernet.encrypt(
                serialized.encode("utf-8")
            ).decode("utf-8")

        self._write_atomic(self.config.state_file, json.dumps(payload, indent=2))

    def write_snapshot(self, html: str) -> None:
        self._write_atomic(self.config.snapshot_file, html)

    def write_ics(self, payload: bytes) -> None:
        self._write_atomic_bytes(self.config.ics_file, payload)

    def read_ics(self) -> bytes | None:
        if not self.config.ics_file.exists():
            return None
        return self.config.ics_file.read_bytes()

    def _resolve_key(self) -> bytes:
        if self.config.storage_key:
            return self.config.storage_key.encode("utf-8")

        key_path = self.config.data_dir / "secret.key"
        if key_path.exists():
            return key_path.read_bytes().strip()

        # A generated key is written once when the stack starts without an injected key.
        key = Fernet.generate_key()
        key_path.write_bytes(key)
        return key

    @staticmethod
    def _write_atomic(path: Path, content: str) -> None:
        with NamedTemporaryFile("w", delete=False, encoding="utf-8", dir=path.parent) as handle:
            handle.write(content)
            temp_name = handle.name
        Path(temp_name).replace(path)

    @staticmethod
    def _write_atomic_bytes(path: Path, content: bytes) -> None:
        with NamedTemporaryFile("wb", delete=False, dir=path.parent) as handle:
            handle.write(content)
            temp_name = handle.name
        Path(temp_name).replace(path)
