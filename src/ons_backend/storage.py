from __future__ import annotations

import base64
import json
import os
import re
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .config import AppConfig
from .models import AppState, LoginCredentials


CREDENTIAL_EXPORT_FORMAT = "ons-rooster-credentials-export"
CREDENTIAL_EXPORT_ITERATIONS = 600_000


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

    def write_post_otp_screenshot(self, payload: bytes) -> None:
        self._write_atomic_bytes(self.config.post_otp_screenshot_file, payload)

    def read_post_otp_screenshot(self) -> bytes | None:
        if not self.config.post_otp_screenshot_file.exists():
            return None
        return self.config.post_otp_screenshot_file.read_bytes()

    def write_ics(self, payload: bytes) -> None:
        self._write_atomic_bytes(self.config.ics_file, payload)

    def read_ics(self) -> bytes | None:
        if not self.config.ics_file.exists():
            return None
        return self.config.ics_file.read_bytes()

    def clear_roster_month_exports(self) -> None:
        if not self.config.roster_exports_dir.exists():
            return
        for export_file in self.config.roster_exports_dir.glob("*.json"):
            export_file.unlink(missing_ok=True)

    def write_roster_month_export(self, month_key: str, payload: dict[str, Any]) -> None:
        self.config.roster_exports_dir.mkdir(parents=True, exist_ok=True)
        safe_month_key = re.sub(r"[^0-9-]", "", month_key)
        if not safe_month_key:
            raise RuntimeError("Kan roosterexport niet opslaan zonder geldige maandsleutel.")
        export_path = self.config.roster_exports_dir / f"{safe_month_key}.json"
        serialized = json.dumps(payload, ensure_ascii=True, indent=2)
        self._write_atomic(export_path, serialized)

    def read_roster_month_export(self, month_key: str) -> dict[str, Any] | None:
        safe_month_key = re.sub(r"[^0-9-]", "", month_key)
        if not safe_month_key:
            return None
        export_path = self.config.roster_exports_dir / f"{safe_month_key}.json"
        if not export_path.exists():
            return None
        payload = json.loads(export_path.read_text(encoding="utf-8"))
        return payload if isinstance(payload, dict) else None

    def write_auth_session(self, payload: dict[str, object] | None) -> None:
        if payload is None:
            self.clear_auth_session()
            return

        serialized = json.dumps(payload, ensure_ascii=True)
        encrypted = self._fernet.encrypt(serialized.encode("utf-8")).decode("utf-8")
        self._write_atomic(self.config.auth_session_file, encrypted)
        self._set_owner_only_permissions(self.config.auth_session_file)

    def read_auth_session(self) -> dict[str, object] | None:
        if not self.config.auth_session_file.exists():
            return None

        encrypted = self.config.auth_session_file.read_text(encoding="utf-8")
        decrypted = self._fernet.decrypt(encrypted.encode("utf-8")).decode("utf-8")
        payload = json.loads(decrypted)
        if not isinstance(payload, dict):
            raise RuntimeError("Het opgeslagen authenticatiesessie-bestand bevat geen JSON-object.")
        return payload

    def clear_auth_session(self) -> None:
        if self.config.auth_session_file.exists():
            self.config.auth_session_file.unlink()

    def write_managed_fcm_service_account(self, content: str) -> None:
        encrypted = self._fernet.encrypt(content.encode("utf-8")).decode("utf-8")
        self._write_atomic(self.config.managed_fcm_service_account_file, encrypted)
        self._set_owner_only_permissions(self.config.managed_fcm_service_account_file)

    def build_credentials_export(self, credentials: LoginCredentials, passphrase: str) -> dict[str, Any]:
        salt = os.urandom(16)
        export_key = self._derive_export_key(passphrase, salt, CREDENTIAL_EXPORT_ITERATIONS)
        payload = json.dumps(
            {"credentials": credentials.to_dict()},
            ensure_ascii=True,
            separators=(",", ":"),
        )
        ciphertext = Fernet(export_key).encrypt(payload.encode("utf-8")).decode("utf-8")
        return {
            "format": CREDENTIAL_EXPORT_FORMAT,
            "version": 1,
            "kdf": "pbkdf2-sha256",
            "iterations": CREDENTIAL_EXPORT_ITERATIONS,
            "salt": base64.urlsafe_b64encode(salt).decode("ascii"),
            "ciphertext": ciphertext,
        }

    @staticmethod
    def decrypt_credentials_export(payload: dict[str, Any], passphrase: str) -> LoginCredentials:
        if str(payload.get("format", "")).strip() != CREDENTIAL_EXPORT_FORMAT:
            raise RuntimeError("Het exportbestand heeft geen geldig ONS-credentialexportformaat.")
        if int(payload.get("version", 0)) != 1:
            raise RuntimeError("Het exportbestand gebruikt een niet-ondersteunde versie.")
        if str(payload.get("kdf", "")).strip() != "pbkdf2-sha256":
            raise RuntimeError("Het exportbestand gebruikt een niet-ondersteund sleutelafleidingsformaat.")

        try:
            iterations = int(payload.get("iterations", 0))
        except (TypeError, ValueError) as exc:
            raise RuntimeError("Het exportbestand bevat geen geldige iteratie-instelling.") from exc
        if iterations <= 0:
            raise RuntimeError("Het exportbestand bevat geen geldige iteratie-instelling.")

        salt_value = str(payload.get("salt", "")).strip()
        ciphertext = str(payload.get("ciphertext", "")).strip()
        if not salt_value or not ciphertext:
            raise RuntimeError("Het exportbestand mist verplichte encryptievelden.")

        try:
            salt = base64.urlsafe_b64decode(salt_value.encode("ascii"))
        except Exception as exc:
            raise RuntimeError("De salt in het exportbestand is ongeldig.") from exc

        export_key = StateStore._derive_export_key(passphrase, salt, iterations)
        try:
            decrypted = Fernet(export_key).decrypt(ciphertext.encode("utf-8")).decode("utf-8")
        except InvalidToken as exc:
            raise RuntimeError(
                "De export-passphrase is ongeldig of het exportbestand is beschadigd."
            ) from exc

        raw_payload = json.loads(decrypted)
        if not isinstance(raw_payload, dict):
            raise RuntimeError("Het exportbestand bevat geen geldig JSON-object.")

        credentials = raw_payload.get("credentials")
        if not isinstance(credentials, dict):
            raise RuntimeError("Het exportbestand bevat geen geldige ONS-inloggegevens.")
        return LoginCredentials.from_dict(credentials)

    def _resolve_key(self) -> bytes:
        if self.config.storage_key:
            return self.config.storage_key.encode("utf-8")

        key_path = self.config.secret_key_file
        if key_path.exists():
            self._set_owner_only_permissions(key_path)
            return key_path.read_bytes().strip()

        # A generated key is written once when the stack starts without an injected key.
        key = Fernet.generate_key()
        key_path.write_bytes(key)
        self._set_owner_only_permissions(key_path)
        return key

    @staticmethod
    def _derive_export_key(passphrase: str, salt: bytes, iterations: int) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
        )
        return base64.urlsafe_b64encode(kdf.derive(passphrase.encode("utf-8")))

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

    @staticmethod
    def _set_owner_only_permissions(path: Path) -> None:
        try:
            path.chmod(0o600)
        except OSError:
            # Permission tightening is best-effort because Windows and container mounts vary.
            pass
