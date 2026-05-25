from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class DeviceRegistration:
    device_id: str
    device_label: str
    fcm_token: str
    api_token_hash: str
    created_at: str
    updated_at: str
    last_seen_at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "device_id": self.device_id,
            "device_label": self.device_label,
            "fcm_token": self.fcm_token,
            "api_token_hash": self.api_token_hash,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "last_seen_at": self.last_seen_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "DeviceRegistration":
        return cls(
            device_id=str(data.get("device_id", "")).strip() or "legacy-device",
            device_label=data.get("device_label", ""),
            fcm_token=data.get("fcm_token", ""),
            api_token_hash=data.get("api_token_hash", ""),
            created_at=data.get("created_at", ""),
            updated_at=data.get("updated_at", ""),
            last_seen_at=data.get("last_seen_at"),
        )


@dataclass
class LoginCredentials:
    login_url: str
    username: str
    password: str

    def to_dict(self) -> dict[str, str]:
        return {
            "login_url": self.login_url,
            "username": self.username,
            "password": self.password,
        }

    @classmethod
    def from_dict(cls, data: dict[str, str]) -> "LoginCredentials":
        return cls(
            login_url=data.get("login_url", ""),
            username=data.get("username", ""),
            password=data.get("password", ""),
        )


@dataclass
class RosterItem:
    date: str
    start: str
    end: str
    description: str
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "date": self.date,
            "start": self.start,
            "end": self.end,
            "description": self.description,
            "raw": self.raw,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RosterItem":
        return cls(
            date=data.get("date", ""),
            start=data.get("start", ""),
            end=data.get("end", ""),
            description=data.get("description", ""),
            raw=data.get("raw", {}),
        )


@dataclass
class SyncState:
    status: str = "idle"
    current_phase: str = "idle"
    auth_ready: bool = False
    last_reason: str | None = None
    last_attempt_at: str | None = None
    last_success_at: str | None = None
    last_failure_at: str | None = None
    last_error: str | None = None
    last_message: str | None = None
    current_challenge_id: str | None = None
    challenge_created_at: str | None = None
    last_sms_received_at: str | None = None
    last_sms_code_suffix: str | None = None
    last_final_url: str | None = None
    last_page_title: str | None = None
    html_snapshot_path: str | None = None
    roster_items: list[RosterItem] = field(default_factory=list)
    debug_notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "current_phase": self.current_phase,
            "auth_ready": self.auth_ready,
            "last_reason": self.last_reason,
            "last_attempt_at": self.last_attempt_at,
            "last_success_at": self.last_success_at,
            "last_failure_at": self.last_failure_at,
            "last_error": self.last_error,
            "last_message": self.last_message,
            "current_challenge_id": self.current_challenge_id,
            "challenge_created_at": self.challenge_created_at,
            "last_sms_received_at": self.last_sms_received_at,
            "last_sms_code_suffix": self.last_sms_code_suffix,
            "last_final_url": self.last_final_url,
            "last_page_title": self.last_page_title,
            "html_snapshot_path": self.html_snapshot_path,
            "roster_items": [item.to_dict() for item in self.roster_items],
            "debug_notes": list(self.debug_notes),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SyncState":
        return cls(
            status=data.get("status", "idle"),
            current_phase=data.get("current_phase", "idle"),
            auth_ready=bool(data.get("auth_ready", False)),
            last_reason=data.get("last_reason"),
            last_attempt_at=data.get("last_attempt_at"),
            last_success_at=data.get("last_success_at"),
            last_failure_at=data.get("last_failure_at"),
            last_error=data.get("last_error"),
            last_message=data.get("last_message"),
            current_challenge_id=data.get("current_challenge_id"),
            challenge_created_at=data.get("challenge_created_at"),
            last_sms_received_at=data.get("last_sms_received_at"),
            last_sms_code_suffix=data.get("last_sms_code_suffix"),
            last_final_url=data.get("last_final_url"),
            last_page_title=data.get("last_page_title"),
            html_snapshot_path=data.get("html_snapshot_path"),
            roster_items=[RosterItem.from_dict(item) for item in data.get("roster_items", [])],
            debug_notes=list(data.get("debug_notes", [])),
        )


@dataclass
class AppState:
    devices: list[DeviceRegistration] = field(default_factory=list)
    active_device_id: str | None = None
    credentials_updated_at: str | None = None
    sync: SyncState = field(default_factory=SyncState)

    def to_dict(self) -> dict[str, Any]:
        return {
            "devices": [device.to_dict() for device in self.devices],
            "active_device_id": self.active_device_id,
            "credentials_updated_at": self.credentials_updated_at,
            "sync": self.sync.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AppState":
        devices_data = data.get("devices")
        if devices_data is None:
            legacy_device = data.get("device")
            devices = [DeviceRegistration.from_dict(legacy_device)] if legacy_device else []
        else:
            devices = [DeviceRegistration.from_dict(device) for device in devices_data]

        active_device_id = data.get("active_device_id")
        if not active_device_id and devices:
            active_device_id = devices[-1].device_id

        return cls(
            devices=devices,
            active_device_id=active_device_id,
            credentials_updated_at=data.get("credentials_updated_at"),
            sync=SyncState.from_dict(data.get("sync", {})),
        )


@dataclass
class AuthenticationResult:
    final_url: str
    page_title: str
    roster_items: list[RosterItem]
    debug_notes: list[str]
    auth_ready: bool = True
