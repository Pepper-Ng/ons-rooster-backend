from __future__ import annotations

import html
import logging
from typing import Any

from aiohttp import web

from .clients import FcmPushClient, NoopPushClient, PlaywrightAutomationClient
from .config import AppConfig
from .service import BackendService
from .storage import StateStore


def create_app(
    *,
    config: AppConfig | None = None,
    service: BackendService | None = None,
) -> web.Application:
    config = config or AppConfig.from_env()
    logging.basicConfig(level=getattr(logging, config.log_level, logging.INFO))

    if service is None:
        store = StateStore(config)
        push_client = FcmPushClient(config)
        if not push_client.is_configured():
            push_client = NoopPushClient()
        # Production wiring stays in one place so tests can inject fake push and browser clients.
        service = BackendService(
            config=config,
            store=store,
            push_client=push_client,
            automation_client=PlaywrightAutomationClient(),
        )

    app = web.Application()
    app["config"] = config
    app["service"] = service

    app.router.add_get("/", handle_root)
    app.router.add_get("/healthz", handle_health)
    app.router.add_get("/rooster.ics", handle_ics)
    app.router.add_get("/debug", handle_debug)
    app.router.add_get("/api/v1/mobile/status", handle_mobile_status)
    app.router.add_post("/api/v1/mobile/setup", handle_mobile_setup)
    app.router.add_put("/api/v1/mobile/setup", handle_mobile_setup)
    app.router.add_post("/api/v1/mobile/tokens/fcm", handle_fcm_token)
    app.router.add_post("/api/v1/mobile/challenges/{challenge_id}/sms-code", handle_sms_code)
    app.router.add_post("/api/v1/admin/refresh", handle_refresh)

    app.on_startup.append(on_startup)
    app.on_cleanup.append(on_cleanup)
    return app


async def on_startup(app: web.Application) -> None:
    await _service(app).start()


async def on_cleanup(app: web.Application) -> None:
    await _service(app).stop()


async def handle_root(request: web.Request) -> web.Response:
    return web.json_response(
        {
            "service": "ons-rooster-backend",
            "health": "/healthz",
            "mobile_status": "/api/v1/mobile/status",
            "debug": "/debug",
        }
    )


async def handle_health(request: web.Request) -> web.Response:
    return web.json_response({"status": "ok"})


async def handle_ics(request: web.Request) -> web.Response:
    payload = await _service(request.app).ics_payload()
    if payload is None:
        return web.Response(status=404, text="Er is nog geen roosterbestand beschikbaar.")
    return web.Response(
        body=payload,
        content_type="text/calendar",
        headers={"Content-Disposition": 'attachment; filename="rooster.ics"'},
    )


async def handle_debug(request: web.Request) -> web.Response:
    token = request.query.get("token") or request.headers.get("X-Debug-Token")
    service = _service(request.app)
    if not service.debug_token_is_valid(token):
        raise web.HTTPUnauthorized(text="Ongeldig debug-token.")

    snapshot = await service.debug_snapshot_html()
    status = service.mobile_status_payload()

    rows = "".join(
        "<tr>"
        f"<td>{html.escape(item.date)}</td>"
        f"<td>{html.escape(item.start)}</td>"
        f"<td>{html.escape(item.end)}</td>"
        f"<td>{html.escape(item.description)}</td>"
        "</tr>"
        for item in service.roster_items()
    )
    notes = "".join(
        f"<li>{html.escape(note)}</li>"
        for note in status["sync"]["debug_notes"]
    )

    body = f"""
<!doctype html>
<html lang="nl">
<head>
  <meta charset="utf-8">
  <title>ONS Rooster Debug</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 2rem; background: #f6f8fb; color: #1f2937; }}
    h1, h2 {{ margin-bottom: 0.5rem; }}
    section {{ background: white; border-radius: 12px; padding: 1rem 1.25rem; margin-bottom: 1rem; box-shadow: 0 8px 24px rgba(15, 23, 42, 0.08); }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ text-align: left; padding: 0.5rem; border-bottom: 1px solid #e5e7eb; vertical-align: top; }}
    code {{ background: #eef2ff; padding: 0.1rem 0.35rem; border-radius: 4px; }}
    pre {{ white-space: pre-wrap; word-break: break-word; background: #0f172a; color: white; padding: 1rem; border-radius: 10px; }}
  </style>
</head>
<body>
  <h1>ONS Rooster Debug</h1>
  <section>
    <h2>Status</h2>
    <p><strong>Backend-URL:</strong> {html.escape(status['public_base_url'])}</p>
    <p><strong>Inlogpagina:</strong> {html.escape(status['login_url'])}</p>
    <p><strong>Gebruikersnaam:</strong> {html.escape(status['username'])}</p>
    <p><strong>App gekoppeld:</strong> {status['device_registered']}</p>
    <p><strong>FCM geconfigureerd:</strong> {status['fcm_configured']}</p>
    <p><strong>Laatste status:</strong> {html.escape(str(status['sync']['last_message'] or '-'))}</p>
    <p><strong>Laatste fout:</strong> {html.escape(str(status['sync']['last_error'] or '-'))}</p>
    <p><strong>Laatste poging:</strong> {html.escape(str(status['sync']['last_attempt_at'] or '-'))}</p>
    <p><strong>Laatste succesvolle login:</strong> {html.escape(str(status['sync']['last_success_at'] or '-'))}</p>
    <p><strong>Laatste eind-URL:</strong> {html.escape(str(status['sync']['last_final_url'] or '-'))}</p>
    <p><strong>Laatste paginatitel:</strong> {html.escape(str(status['sync']['last_page_title'] or '-'))}</p>
  </section>
  <section>
    <h2>Roosterresultaat</h2>
    <table>
      <thead>
        <tr><th>Datum</th><th>Begin</th><th>Einde</th><th>Omschrijving</th></tr>
      </thead>
      <tbody>{rows or '<tr><td colspan="4">Nog geen roosterdata beschikbaar.</td></tr>'}</tbody>
    </table>
  </section>
  <section>
    <h2>Debugnotities</h2>
    <ul>{notes or '<li>Nog geen debugnotities beschikbaar.</li>'}</ul>
  </section>
  <section>
    <h2>Laatste HTML-snapshot</h2>
    <pre>{html.escape(snapshot[:4000] if snapshot else 'Er is nog geen HTML-snapshot opgeslagen.')}</pre>
  </section>
</body>
</html>
"""
    return web.Response(text=body, content_type="text/html")


async def handle_mobile_status(request: web.Request) -> web.Response:
    _require_mobile_auth(request)
    return web.json_response(_service(request.app).mobile_status_payload())


async def handle_mobile_setup(request: web.Request) -> web.Response:
    service = _service(request.app)
    payload = await request.json()
    auth_token = _extract_bearer_token(request)
    setup_secret = payload.get("setup_secret") or request.headers.get("X-Setup-Secret")

    if service.has_device():
        if not (service.mobile_token_is_valid(auth_token) or service.setup_secret_is_valid(setup_secret)):
            raise web.HTTPUnauthorized(text="Ongeldige app-verificatie of installatiecode.")
    elif not service.setup_secret_is_valid(setup_secret):
        raise web.HTTPUnauthorized(text="Ongeldige installatiecode.")

    required_fields = ["login_url", "username", "password", "fcm_token"]
    missing = [field for field in required_fields if not str(payload.get(field, "")).strip()]
    if missing:
        raise web.HTTPBadRequest(text=f"Ontbrekende velden: {', '.join(missing)}")

    result = await service.upsert_mobile_setup(
        login_url=str(payload.get("login_url", "")),
        username=str(payload.get("username", "")),
        password=str(payload.get("password", "")),
        fcm_token=str(payload.get("fcm_token", "")),
        device_label=str(payload.get("device_label", "Android-telefoon")),
        rotate_api_token=bool(payload.get("rotate_api_token", False)),
    )
    return web.json_response(result, status=200)


async def handle_fcm_token(request: web.Request) -> web.Response:
    _require_mobile_auth(request)
    payload = await request.json()
    token = str(payload.get("fcm_token", "")).strip()
    if not token:
        raise web.HTTPBadRequest(text="Het FCM-token ontbreekt.")
    await _service(request.app).update_fcm_token(token, payload.get("device_label"))
    return web.json_response({"message": "Het FCM-token is bijgewerkt."})


async def handle_sms_code(request: web.Request) -> web.Response:
    _require_mobile_auth(request)
    payload = await request.json()
    code = str(payload.get("code", "")).strip()
    sender = str(payload.get("sender", "")).strip()
    if not code:
        raise web.HTTPBadRequest(text="De SMS-code ontbreekt.")
    await _service(request.app).submit_sms_code(request.match_info["challenge_id"], code, sender)
    return web.json_response({"message": "De SMS-code is ontvangen."})


async def handle_refresh(request: web.Request) -> web.Response:
    token = request.headers.get("X-Admin-Token") or request.query.get("token")
    service = _service(request.app)
    if not service.admin_token_is_valid(token):
        raise web.HTTPUnauthorized(text="Ongeldig admin-token.")
    status = await service.trigger_refresh(reason="manual", wait=False)
    return web.json_response({"message": "De handmatige synchronisatie is gestart.", "status": status})


def _service(app: web.Application) -> BackendService:
    return app["service"]


def _extract_bearer_token(request: web.Request) -> str | None:
    authorization = request.headers.get("Authorization", "")
    if authorization.lower().startswith("bearer "):
        return authorization.split(" ", 1)[1].strip()
    return None


def _require_mobile_auth(request: web.Request) -> None:
    token = _extract_bearer_token(request)
    if not _service(request.app).mobile_token_is_valid(token):
        raise web.HTTPUnauthorized(text="Ongeldige app-token.")
