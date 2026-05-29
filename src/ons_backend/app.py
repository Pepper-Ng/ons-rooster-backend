from __future__ import annotations

import asyncio
import hashlib
import html
import hmac
import json
import logging
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlencode

from aiohttp import web

from .clients import FcmPushClient, HttpLoginAutomationClient
from .config import AppConfig
from .service import BackendService
from .storage import StateStore

OPS_SESSION_COOKIE = "ons_status_session"
MOCK_SMS_CODE = "123456"
ONS_BRAND_LOGO_DATA_URI = "data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMzgyIiBoZWlnaHQ9IjEzMSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj48ZyBmaWxsPSIjQkRCREJEIiBmaWxsLXJ1bGU9ImV2ZW5vZGQiPjxwYXRoIGQ9Ik0xNTEuMDMxIDEyNy40NDlWMy4xNDJoMzcuNjQ2djE2LjIwMVMyMDAuNjMuNzE5IDIyNC45MjcuNzE5YzI0LjY5MiAwIDQ0Ljc0IDE3LjgyMSA0NC43NCA0MS4yOTZ2ODUuNDM0aC0zOC44NzRWNTQuNTc4YzAtMTAuMzQzLTIuODM0LTIwLjA1LTE5LjQzMi0yMC4wNS0xMi4xNDkgMC0yMi4yNjcgOS45MjMtMjIuMjY3IDIxLjg1OHY3MS4wNjNoLTM4LjA2M002Ni44NjggOTUuNDY3Yy0xNy41NjUgMC0zMC41ODgtMTMuMjMtMzAuNTg4LTMwLjE3OCAwLS41NDYuMDQ1LTEuMDc5LjA2OC0xLjYxOGg2MS4wOWMtLjA5IDE5LjcwNy0xMS42MjIgMzEuNzk2LTMwLjU3IDMxLjc5NlptLjM5LTk0Ljc0OEMyOS43NDMuNzE5LjU2OSAyOC4xMTkuNTY5IDY0LjYzMmMwIDMzLjk1NiAyOC41NzYgNjQuNTIzIDY1Ljg5NiA2NC41MjMgMzkuNjk5IDAgNjYuNDkzLTI3Ljk5NSA2Ni40OTMtNjUuMTEzIDAtMzYuNzE0LTI4Ljc2Ni02My4zMjMtNjUuNy02My4zMjNaTTMyMy44IDM4LjM2OGMwLTQuODQyIDMuODM1LTcuNDg0IDkuOTA1LTcuNDg0IDEwLjkzNyAwIDE1LjM5OCA5LjcwOSAxNS4zOTggOS43MDloMzAuNzgzYzAtMTQuMTQ3LTEyLjc1MS0zOS44NzQtNDIuOTMxLTM5Ljg3NC0yNy41MzQgMC00Ny41NzkgMTYuNDAxLTQ3LjU3OSA0MC40ODYgMCA0My43MyA1NS42NzQgMzUuNjM0IDU1LjY3NCA1MS4wMTQgMCA1Ljg3LTcuMjkzIDguNzA0LTEzLjM1OCA4LjcwNC0xMS4xNDIgMC0xNy40MjUtMTAuOTI1LTE3LjQyNS0xMC45MjVsLTI4LjkzOCAxNC41NjhjOS43MTggMTguMjM3IDI1LjA5OCAyNS45MTMgNDUuOTUgMjUuOTEzIDI2LjMyMyAwIDQ5LjgwMy0xNC4zNzIgNDkuODAzLTQxLjI5MiAwLTQyLjUxLTU3LjI4Mi0zNi44NC01Ny4yODItNTAuODE5Ii8+PC9nPjwvc3ZnPg=="


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
        service = BackendService(
            config=config,
            store=store,
            push_client=push_client,
            automation_client=HttpLoginAutomationClient(),
        )

    app = web.Application()
    app["config"] = config
    app["service"] = service

    app.router.add_get("/", handle_root)
    app.router.add_get("/healthz", handle_health)
    app.router.add_get("/rooster.ics", handle_ics)
    app.router.add_get("/debug", handle_debug)
    app.router.add_get("/install", handle_install_page)
    app.router.add_post("/install", handle_install_upload)
    app.router.add_get("/status", handle_status_page)
    app.router.add_post("/status/login", handle_status_login)
    app.router.add_post("/status/logout", handle_status_logout)
    app.router.add_get("/status/auth-trace/{entry_id}", handle_status_auth_trace)
    app.router.add_post("/status/refresh", handle_status_refresh)
    app.router.add_post("/status/challenges/mock-sms", handle_status_mock_sms)
    app.router.add_post("/status/devices/{device_id}/activate", handle_status_activate_device)
    app.router.add_post("/status/devices/{device_id}/ping", handle_status_ping_device)
    app.router.add_post("/status/devices/{device_id}/remove", handle_status_remove_device)
    app.router.add_get("/sandbox/hasmoves/login", handle_mock_login_page)
    app.router.add_post("/sandbox/hasmoves/login", handle_mock_login_submit)
    app.router.add_post("/sandbox/hasmoves/challenge", handle_mock_challenge_submit)
    app.router.add_get("/sandbox/hasmoves/rooster", handle_mock_rooster_page)
    app.router.add_get("/status/live", handle_status_live)
    app.router.add_get("/api/v1/mobile/config", handle_mobile_config)
    app.router.add_get("/api/v1/mobile/status", handle_mobile_status)
    app.router.add_get("/api/v1/mobile/live", handle_mobile_live)
    app.router.add_post("/api/v1/mobile/setup", handle_mobile_setup)
    app.router.add_put("/api/v1/mobile/setup", handle_mobile_setup)
    app.router.add_delete("/api/v1/mobile/device", handle_mobile_device_remove)
    app.router.add_post("/api/v1/mobile/tokens/fcm", handle_fcm_token)
    app.router.add_post("/api/v1/mobile/challenges/{challenge_id}/sms-code", handle_sms_code)
    app.router.add_get("/api/v1/admin/status", handle_admin_status)
    app.router.add_post("/api/v1/admin/challenges/mock-sms", handle_admin_mock_sms)
    app.router.add_post("/api/v1/admin/devices/{device_id}/activate", handle_admin_activate_device)
    app.router.add_post("/api/v1/admin/devices/{device_id}/ping", handle_admin_ping_device)
    app.router.add_delete("/api/v1/admin/devices/{device_id}", handle_admin_remove_device)
    app.router.add_post("/api/v1/admin/portals", handle_admin_portal_upsert)
    app.router.add_delete("/api/v1/admin/portals/{portal_id}", handle_admin_portal_remove)
    app.router.add_post("/api/v1/admin/refresh", handle_refresh)
    app.router.add_get("/api/v1/admin/fcm", handle_admin_fcm_status)
    app.router.add_post("/api/v1/admin/fcm/test", handle_admin_fcm_test)

    app.on_startup.append(on_startup)
    app.on_cleanup.append(on_cleanup)
    return app


async def on_startup(app: web.Application) -> None:
    await _service(app).start()


async def on_cleanup(app: web.Application) -> None:
    await _service(app).stop()


async def handle_root(request: web.Request) -> web.Response:
    config = request.app["config"]
    return web.json_response(
        {
            "service": "ons-rooster-backend",
            "health": "/healthz",
            "mobile_status": "/api/v1/mobile/status",
            "debug": "/debug",
            "install": "/install",
            "status": "/status",
            "mock_login_basic": f"{config.public_base_url}/sandbox/hasmoves/login",
            "mock_login_sms": f"{config.public_base_url}/sandbox/hasmoves/login?mode=sms",
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
    <p><strong>Operatorpagina:</strong> <a href="/status">/status</a></p>
    <p><strong>Installatiepagina:</strong> <a href="/install">/install</a></p>
    <p><strong>Backend-URL:</strong> {html.escape(status['public_base_url'])}</p>
    <p><strong>Inlogpagina:</strong> {html.escape(status['login_url'])}</p>
    <p><strong>Gebruikersnaam:</strong> {html.escape(status['username'])}</p>
    <p><strong>Gekoppelde apparaten:</strong> {status['device_count']}</p>
    <p><strong>Actief apparaat:</strong> {html.escape(status['active_device_label'] or '-')}</p>
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


async def handle_install_page(request: web.Request) -> web.Response:
    authorized = _ops_is_authorized(request)
    diagnostics = _fcm_diagnostics(request.app) if authorized else None
    error = request.query.get("error") if authorized else None
    response = _render_install_response(
        request.app,
        diagnostics=diagnostics,
        message=request.query.get("message"),
        error=error,
        status=200 if authorized else 401,
        authorized=authorized,
    )
    _maybe_set_ops_session_cookie(request, response, authorized=authorized)
    return response


async def handle_install_upload(request: web.Request) -> web.Response:
    form = await request.post()
    form_token = str(form.get("admin_token", "")).strip()
    if not (_ops_is_authorized(request) or _service(request.app).admin_token_is_valid(form_token)):
        return _render_install_response(
            request.app,
            diagnostics=None,
            message=None,
            error="Ongeldig admin-token.",
            status=401,
            authorized=False,
        )

    service = _service(request.app)
    upload = form.get("firebase_key")
    if upload is None or not hasattr(upload, "file"):
        return _render_install_response(
            request.app,
            diagnostics=_fcm_diagnostics(request.app),
            message=None,
            error="Selecteer een Firebase service-account JSON-bestand om te uploaden.",
            status=400,
            authorized=True,
        )

    file_bytes = upload.file.read()
    try:
        raw_payload = file_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return _render_install_response(
            request.app,
            diagnostics=_fcm_diagnostics(request.app),
            message=None,
            error="De geuploade Firebase-sleutel moet UTF-8 JSON zijn.",
            status=400,
            authorized=True,
        )

    try:
        diagnostics = await service.install_fcm_service_account(raw_payload)
    except Exception as exc:
        return _render_install_response(
            request.app,
            diagnostics=_fcm_diagnostics(request.app),
            message=None,
            error=str(exc),
            status=400,
            authorized=True,
        )

    diagnostics.update(_device_summary(service))
    return _render_install_response(
        request.app,
        diagnostics=diagnostics,
        message="De Firebase-sleutel is opgeslagen. De backend kan FCM nu zonder redeploy gebruiken.",
        error=None,
        status=200,
        authorized=True,
    )


async def handle_status_page(request: web.Request) -> web.Response:
    if not _ops_is_authorized(request):
        return _render_status_page(
            request.app,
            authorized=False,
            message=None,
            error=request.query.get("error"),
            status=401 if request.query.get("error") else 200,
        )

    response = _render_status_page(
        request.app,
        authorized=True,
        message=request.query.get("message"),
        error=request.query.get("error"),
        status=200,
    )
    _maybe_set_ops_session_cookie(request, response, authorized=True)
    return response


async def handle_status_login(request: web.Request) -> web.Response:
    form = await request.post()
    token = str(form.get("admin_token", "")).strip()
    if not _service(request.app).admin_token_is_valid(token):
        return _render_status_page(
            request.app,
            authorized=False,
            message=None,
            error="Ongeldig admin-token.",
            status=401,
        )

    response = web.HTTPSeeOther(location="/status")
    response.set_cookie(
        OPS_SESSION_COOKIE,
        _ops_session_value(request.app["config"]),
        secure=request.url.scheme == "https",
        httponly=True,
        samesite="Strict",
        path="/",
    )
    raise response


async def handle_status_logout(request: web.Request) -> web.Response:
    response = web.HTTPSeeOther(location="/status")
    response.del_cookie(OPS_SESSION_COOKIE, path="/")
    raise response


async def handle_status_auth_trace(request: web.Request) -> web.Response:
    _require_ops_auth(request)
    snapshot = await _service(request.app).auth_trace_snapshot_html(request.match_info["entry_id"])
    if snapshot is None:
        raise web.HTTPNotFound(text="Er is geen HTML-snapshot voor deze authenticatiestap opgeslagen.")

    return web.Response(
        text=(
            "<!doctype html><html lang='nl'><head><meta charset='utf-8'><title>Authenticatiesnapshot</title>"
            "<style>body { font-family: Arial, sans-serif; margin: 2rem; background: #f6f8fb; color: #1f2937; } "
            "pre { white-space: pre-wrap; word-break: break-word; background: #0f172a; color: white; padding: 1rem; border-radius: 10px; }</style>"
            "</head><body><p><a href='/status'>Terug naar operatorstatus</a></p>"
            f"<pre>{html.escape(snapshot[:12000])}</pre></body></html>"
        ),
        content_type="text/html",
    )


async def handle_status_refresh(request: web.Request) -> web.Response:
    _require_ops_auth(request)
    await _service(request.app).trigger_refresh(reason="manual-status", wait=False)
    raise _status_redirect("De handmatige synchronisatie is gestart.")


async def handle_status_mock_sms(request: web.Request) -> web.Response:
    _require_ops_auth(request)
    try:
        await _service(request.app).submit_mock_sms_code(code=MOCK_SMS_CODE)
    except Exception as exc:
        raise _status_redirect(error=str(exc))
    raise _status_redirect(f"Mock OTP {MOCK_SMS_CODE} is ingestuurd voor de actieve uitdaging.")


async def handle_status_activate_device(request: web.Request) -> web.Response:
    _require_ops_auth(request)
    try:
        device = await _service(request.app).activate_device(request.match_info["device_id"])
    except Exception as exc:
        raise _status_redirect(error=str(exc))
    raise _status_redirect(f"{device.device_label} is nu het actieve apparaat.")


async def handle_status_ping_device(request: web.Request) -> web.Response:
    _require_ops_auth(request)
    service = _service(request.app)
    device = service.device_by_id(request.match_info["device_id"])
    if device is None:
        raise _status_redirect(error="Het gevraagde apparaat bestaat niet meer.")

    message = f"Ping vanaf de statuspagina voor {device.device_label} om {datetime.now(UTC).strftime('%H:%M:%S')} UTC."
    try:
        await service.send_test_notification(message, device_id=device.device_id)
    except Exception as exc:
        raise _status_redirect(error=str(exc))
    raise _status_redirect(f"FCM-ping is verzonden naar {device.device_label}.")


async def handle_status_remove_device(request: web.Request) -> web.Response:
    _require_ops_auth(request)
    try:
        device = await _service(request.app).remove_device(request.match_info["device_id"])
    except Exception as exc:
        raise _status_redirect(error=str(exc))
    raise _status_redirect(f"{device.device_label} is verwijderd.")


async def handle_mock_login_page(request: web.Request) -> web.Response:
    return web.Response(
        text=_render_mock_login_page(request.app["config"].public_base_url, request.query.get("mode", "basic")),
        content_type="text/html",
    )


async def handle_mock_login_submit(request: web.Request) -> web.Response:
    form = await request.post()
    username = str(form.get("username", "demo")).strip() or "demo"
    mode = request.query.get("mode", "basic")
    if mode == "sms":
        return web.Response(
            text=_render_mock_challenge_page(username=username, error=None),
            content_type="text/html",
        )
    raise web.HTTPSeeOther(location=f"/sandbox/hasmoves/rooster?{urlencode({'user': username, 'mode': mode})}")


async def handle_mock_challenge_submit(request: web.Request) -> web.Response:
    form = await request.post()
    username = str(form.get("username", "demo")).strip() or "demo"
    code = str(form.get("code", "")).strip()
    if code != MOCK_SMS_CODE:
        return web.Response(
            text=_render_mock_challenge_page(
                username=username,
                error=f"Gebruik voor deze test de mock code {MOCK_SMS_CODE}.",
            ),
            content_type="text/html",
            status=400,
        )
    raise web.HTTPSeeOther(location=f"/sandbox/hasmoves/rooster?{urlencode({'user': username, 'mode': 'sms'})}")


async def handle_mock_rooster_page(request: web.Request) -> web.Response:
    user = request.query.get("user", "demo")
    mode = request.query.get("mode", "basic")
    roster_rows = [
        ("26-05-2026", "08:00", "16:00", f"Mock vroege dienst voor {user}"),
        ("27-05-2026", "10:00", "18:30", "Mock late dienst"),
        ("29-05-2026", "12:00", "20:00", "Mock weekenddienst"),
    ]
    rows = "".join(
        f"<tr><td>{date}</td><td>{start}</td><td>{end}</td><td>{html.escape(description)}</td></tr>"
        for date, start, end, description in roster_rows
    )
    body = f"""
<!doctype html>
<html lang="nl">
<head>
  <meta charset="utf-8">
  <title>Mock HasMoves Rooster</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 2rem; background: #f6f8fb; color: #1f2937; }}
    section {{ background: white; border-radius: 12px; padding: 1rem 1.25rem; box-shadow: 0 8px 24px rgba(15, 23, 42, 0.08); }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ text-align: left; padding: 0.5rem; border-bottom: 1px solid #e5e7eb; }}
  </style>
</head>
<body>
  <section>
    <h1>Mock HasMoves Rooster</h1>
    <p>Deze pagina is bedoeld voor backend-loopback tests. Inlogmodus: {html.escape(mode)}.</p>
    <table>
      <thead><tr><th>Datum</th><th>Begin</th><th>Einde</th><th>Omschrijving</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </section>
</body>
</html>
"""
    return web.Response(text=body, content_type="text/html")


async def handle_status_live(request: web.Request) -> web.StreamResponse:
    _require_ops_auth(request)
    service = _service(request.app)
    websocket = web.WebSocketResponse(heartbeat=20.0)
    await websocket.prepare(request)

    version = service.live_version()
    await websocket.send_json(service.operator_status_payload())

    try:
        while True:
            try:
                version = await service.wait_for_live_update(version, timeout_seconds=25)
                await websocket.send_json(service.operator_status_payload())
            except asyncio.TimeoutError:
                if websocket.closed:
                    break
                await websocket.ping()
    except ConnectionResetError:
        pass
    finally:
        if not websocket.closed:
            await websocket.close()

    return websocket


async def handle_mobile_config(request: web.Request) -> web.Response:
    return web.json_response(_service(request.app).mobile_config_payload())


async def handle_mobile_status(request: web.Request) -> web.Response:
    auth_token = _require_mobile_auth(request)
    return web.json_response(_service(request.app).mobile_status_payload(auth_token))


async def handle_mobile_live(request: web.Request) -> web.StreamResponse:
    auth_token = _require_mobile_auth(request)
    service = _service(request.app)
    websocket = web.WebSocketResponse(heartbeat=20.0)
    await websocket.prepare(request)

    device = await service.register_mobile_live_connection(auth_token)
    version = service.live_version()
    await websocket.send_json(service.mobile_status_payload(auth_token))

    try:
        while True:
            try:
                version = await service.wait_for_live_update(version, timeout_seconds=25)
                await websocket.send_json(service.mobile_status_payload(auth_token))
            except asyncio.TimeoutError:
                if websocket.closed:
                    break
                await websocket.ping()
    except ConnectionResetError:
        pass
    finally:
        await service.unregister_mobile_live_connection(device.device_id)
        if not websocket.closed:
            await websocket.close()

    return websocket


async def handle_mobile_setup(request: web.Request) -> web.Response:
    service = _service(request.app)
    payload = await request.json()
    auth_token = _extract_bearer_token(request)
    setup_secret = payload.get("setup_secret") or request.headers.get("X-Setup-Secret")
    portal_id = str(payload.get("portal_id", "")).strip() or None
    selected_portal = service.portal_by_id(portal_id)
    resolved_login_url = selected_portal.login_url if selected_portal is not None else str(payload.get("login_url", ""))

    if service.has_device():
        if not (service.mobile_token_is_valid(auth_token) or service.setup_secret_is_valid(setup_secret)):
            raise web.HTTPUnauthorized(text="Ongeldige app-verificatie of installatiecode.")
    elif not service.setup_secret_is_valid(setup_secret):
        raise web.HTTPUnauthorized(text="Ongeldige installatiecode.")

    required_fields = ["username", "password", "fcm_token"]
    missing = [field for field in required_fields if not str(payload.get(field, "")).strip()]
    if not str(resolved_login_url).strip():
        missing.append("login_url of portal_id")
    if missing:
        raise web.HTTPBadRequest(text=f"Ontbrekende velden: {', '.join(missing)}")

    result = await service.upsert_mobile_setup(
        login_url=str(resolved_login_url),
        portal_id=selected_portal.portal_id if selected_portal is not None else portal_id,
        username=str(payload.get("username", "")),
        password=str(payload.get("password", "")),
        fcm_token=str(payload.get("fcm_token", "")),
        device_label=str(payload.get("device_label", "Android-telefoon")),
        rotate_api_token=bool(payload.get("rotate_api_token", False)),
        auth_token=auth_token,
    )
    return web.json_response(result, status=200)


async def handle_fcm_token(request: web.Request) -> web.Response:
    auth_token = _require_mobile_auth(request)
    payload = await request.json()
    token = str(payload.get("fcm_token", "")).strip()
    if not token:
        raise web.HTTPBadRequest(text="Het FCM-token ontbreekt.")
    await _service(request.app).update_fcm_token_for_device(auth_token, token, payload.get("device_label"))
    return web.json_response({"message": "Het FCM-token is bijgewerkt."})


async def handle_mobile_device_remove(request: web.Request) -> web.Response:
    auth_token = _require_mobile_auth(request)
    device = await _service(request.app).remove_device_for_mobile_token(auth_token)
    return web.json_response(
        {
            "message": f"{device.device_label} is ontkoppeld.",
            "device_id": device.device_id,
        }
    )


async def handle_sms_code(request: web.Request) -> web.Response:
    auth_token = _require_mobile_auth(request)
    payload = await request.json()
    code = str(payload.get("code", "")).strip()
    sender = str(payload.get("sender", "")).strip()
    if not code:
        raise web.HTTPBadRequest(text="De SMS-code ontbreekt.")
    await _service(request.app).submit_sms_code(
        auth_token,
        request.match_info["challenge_id"],
        code,
        sender,
    )
    return web.json_response({"message": "De SMS-code is ontvangen."})


async def handle_refresh(request: web.Request) -> web.Response:
    _require_ops_auth(request)
    service = _service(request.app)
    await service.trigger_refresh(reason="manual", wait=False)
    return web.json_response({"message": "De handmatige synchronisatie is gestart.", "status": service.operator_status_payload()})


async def handle_admin_status(request: web.Request) -> web.Response:
    _require_ops_auth(request)
    return web.json_response(_service(request.app).operator_status_payload())


async def handle_admin_mock_sms(request: web.Request) -> web.Response:
    _require_ops_auth(request)
    try:
        await _service(request.app).submit_mock_sms_code(code=MOCK_SMS_CODE)
    except RuntimeError as exc:
        raise web.HTTPBadRequest(text=str(exc))
    return web.json_response(
        {
            "message": f"Mock OTP {MOCK_SMS_CODE} is ingestuurd.",
            "status": _service(request.app).operator_status_payload(),
        }
    )


async def handle_admin_activate_device(request: web.Request) -> web.Response:
    _require_ops_auth(request)
    try:
        device = await _service(request.app).activate_device(request.match_info["device_id"])
    except RuntimeError as exc:
        raise web.HTTPBadRequest(text=str(exc))
    return web.json_response(
        {
            "message": f"{device.device_label} is nu het actieve apparaat.",
            "status": _service(request.app).operator_status_payload(),
        }
    )


async def handle_admin_ping_device(request: web.Request) -> web.Response:
    _require_ops_auth(request)
    service = _service(request.app)
    device = service.device_by_id(request.match_info["device_id"])
    if device is None:
        raise web.HTTPBadRequest(text="Het gevraagde apparaat bestaat niet meer.")

    message = f"Ping vanaf de statuspagina voor {device.device_label} om {datetime.now(UTC).strftime('%H:%M:%S')} UTC."
    try:
        await service.send_test_notification(message, device_id=device.device_id)
    except RuntimeError as exc:
        raise web.HTTPBadRequest(text=str(exc))
    return web.json_response(
        {
            "message": f"FCM-ping is verzonden naar {device.device_label}.",
            "status": service.operator_status_payload(),
        }
    )


async def handle_admin_remove_device(request: web.Request) -> web.Response:
    _require_ops_auth(request)
    try:
        device = await _service(request.app).remove_device(request.match_info["device_id"])
    except RuntimeError as exc:
        raise web.HTTPBadRequest(text=str(exc))
    return web.json_response(
        {
            "message": f"{device.device_label} is verwijderd.",
            "device_id": device.device_id,
            "status": _service(request.app).operator_status_payload(),
        }
    )


async def handle_admin_portal_upsert(request: web.Request) -> web.Response:
    _require_ops_auth(request)
    payload = await _read_request_payload(request)
    try:
        portal = await _service(request.app).upsert_portal(
            portal_id=str(payload.get("portal_id", "")).strip() or None,
            name=str(payload.get("name", "")),
            login_url=str(payload.get("login_url", "")),
            logo_url=str(payload.get("logo_url", "")),
        )
    except RuntimeError as exc:
        raise web.HTTPBadRequest(text=str(exc))

    return web.json_response(
        {
            "message": f"Portal {portal.name} is opgeslagen.",
            "portal": portal.to_dict(),
            "status": _service(request.app).operator_status_payload(),
        }
    )


async def handle_admin_portal_remove(request: web.Request) -> web.Response:
    _require_ops_auth(request)
    try:
        portal = await _service(request.app).remove_portal(request.match_info["portal_id"])
    except RuntimeError as exc:
        raise web.HTTPBadRequest(text=str(exc))

    return web.json_response(
        {
            "message": f"Portal {portal.name} is verwijderd.",
            "portal_id": portal.portal_id,
            "status": _service(request.app).operator_status_payload(),
        }
    )


async def handle_admin_fcm_status(request: web.Request) -> web.Response:
    service = _service(request.app)
    token = request.headers.get("X-Admin-Token") or request.query.get("token")
    if not service.admin_token_is_valid(token):
        raise web.HTTPUnauthorized(text="Ongeldig admin-token.")

    diagnostics = _fcm_diagnostics(request.app)
    diagnostics["public_base_url"] = request.app["config"].public_base_url
    return web.json_response(diagnostics)


async def handle_admin_fcm_test(request: web.Request) -> web.Response:
    service = _service(request.app)
    token = request.headers.get("X-Admin-Token") or request.query.get("token")
    if not service.admin_token_is_valid(token):
        raise web.HTTPUnauthorized(text="Ongeldig admin-token.")

    payload = await request.json() if request.can_read_body else {}
    message = str(payload.get("message", "Testmelding vanaf de backend."))
    await service.send_test_notification(message, device_id=str(payload.get("device_id", "")).strip() or None)

    diagnostics = FcmPushClient(request.app["config"]).diagnostics()
    return web.json_response(
        {
            "message": "De FCM-testmelding is verzonden.",
            "fcm": diagnostics,
        }
    )


def _service(app: web.Application) -> BackendService:
    return app["service"]


def _device_summary(service: BackendService) -> dict[str, Any]:
    active_device = service.active_device()
    return {
        "device_registered": service.has_device(),
        "device_has_token": bool(active_device and active_device.fcm_token),
        "device_count": service.device_count(),
        "active_device_label": active_device.device_label if active_device else "",
    }


def _fcm_diagnostics(app: web.Application) -> dict[str, Any]:
    service = _service(app)
    diagnostics = FcmPushClient(app["config"]).diagnostics()
    diagnostics.update(_device_summary(service))
    return diagnostics


def _ops_is_authorized(request: web.Request) -> bool:
    service = _service(request.app)
    token = request.headers.get("X-Admin-Token") or request.query.get("token")
    if service.admin_token_is_valid(token):
        return True
    if not request.app["config"].admin_token:
        return True
    cookie_value = request.cookies.get(OPS_SESSION_COOKIE)
    return bool(cookie_value and hmac.compare_digest(cookie_value, _ops_session_value(request.app["config"])))


def _ops_session_value(config: AppConfig) -> str:
    return hashlib.sha256(f"ons-status-session:{config.admin_token}".encode("utf-8")).hexdigest()


def _maybe_set_ops_session_cookie(request: web.Request, response: web.StreamResponse, *, authorized: bool) -> None:
    if not authorized:
        return

    token = request.query.get("token")
    if not _service(request.app).admin_token_is_valid(token):
        return

    response.set_cookie(
        OPS_SESSION_COOKIE,
        _ops_session_value(request.app["config"]),
        secure=request.url.scheme == "https",
        httponly=True,
        samesite="Strict",
        path="/",
    )


def _require_ops_auth(request: web.Request) -> None:
    if not _ops_is_authorized(request):
        raise web.HTTPUnauthorized(text="Ongeldig admin-token.")


def _status_redirect(message: str | None = None, error: str | None = None) -> web.HTTPSeeOther:
    query: dict[str, str] = {}
    if message:
        query["message"] = message
    if error:
        query["error"] = error
    location = "/status"
    if query:
        location = f"{location}?{urlencode(query)}"
    return web.HTTPSeeOther(location=location)


def _render_status_page(
    app: web.Application,
    *,
    authorized: bool,
    message: str | None,
    error: str | None,
    status: int,
) -> web.Response:
    config = app["config"]
    service = _service(app)
    flash = ""
    if message:
        flash += f'<p class="flash flash-ok">{html.escape(message)}</p>'
    if error:
        flash += f'<p class="flash flash-error">{html.escape(error)}</p>'

    if not authorized:
        body = f"""
<!doctype html>
<html lang="nl">
<head>
  <meta charset="utf-8">
  <title>ONS Rooster Operatorstatus</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 2rem; background: #f6f8fb; color: #1f2937; }}
    section {{ max-width: 32rem; background: white; border-radius: 12px; padding: 1.25rem; box-shadow: 0 8px 24px rgba(15, 23, 42, 0.08); }}
    form {{ display: grid; gap: 0.8rem; }}
    label {{ display: grid; gap: 0.35rem; font-weight: 600; }}
    input, button {{ font: inherit; }}
    input[type="password"] {{ padding: 0.65rem 0.8rem; border: 1px solid #cbd5e1; border-radius: 10px; }}
    button {{ width: fit-content; border: 0; border-radius: 999px; padding: 0.7rem 1.1rem; background: #0f766e; color: white; cursor: pointer; }}
    .flash {{ border-radius: 10px; padding: 0.85rem 1rem; font-weight: 600; margin-bottom: 1rem; }}
    .flash-error {{ background: #fee2e2; color: #991b1b; }}
  </style>
</head>
<body>
  <section>
    <h1>ONS Rooster Operatorstatus</h1>
    <p>Gebruik hier het admin-token als wachtwoord om de statuspagina en FCM-acties te openen.</p>
    {flash}
    <form method="post" action="/status/login">
      <label>
        <span>Admin-token</span>
        <input type="password" name="admin_token" autocomplete="current-password" required>
      </label>
      <button type="submit">Open statuspagina</button>
    </form>
  </section>
</body>
</html>
"""
        return web.Response(text=body, content_type="text/html", status=status)

    status_snapshot = service.operator_status_payload()
    status_payload = status_snapshot["status"]
    diagnostics = _fcm_diagnostics(app)
    devices = status_snapshot["devices"]
    portals = status_snapshot["portals"]
    mock_basic_url = f"{config.public_base_url}/sandbox/hasmoves/login"
    mock_sms_url = f"{config.public_base_url}/sandbox/hasmoves/login?mode=sms"
    challenge_controls = "hidden"
    if status_payload["sync"]["current_challenge_id"]:
        challenge_controls = ""

    device_rows = "".join(
        f"""
                <tr data-device-id="{html.escape(device['device_id'])}" data-device-label="{html.escape(device['device_label'])}">
          <td>{html.escape(device['device_label'])}</td>
          <td><code>{html.escape(device['device_id'])}</code></td>
          <td>{html.escape(device['fcm_token_suffix'] or '-')}</td>
          <td>{html.escape(device['last_seen_at'] or '-')}</td>
                    <td>{'Verbonden' if device['is_connected'] else 'Niet verbonden'}</td>
          <td>{'Ja' if device['is_active'] else 'Nee'}</td>
          <td>
            <div class="actions">
                            <button type="button" data-device-action="ping">FCM-ping</button>
                            <button type="button" data-device-action="activate"{' disabled' if device['is_active'] else ''}>Maak actief</button>
                            <button type="button" class="danger" data-device-action="remove">Verwijder</button>
            </div>
          </td>
        </tr>
"""
        for device in devices
    )

    portal_cards = "".join(
        f"""
                <article class="portal-card" data-portal-id="{html.escape(portal['portal_id'])}">
                    <div class="portal-card-header">
                        <div>
                            <h3>{html.escape(portal['name'])}</h3>
                            <p>{html.escape(portal['login_url'])}</p>
                        </div>
                        {f'<img src="{html.escape(portal["logo_url"])}" alt="{html.escape(portal["name"])} logo">' if portal['logo_url'] else '<div class="portal-logo-placeholder">Geen logo</div>'}
                    </div>
                    <div class="actions">
                        <button type="button" data-portal-action="edit">Wijzig</button>
                        <button type="button" class="danger" data-portal-action="remove">Verwijder</button>
                    </div>
                </article>
"""
        for portal in portals
    )

    selected_portal = next((portal for portal in portals if portal.get("is_selected")), portals[0] if portals else None)
    initial_snapshot_json = json.dumps(status_snapshot, ensure_ascii=True).replace("</", "<\\/")

    body = f"""
<!doctype html>
<html lang="nl">
<head>
  <meta charset="utf-8">
  <title>ONS Rooster Operatorstatus</title>
  <style>
        body {{ font-family: "Segoe UI", Aptos, sans-serif; margin: 2rem; background: linear-gradient(180deg, #f8fafc 0%, #eef4f5 100%); color: #1f2937; }}
    h1, h2 {{ margin-bottom: 0.5rem; }}
        h3 {{ margin: 0 0 0.35rem; }}
        section {{ background: white; border-radius: 16px; padding: 1rem 1.25rem; margin-bottom: 1rem; box-shadow: 0 12px 32px rgba(15, 23, 42, 0.08); }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ text-align: left; padding: 0.6rem; border-bottom: 1px solid #e5e7eb; vertical-align: top; }}
        form {{ display: grid; gap: 0.85rem; }}
        label {{ display: grid; gap: 0.35rem; font-weight: 600; }}
        input {{ font: inherit; padding: 0.7rem 0.85rem; border: 1px solid #cbd5e1; border-radius: 10px; }}
    .actions {{ display: flex; gap: 0.5rem; flex-wrap: wrap; }}
    button {{ border: 0; border-radius: 999px; padding: 0.6rem 0.95rem; background: #0f766e; color: white; cursor: pointer; }}
    button.danger {{ background: #b91c1c; }}
    button[disabled] {{ opacity: 0.55; cursor: not-allowed; }}
    .flash {{ border-radius: 10px; padding: 0.85rem 1rem; font-weight: 600; margin-bottom: 1rem; }}
    .flash-ok {{ background: #dcfce7; color: #166534; }}
    .flash-error {{ background: #fee2e2; color: #991b1b; }}
    code {{ background: #eef2ff; padding: 0.1rem 0.35rem; border-radius: 4px; }}
    .toolbar {{ display: flex; gap: 0.75rem; flex-wrap: wrap; }}
        .toolbar form {{ display: inline; }}
    a {{ color: #0f766e; }}
        .hero {{ display: flex; align-items: center; justify-content: space-between; gap: 1.5rem; margin-bottom: 1rem; }}
        .hero-copy {{ display: grid; gap: 0.5rem; }}
        .hero-copy p {{ margin: 0; max-width: 48rem; color: #475569; }}
        .brand-mark {{ width: 220px; max-width: 38vw; height: auto; opacity: 0.9; }}
        .live-pill {{ display: inline-flex; align-items: center; gap: 0.5rem; width: fit-content; border-radius: 999px; padding: 0.45rem 0.8rem; background: #e2e8f0; color: #334155; font-size: 0.92rem; font-weight: 600; }}
        .live-pill::before {{ content: ""; width: 10px; height: 10px; border-radius: 999px; background: #94a3b8; }}
        .live-pill.live::before {{ background: #16a34a; }}
        .live-pill.retrying::before {{ background: #f59e0b; }}
        .overview-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 0.85rem; }}
        .overview-card {{ border-radius: 14px; background: #f8fafc; padding: 0.9rem 1rem; }}
        .overview-card strong {{ display: block; margin-bottom: 0.35rem; font-size: 0.92rem; color: #0f172a; }}
        .status-duo {{ display: flex; gap: 0.5rem; flex-wrap: wrap; }}
        .status-chip {{ display: inline-flex; align-items: center; border-radius: 999px; padding: 0.28rem 0.7rem; font-size: 0.9rem; font-weight: 600; background: #e2e8f0; color: #0f172a; }}
        .status-chip.online {{ background: #dcfce7; color: #166534; }}
        .status-chip.paired {{ background: #dbeafe; color: #1d4ed8; }}
        .section-note {{ margin: 0 0 0.85rem; color: #475569; max-width: 52rem; }}
        .portal-manager {{ display: grid; grid-template-columns: minmax(280px, 360px) minmax(0, 1fr); gap: 1rem; align-items: start; }}
        .portal-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 0.85rem; }}
        .portal-card {{ border: 1px solid #e2e8f0; border-radius: 16px; padding: 1rem; background: #fcfdfd; }}
        .portal-card-header {{ display: flex; justify-content: space-between; gap: 1rem; align-items: flex-start; margin-bottom: 0.85rem; }}
        .portal-card-header p {{ margin: 0; word-break: break-word; color: #475569; font-size: 0.92rem; }}
        .portal-card img, .portal-logo-placeholder {{ width: 64px; height: 64px; border-radius: 14px; background: #f1f5f9; object-fit: contain; padding: 0.35rem; flex: 0 0 auto; }}
        .portal-logo-placeholder {{ display: inline-flex; align-items: center; justify-content: center; font-size: 0.75rem; color: #64748b; text-align: center; }}
        .portal-editor {{ border: 1px solid #d8e5ea; border-radius: 16px; background: #f8fbfc; padding: 1rem; }}
        .portal-editor h3 {{ margin: 0 0 0.75rem; }}
        .portal-form-grid {{ display: grid; gap: 0.85rem; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); }}
        .portal-form-actions {{ display: flex; gap: 0.75rem; flex-wrap: wrap; }}
        .challenge-note {{ margin: 0; color: #475569; }}
        .console-shell {{ background: #0f172a; color: #e2e8f0; border-radius: 16px; padding: 1rem; font: 0.92rem/1.55 Consolas, "Courier New", monospace; max-height: 420px; overflow: auto; margin-bottom: 1rem; }}
        .console-line {{ padding: 0.2rem 0; border-bottom: 1px solid rgba(148, 163, 184, 0.12); }}
        .console-line:last-child {{ border-bottom: 0; }}
        .console-meta {{ color: #93c5fd; margin-right: 0.5rem; }}
        .trace-table a {{ color: #0f766e; }}
        @media (max-width: 900px) {{ .portal-manager {{ grid-template-columns: 1fr; }} }}
        @media (max-width: 720px) {{ .hero {{ flex-direction: column-reverse; align-items: flex-start; }} .brand-mark {{ max-width: 72vw; }} }}
  </style>
</head>
<body>
    <div class="hero">
        <div class="hero-copy">
            <img class="brand-mark" src="{ONS_BRAND_LOGO_DATA_URI}" alt="ONS logo">
            <h1>ONS Rooster Operatorstatus</h1>
            <p>De pagina luistert live mee met backendwijzigingen. Nieuwe koppelingen, verwijderingen, statusfases en OTP-verzoeken verschijnen automatisch zonder handmatige refresh.</p>
            <span id="live-indicator" class="live-pill">Operatorpagina verbinden...</span>
        </div>
    </div>
    <div id="flash-host">{flash}</div>
  <section>
    <div class="toolbar">
            <button type="button" id="btn-refresh-sync">Start sync nu</button>
      <form method="post" action="/status/logout"><button type="submit">Uitloggen</button></form>
      <a href="/install">Firebase-installatie</a>
      <a href="/debug?token={html.escape(config.debug_token)}">Debugpagina</a>
    </div>
  </section>
  <section>
    <h2>Overzicht</h2>
        <div id="overview-grid" class="overview-grid">
            <div class="overview-card"><strong>Backend-URL</strong><span>{html.escape(status_payload['public_base_url'])}</span></div>
            <div class="overview-card"><strong>Inlogpagina</strong><span>{html.escape(status_payload['login_url'])}</span></div>
            <div class="overview-card"><strong>Appstatus</strong><div class="status-duo"><span class="status-chip {'online' if devices and any(device['is_connected'] for device in devices) else ''}">{'Verbonden' if devices and any(device['is_connected'] for device in devices) else 'Geen live appverbinding'}</span><span class="status-chip {'paired' if status_payload['device_registered'] else ''}">{'Gekoppeld' if status_payload['device_registered'] else 'Niet gekoppeld'}</span></div></div>
            <div class="overview-card"><strong>Actief apparaat</strong><span>{html.escape(status_payload['active_device_label'] or '-')}</span></div>
            <div class="overview-card"><strong>Aantal apparaten</strong><span>{status_payload['device_count']}</span></div>
            <div class="overview-card"><strong>FCM geconfigureerd</strong><span>{diagnostics['configured']}</span></div>
            <div class="overview-card"><strong>Laatste status</strong><span>{html.escape(str(status_payload['sync']['last_message'] or '-'))}</span></div>
            <div class="overview-card"><strong>Laatste fout</strong><span>{html.escape(str(status_payload['sync']['last_error'] or '-'))}</span></div>
            <div class="overview-card"><strong>Huidige fase</strong><span>{html.escape(str(status_payload['sync']['current_phase'] or '-'))}</span></div>
            <div class="overview-card"><strong>Laatste succesvolle login</strong><span>{html.escape(str(status_payload['sync']['last_success_at'] or '-'))}</span></div>
        </div>
  </section>
  <section>
    <h2>Gekoppelde apparaten</h2>
        <p class="section-note">Het actieve apparaat ontvangt de eerstvolgende verificatievraag wanneer meerdere gekoppelde apparaten beschikbaar zijn.</p>
    <table>
      <thead>
                <tr><th>Label</th><th>Device-ID</th><th>FCM suffix</th><th>Laatst gezien</th><th>Verbonden</th><th>Actief</th><th>Acties</th></tr>
      </thead>
            <tbody id="device-table-body">{device_rows or '<tr><td colspan="7">Nog geen apparaten gekoppeld.</td></tr>'}</tbody>
    </table>
  </section>
    <section id="challenge-section" {challenge_controls}>
        <h2>Actieve testuitdaging</h2>
        <p id="challenge-id-line"><strong>Challenge-ID:</strong> {html.escape(status_payload['sync']['current_challenge_id'] or '-')}</p>
        <p class="challenge-note">Gebruik de mock code <code>{MOCK_SMS_CODE}</code> om een sandbox-OTP in te vullen zonder echte SMS.</p>
        <div class="actions"><button type="button" id="btn-mock-sms">Vul mock OTP {MOCK_SMS_CODE} in</button></div>
    </section>
    <section>
        <h2>Authenticatieconsole</h2>
        <p class="section-note">Deze live console toont iedere backend-stap tijdens de aanmeldflow. HTML-snapshots van individuele stappen zijn direct te openen.</p>
        <div id="auth-console" class="console-shell"></div>
        <table class="trace-table">
            <thead>
                <tr><th>Tijd</th><th>Fase</th><th>Stap</th><th>URL</th><th>Snapshot</th></tr>
            </thead>
            <tbody id="auth-trace-body"><tr><td colspan="5">Nog geen authenticatiestappen vastgelegd.</td></tr></tbody>
        </table>
    </section>
    <section>
        <h2>Portalen beheren</h2>
        <p class="section-note">Voeg een nieuw portaal toe of kies <strong>Wijzig</strong> bij een bestaand portaal om naam, login-URL of logo aan te passen. Verwijderen werkt direct op de pagina.</p>
        <div class="portal-manager">
            <form id="portal-form" class="portal-editor" action="/api/v1/admin/portals" method="post">
                <h3 id="portal-form-heading">{'Portaal wijzigen' if selected_portal else 'Nieuw portaal toevoegen'}</h3>
                <input type="hidden" id="portal_id" name="portal_id" value="{html.escape(selected_portal['portal_id'] if selected_portal else '')}">
                <div class="portal-form-grid">
                    <label>
                        <span>Naam</span>
                        <input type="text" id="portal_name" name="name" value="{html.escape(selected_portal['name'] if selected_portal else '')}" required>
                    </label>
                    <label>
                        <span>Login-URL</span>
                        <input type="url" id="portal_login_url" name="login_url" value="{html.escape(selected_portal['login_url'] if selected_portal else '')}" required>
                    </label>
                    <label>
                        <span>Logo-URL</span>
                        <input type="url" id="portal_logo_url" name="logo_url" value="{html.escape(selected_portal['logo_url'] if selected_portal else '')}">
                    </label>
                </div>
                <div class="portal-form-actions">
                    <button type="submit">Portaal opslaan</button>
                    <button type="button" id="btn-portal-reset">Nieuw portaal</button>
                </div>
            </form>
            <div id="portal-list" class="portal-grid">{portal_cards}</div>
        </div>
    </section>
  <section>
    <h2>Mock HasMoves testflow</h2>
    <p>Gebruik deze URL als ONS-inlog-URL in de app of in backend-tests om de live HasMoves-site te omzeilen.</p>
    <p><strong>Basisflow:</strong> <a href="{html.escape(mock_basic_url)}">{html.escape(mock_basic_url)}</a></p>
    <p><strong>SMS-flow:</strong> <a href="{html.escape(mock_sms_url)}">{html.escape(mock_sms_url)}</a></p>
    <p>Voor de SMS-flow accepteert de mock challenge code <code>{MOCK_SMS_CODE}</code>. Je kunt die via de knop hierboven in de actieve uitdaging injecteren.</p>
  </section>
    <script id="initial-status-json" type="application/json">{initial_snapshot_json}</script>
    <script>
        const initialStatus = JSON.parse(document.getElementById('initial-status-json').textContent);
        const liveIndicator = document.getElementById('live-indicator');
        const flashHost = document.getElementById('flash-host');
        const overviewGrid = document.getElementById('overview-grid');
        const deviceTableBody = document.getElementById('device-table-body');
        const challengeSection = document.getElementById('challenge-section');
        const challengeIdLine = document.getElementById('challenge-id-line');
        const portalList = document.getElementById('portal-list');
        const authConsole = document.getElementById('auth-console');
        const authTraceBody = document.getElementById('auth-trace-body');
        const portalForm = document.getElementById('portal-form');
        const portalFormHeading = document.getElementById('portal-form-heading');
        const portalIdInput = document.getElementById('portal_id');
        const portalNameInput = document.getElementById('portal_name');
        const portalLoginUrlInput = document.getElementById('portal_login_url');
        const portalLogoUrlInput = document.getElementById('portal_logo_url');
        const liveUrl = `${{window.location.protocol === 'https:' ? 'wss' : 'ws'}}://${{window.location.host}}/status/live`;
        let socket = null;
        let reconnectHandle = null;
        let statusSnapshot = initialStatus;

        function escapeHtml(value) {{
            const div = document.createElement('div');
            div.textContent = value ?? '';
            return div.innerHTML;
        }}

        function formatTimestamp(value) {{
            if (!value) return '-';
            const parsed = new Date(value);
            if (Number.isNaN(parsed.getTime())) return value;
            return parsed.toLocaleString('nl-NL');
        }}

        function setFlash(kind, text) {{
            if (!text) return;
            flashHost.innerHTML = `<p class="flash ${{kind === 'error' ? 'flash-error' : 'flash-ok'}}">${{escapeHtml(text)}}</p>`;
        }}

        function clearPortalForm() {{
            portalIdInput.value = '';
            portalNameInput.value = '';
            portalLoginUrlInput.value = '';
            portalLogoUrlInput.value = '';
            portalFormHeading.textContent = 'Nieuw portaal toevoegen';
        }}

        function fillPortalForm(portal) {{
            portalIdInput.value = portal.portal_id || '';
            portalNameInput.value = portal.name || '';
            portalLoginUrlInput.value = portal.login_url || '';
            portalLogoUrlInput.value = portal.logo_url || '';
            portalFormHeading.textContent = portal.name ? `Portaal wijzigen: ${{portal.name}}` : 'Portaal wijzigen';
        }}

        function syncPortalForm(snapshot) {{
            if (!portalIdInput.value) {{
                portalFormHeading.textContent = 'Nieuw portaal toevoegen';
                return;
            }}

            const currentPortal = snapshot.portals.find((portal) => portal.portal_id === portalIdInput.value);
            if (currentPortal) {{
                fillPortalForm(currentPortal);
                return;
            }}

            clearPortalForm();
        }}

        function renderOverview(snapshot) {{
            const status = snapshot.status;
            const anyConnected = snapshot.devices.some((device) => device.is_connected);
            overviewGrid.innerHTML = `
                <div class="overview-card"><strong>Backend-URL</strong><span>${{escapeHtml(status.public_base_url)}}</span></div>
                <div class="overview-card"><strong>Inlogpagina</strong><span>${{escapeHtml(status.login_url)}}</span></div>
                <div class="overview-card"><strong>Appstatus</strong><div class="status-duo"><span class="status-chip ${{anyConnected ? 'online' : ''}}">${{anyConnected ? 'Verbonden' : 'Geen live appverbinding'}}</span><span class="status-chip ${{status.device_registered ? 'paired' : ''}}">${{status.device_registered ? 'Gekoppeld' : 'Niet gekoppeld'}}</span></div></div>
                <div class="overview-card"><strong>Actief apparaat</strong><span>${{escapeHtml(status.active_device_label || '-')}}</span></div>
                <div class="overview-card"><strong>Aantal apparaten</strong><span>${{snapshot.devices.length}}</span></div>
                <div class="overview-card"><strong>FCM geconfigureerd</strong><span>${{snapshot.fcm_configured ? 'Ja' : 'Nee'}}</span></div>
                <div class="overview-card"><strong>Laatste status</strong><span>${{escapeHtml(status.sync.last_message || '-')}}</span></div>
                <div class="overview-card"><strong>Laatste fout</strong><span>${{escapeHtml(status.sync.last_error || '-')}}</span></div>
                <div class="overview-card"><strong>Huidige fase</strong><span>${{escapeHtml(status.sync.current_phase || '-')}}</span></div>
                <div class="overview-card"><strong>Laatste succesvolle login</strong><span>${{escapeHtml(formatTimestamp(status.sync.last_success_at))}}</span></div>`;
        }}

        function renderDevices(snapshot) {{
            if (!snapshot.devices.length) {{
                deviceTableBody.innerHTML = '<tr><td colspan="7">Nog geen apparaten gekoppeld.</td></tr>';
                return;
            }}

            deviceTableBody.innerHTML = snapshot.devices.map((device) => `
                <tr data-device-id="${{escapeHtml(device.device_id)}}" data-device-label="${{escapeHtml(device.device_label)}}">
                    <td>${{escapeHtml(device.device_label)}}</td>
                    <td><code>${{escapeHtml(device.device_id)}}</code></td>
                    <td>${{escapeHtml(device.fcm_token_suffix || '-')}}</td>
                    <td>${{escapeHtml(formatTimestamp(device.last_seen_at))}}</td>
                    <td>${{device.is_connected ? 'Verbonden' : 'Niet verbonden'}}</td>
                    <td>${{device.is_active ? 'Ja' : 'Nee'}}</td>
                    <td>
                        <div class="actions">
                            <button type="button" data-device-action="ping">FCM-ping</button>
                            <button type="button" data-device-action="activate" ${{device.is_active ? 'disabled' : ''}}>Maak actief</button>
                            <button type="button" class="danger" data-device-action="remove">Verwijder</button>
                        </div>
                    </td>
                </tr>`).join('');
        }}

        function renderChallenge(snapshot) {{
            const challengeId = snapshot.status.sync.current_challenge_id;
            if (!challengeId) {{
                challengeSection.hidden = true;
                challengeIdLine.innerHTML = '<strong>Challenge-ID:</strong> -';
                return;
            }}

            challengeSection.hidden = false;
            challengeIdLine.innerHTML = `<strong>Challenge-ID:</strong> ${{escapeHtml(challengeId)}}`;
        }}

        function renderPortals(snapshot) {{
            if (!snapshot.portals.length) {{
                portalList.innerHTML = '<p>Er zijn nog geen portalen geconfigureerd.</p>';
                return;
            }}

            portalList.innerHTML = snapshot.portals.map((portal) => `
                <article class="portal-card" data-portal-id="${{escapeHtml(portal.portal_id)}}">
                    <div class="portal-card-header">
                        <div>
                            <h3>${{escapeHtml(portal.name)}}</h3>
                            <p>${{escapeHtml(portal.login_url)}}</p>
                        </div>
                        ${{portal.logo_url ? `<img src="${{escapeHtml(portal.logo_url)}}" alt="${{escapeHtml(portal.name)}} logo">` : '<div class="portal-logo-placeholder">Geen logo</div>'}}
                    </div>
                    <div class="actions">
                        <button type="button" data-portal-action="edit">Wijzig</button>
                        <button type="button" class="danger" data-portal-action="remove">Verwijder</button>
                    </div>
                </article>`).join('');
        }}

        function renderAuthTrace(snapshot) {{
            const entries = snapshot.status.sync.auth_trace || [];
            if (!entries.length) {{
                authConsole.innerHTML = '<div class="console-line">Nog geen authenticatiestappen vastgelegd.</div>';
                authTraceBody.innerHTML = '<tr><td colspan="5">Nog geen authenticatiestappen vastgelegd.</td></tr>';
                return;
            }}

            authConsole.innerHTML = entries.map((entry) => `
                <div class="console-line">
                    <span class="console-meta">[${{escapeHtml(formatTimestamp(entry.created_at))}}] ${{escapeHtml(entry.phase || '-')}}</span>
                    <strong>${{escapeHtml(entry.label || '-')}}</strong>
                    <span> - ${{escapeHtml(entry.message || '-')}}</span>
                </div>`).join('');
            authConsole.scrollTop = authConsole.scrollHeight;

            authTraceBody.innerHTML = entries.map((entry) => `
                <tr>
                    <td>${{escapeHtml(formatTimestamp(entry.created_at))}}</td>
                    <td>${{escapeHtml(entry.phase || '-')}}</td>
                    <td>${{escapeHtml(entry.label || '-')}}</td>
                    <td>${{entry.url ? `<a href="${{escapeHtml(entry.url)}}" target="_blank" rel="noreferrer">${{escapeHtml(entry.url)}}</a>` : '-'}}</td>
                    <td>${{entry.snapshot_path ? `<a href="${{escapeHtml(entry.snapshot_path)}}" target="_blank" rel="noreferrer">Bekijk HTML</a>` : '-'}}</td>
                </tr>`).join('');
        }}

        function render(snapshot) {{
            statusSnapshot = snapshot;
            renderOverview(snapshot);
            renderDevices(snapshot);
            renderChallenge(snapshot);
            renderAuthTrace(snapshot);
            renderPortals(snapshot);
            syncPortalForm(snapshot);
        }}

        function applyStatusPayload(response) {{
            if (response?.status) {{
                render(response.status);
            }}
        }}

        async function callJson(url, options = {{}}) {{
            const response = await fetch(url, {{
                credentials: 'same-origin',
                headers: {{ 'Accept': 'application/json', ...(options.body ? {{ 'Content-Type': 'application/json' }} : {{}}) }},
                ...options,
            }});
            const text = await response.text();
            let payload = {{}};
            if (text) {{
                try {{
                    payload = JSON.parse(text);
                }} catch (_error) {{
                    payload = {{ message: text }};
                }}
            }}
            if (!response.ok) {{
                throw new Error(payload.message || text || 'Er ging iets mis.');
            }}
            return payload;
        }}

        async function connectLive() {{
            if (socket && (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING)) {{
                return;
            }}

            liveIndicator.textContent = 'Operatorpagina verbinden...';
            liveIndicator.className = 'live-pill retrying';
            socket = new WebSocket(liveUrl);
            socket.addEventListener('open', () => {{
                liveIndicator.textContent = 'Operatorpagina live';
                liveIndicator.className = 'live-pill live';
            }});
            socket.addEventListener('message', (event) => {{
                render(JSON.parse(event.data));
            }});
            socket.addEventListener('close', () => {{
                liveIndicator.textContent = 'Operatorpagina tijdelijk onderbroken, opnieuw verbinden...';
                liveIndicator.className = 'live-pill retrying';
                reconnectHandle = window.setTimeout(connectLive, 2000);
            }});
            socket.addEventListener('error', () => {{
                socket.close();
            }});
        }}

        document.getElementById('btn-refresh-sync').addEventListener('click', async () => {{
            try {{
                const response = await callJson('/api/v1/admin/refresh', {{ method: 'POST' }});
                applyStatusPayload(response);
                setFlash('ok', response.message || 'Synchronisatie gestart.');
            }} catch (error) {{
                setFlash('error', error.message);
            }}
        }});

        document.getElementById('btn-mock-sms').addEventListener('click', async () => {{
            try {{
                const response = await callJson('/api/v1/admin/challenges/mock-sms', {{ method: 'POST' }});
                applyStatusPayload(response);
                setFlash('ok', response.message || 'Mock OTP ingestuurd.');
            }} catch (error) {{
                setFlash('error', error.message);
            }}
        }});

        deviceTableBody.addEventListener('click', async (event) => {{
            const button = event.target.closest('button[data-device-action]');
            if (!button) return;

            const row = button.closest('tr[data-device-id]');
            const deviceId = row?.dataset.deviceId;
            const deviceLabel = row?.dataset.deviceLabel || 'dit apparaat';
            if (!deviceId) return;

            const action = button.dataset.deviceAction;
            const endpoints = {{
                ping: ['/api/v1/admin/devices/' + deviceId + '/ping', 'POST'],
                activate: ['/api/v1/admin/devices/' + deviceId + '/activate', 'POST'],
                remove: ['/api/v1/admin/devices/' + deviceId, 'DELETE'],
            }};
            const [url, method] = endpoints[action] || [];
            if (!url) return;
            if (action === 'remove' && !window.confirm(`Weet je zeker dat je "${{deviceLabel}}" wilt verwijderen?`)) {{
                return;
            }}

            try {{
                const response = await callJson(url, {{ method }});
                applyStatusPayload(response);
                setFlash('ok', response.message || 'Actie uitgevoerd.');
            }} catch (error) {{
                setFlash('error', error.message);
            }}
        }});

        portalList.addEventListener('click', async (event) => {{
            const button = event.target.closest('button[data-portal-action]');
            if (!button) return;
            const card = button.closest('[data-portal-id]');
            const portalId = card?.dataset.portalId;
            if (!portalId) return;

            const portal = statusSnapshot.portals.find((item) => item.portal_id === portalId);
            if (!portal) return;

            if (button.dataset.portalAction === 'edit') {{
                fillPortalForm(portal);
                return;
            }}

            if (!window.confirm(`Weet je zeker dat je het portaal "${{portal.name}}" wilt verwijderen?`)) {{
                return;
            }}

            try {{
                const response = await callJson('/api/v1/admin/portals/' + portalId, {{ method: 'DELETE' }});
                applyStatusPayload(response);
                setFlash('ok', response.message || 'Portaal verwijderd.');
            }} catch (error) {{
                setFlash('error', error.message);
            }}
        }});

        portalForm.addEventListener('submit', async (event) => {{
            event.preventDefault();
            try {{
                const response = await callJson('/api/v1/admin/portals', {{
                    method: 'POST',
                    body: JSON.stringify({{
                        portal_id: portalIdInput.value,
                        name: portalNameInput.value,
                        login_url: portalLoginUrlInput.value,
                        logo_url: portalLogoUrlInput.value,
                    }}),
                }});
                if (response.portal) {{
                    fillPortalForm(response.portal);
                }}
                applyStatusPayload(response);
                setFlash('ok', response.message || 'Portaal opgeslagen.');
            }} catch (error) {{
                setFlash('error', error.message);
            }}
        }});

        document.getElementById('btn-portal-reset').addEventListener('click', () => clearPortalForm());

        render(initialStatus);
        connectLive();
    </script>
</body>
</html>
"""
    return web.Response(text=body, content_type="text/html", status=status)


def _render_install_response(
    app: web.Application,
    *,
    diagnostics: dict[str, Any] | None,
    message: str | None,
    error: str | None,
    status: int,
    authorized: bool,
) -> web.Response:
    config = app["config"]
    upload_enabled = config.managed_fcm_upload_enabled
    upload_disabled_attr = " disabled" if not upload_enabled else ""
    flash = ""
    if message:
        flash += f'<p class="flash flash-ok">{html.escape(message)}</p>'
    if error:
        flash += f'<p class="flash flash-error">{html.escape(error)}</p>'

    token_field = ""
    if not authorized:
        token_field = """
      <label>
        <span>Admin-token</span>
        <input type="password" name="admin_token" autocomplete="current-password" required>
      </label>
"""

    diagnostics_markup = ""
    if diagnostics is not None:
        diagnostics_markup = f"""
  <section>
    <h2>Firebase-status</h2>
    <p><strong>Geconfigureerd:</strong> {diagnostics['configured']}</p>
    <p><strong>Project-ID:</strong> {html.escape(str(diagnostics['project_id'] or '-'))}</p>
    <p><strong>Bron:</strong> {html.escape(str(diagnostics['service_account_source']))}</p>
    <p><strong>Bestandspad:</strong> {html.escape(str(diagnostics['service_account_path'] or '-'))}</p>
    <p><strong>Bestand aanwezig:</strong> {diagnostics['service_account_file_exists']}</p>
    <p><strong>Aantal apparaten:</strong> {diagnostics['device_count']}</p>
    <p><strong>Actief apparaat:</strong> {html.escape(str(diagnostics['active_device_label'] or '-'))}</p>
    <p><strong>Configuratiefout:</strong> {html.escape(str(diagnostics['config_error'] or '-'))}</p>
  </section>
"""

    upload_note = (
        "De geuploade Firebase-sleutel wordt versleuteld opgeslagen in DATA_DIR met STORAGE_KEY of de lokale secret.key."
        if upload_enabled
        else "Firebase wordt hier al beheerd via stack-omgevingsvariabelen of een vaste bestandsmount. Uploaden via de pagina is daarom uitgeschakeld."
    )

    body = f"""
<!doctype html>
<html lang="nl">
<head>
  <meta charset="utf-8">
  <title>ONS Rooster Installatie</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 2rem; background: #f6f8fb; color: #1f2937; }}
    h1, h2 {{ margin-bottom: 0.5rem; }}
    section {{ background: white; border-radius: 12px; padding: 1rem 1.25rem; margin-bottom: 1rem; box-shadow: 0 8px 24px rgba(15, 23, 42, 0.08); }}
    form {{ display: grid; gap: 0.9rem; }}
    label {{ display: grid; gap: 0.35rem; font-weight: 600; }}
    input, button {{ font: inherit; }}
    input[type="password"], input[type="file"] {{ padding: 0.65rem 0.8rem; border: 1px solid #cbd5e1; border-radius: 10px; background: #fff; }}
    button {{ width: fit-content; border: 0; border-radius: 999px; padding: 0.7rem 1.1rem; background: #0f766e; color: white; cursor: pointer; }}
    button[disabled] {{ cursor: not-allowed; opacity: 0.55; }}
    .flash {{ border-radius: 10px; padding: 0.85rem 1rem; font-weight: 600; margin-bottom: 1rem; }}
    .flash-ok {{ background: #dcfce7; color: #166534; }}
    .flash-error {{ background: #fee2e2; color: #991b1b; }}
    code {{ background: #eef2ff; padding: 0.1rem 0.35rem; border-radius: 4px; }}
  </style>
</head>
<body>
  <h1>ONS Rooster Installatie</h1>
  <section>
    <h2>Firebase admin key upload</h2>
    <p>{html.escape(upload_note)}</p>
    <p>Open deze pagina via HTTPS. Daarna kun je op de operatorstatuspagina per gekoppeld apparaat een FCM-ping versturen.</p>
    {flash}
    <form method="post" enctype="multipart/form-data" action="/install">
{token_field}      <label>
        <span>Firebase service-account JSON</span>
        <input type="file" name="firebase_key" accept=".json,application/json" required{upload_disabled_attr}>
      </label>
      <button type="submit"{upload_disabled_attr}>Firebase-sleutel opslaan</button>
    </form>
  </section>
  {diagnostics_markup}
</body>
</html>
"""
    return web.Response(text=body, content_type="text/html", status=status)


def _render_mock_login_page(public_base_url: str, mode: str) -> str:
    mode_label = "SMS" if mode == "sms" else "basis"
    helper = (
        f"Na inloggen verschijnt een OTP-veld. Gebruik daarna mock code {MOCK_SMS_CODE}."
        if mode == "sms"
        else "Na inloggen volgt direct de mock roosterpagina."
    )
    return f"""
<!doctype html>
<html lang="nl">
<head>
  <meta charset="utf-8">
  <title>Mock HasMoves Login</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 2rem; background: #f6f8fb; color: #1f2937; }}
    section {{ max-width: 32rem; background: white; border-radius: 12px; padding: 1.25rem; box-shadow: 0 8px 24px rgba(15, 23, 42, 0.08); }}
    form {{ display: grid; gap: 0.9rem; }}
    label {{ display: grid; gap: 0.35rem; font-weight: 600; }}
    input, button {{ font: inherit; }}
    input {{ padding: 0.65rem 0.8rem; border: 1px solid #cbd5e1; border-radius: 10px; }}
    button {{ width: fit-content; border: 0; border-radius: 999px; padding: 0.7rem 1.1rem; background: #0f766e; color: white; cursor: pointer; }}
  </style>
</head>
<body>
  <section>
    <h1>Mock HasMoves Login</h1>
    <p>Testmodus: {html.escape(mode_label)}. {html.escape(helper)}</p>
    <p><strong>Publieke backend-URL:</strong> {html.escape(public_base_url)}</p>
    <form method="post" action="/sandbox/hasmoves/login?mode={html.escape(mode)}">
      <label>
        <span>Gebruikersnaam</span>
                <input type="text" name="username" autocomplete="username" required>
      </label>
      <label>
        <span>Wachtwoord</span>
        <input type="password" name="password" autocomplete="current-password" required>
      </label>
      <button type="submit">Inloggen</button>
    </form>
  </section>
</body>
</html>
"""


def _render_mock_challenge_page(username: str, error: str | None) -> str:
    flash = ""
    if error:
        flash = f'<p style="background:#fee2e2;color:#991b1b;padding:0.8rem 1rem;border-radius:10px;font-weight:600;">{html.escape(error)}</p>'
    return f"""
<!doctype html>
<html lang="nl">
<head>
  <meta charset="utf-8">
  <title>Mock HasMoves OTP</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 2rem; background: #f6f8fb; color: #1f2937; }}
    section {{ max-width: 32rem; background: white; border-radius: 12px; padding: 1.25rem; box-shadow: 0 8px 24px rgba(15, 23, 42, 0.08); }}
    form {{ display: grid; gap: 0.9rem; }}
    label {{ display: grid; gap: 0.35rem; font-weight: 600; }}
    input, button {{ font: inherit; }}
    input {{ padding: 0.65rem 0.8rem; border: 1px solid #cbd5e1; border-radius: 10px; }}
    button {{ width: fit-content; border: 0; border-radius: 999px; padding: 0.7rem 1.1rem; background: #0f766e; color: white; cursor: pointer; }}
    code {{ background: #eef2ff; padding: 0.1rem 0.35rem; border-radius: 4px; }}
  </style>
</head>
<body>
  <section>
    <h1>Mock HasMoves OTP</h1>
    <p>Gebruik voor deze test de vaste mock code <code>{MOCK_SMS_CODE}</code>.</p>
    {flash}
    <form method="post" action="/sandbox/hasmoves/challenge?mode=sms">
      <input type="hidden" name="username" value="{html.escape(username)}">
      <label>
        <span>SMS-code</span>
        <input type="text" name="code" autocomplete="one-time-code" required>
      </label>
      <button type="submit">Bevestigen</button>
    </form>
  </section>
</body>
</html>
"""


def _extract_bearer_token(request: web.Request) -> str | None:
    authorization = request.headers.get("Authorization", "")
    if authorization.lower().startswith("bearer "):
        return authorization.split(" ", 1)[1].strip()
    return None


async def _read_request_payload(request: web.Request) -> dict[str, Any]:
    if request.content_type.startswith("application/json"):
        payload = await request.json()
        if isinstance(payload, dict):
            return payload
        return {}
    if request.can_read_body:
        form = await request.post()
        return {key: value for key, value in form.items()}
    return {}


def _require_mobile_auth(request: web.Request) -> str:
    token = _extract_bearer_token(request)
    if not _service(request.app).mobile_token_is_valid(token):
        raise web.HTTPUnauthorized(text="Ongeldige app-token.")
    assert token is not None
    return token