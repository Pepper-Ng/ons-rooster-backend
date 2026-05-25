from __future__ import annotations

import hashlib
import html
import hmac
import logging
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlencode

from aiohttp import web

from .clients import FcmPushClient, PlaywrightAutomationClient
from .config import AppConfig
from .service import BackendService
from .storage import StateStore

OPS_SESSION_COOKIE = "ons_status_session"
MOCK_SMS_CODE = "123456"


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
            automation_client=PlaywrightAutomationClient(),
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
    app.router.add_post("/status/refresh", handle_status_refresh)
    app.router.add_post("/status/challenges/mock-sms", handle_status_mock_sms)
    app.router.add_post("/status/devices/{device_id}/activate", handle_status_activate_device)
    app.router.add_post("/status/devices/{device_id}/ping", handle_status_ping_device)
    app.router.add_post("/status/devices/{device_id}/remove", handle_status_remove_device)
    app.router.add_get("/sandbox/hasmoves/login", handle_mock_login_page)
    app.router.add_post("/sandbox/hasmoves/login", handle_mock_login_submit)
    app.router.add_post("/sandbox/hasmoves/challenge", handle_mock_challenge_submit)
    app.router.add_get("/sandbox/hasmoves/rooster", handle_mock_rooster_page)
    app.router.add_get("/api/v1/mobile/status", handle_mobile_status)
    app.router.add_post("/api/v1/mobile/setup", handle_mobile_setup)
    app.router.add_put("/api/v1/mobile/setup", handle_mobile_setup)
    app.router.add_post("/api/v1/mobile/tokens/fcm", handle_fcm_token)
    app.router.add_post("/api/v1/mobile/challenges/{challenge_id}/sms-code", handle_sms_code)
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
    return _render_install_response(
        request.app,
        diagnostics=diagnostics,
        message=request.query.get("message"),
        error=error,
        status=200 if authorized else 401,
        authorized=authorized,
    )


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

    return _render_status_page(
        request.app,
        authorized=True,
        message=request.query.get("message"),
        error=request.query.get("error"),
        status=200,
    )


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
    token = request.headers.get("X-Admin-Token") or request.query.get("token")
    service = _service(request.app)
    if not service.admin_token_is_valid(token):
        raise web.HTTPUnauthorized(text="Ongeldig admin-token.")
    status = await service.trigger_refresh(reason="manual", wait=False)
    return web.json_response({"message": "De handmatige synchronisatie is gestart.", "status": status})


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

    status_payload = service.mobile_status_payload()
    diagnostics = _fcm_diagnostics(app)
    devices = service.paired_devices_payload()
    mock_basic_url = f"{config.public_base_url}/sandbox/hasmoves/login"
    mock_sms_url = f"{config.public_base_url}/sandbox/hasmoves/login?mode=sms"
    challenge_controls = ""
    if status_payload["sync"]["current_challenge_id"]:
        challenge_controls = f"""
  <section>
    <h2>Actieve testuitdaging</h2>
    <p><strong>Challenge-ID:</strong> {html.escape(status_payload['sync']['current_challenge_id'])}</p>
    <p>Gebruik de mock code <code>{MOCK_SMS_CODE}</code> om een sandbox-OTP in te vullen zonder echte SMS.</p>
    <form method="post" action="/status/challenges/mock-sms">
      <button type="submit">Vul mock OTP {MOCK_SMS_CODE} in</button>
    </form>
  </section>
"""

    device_rows = "".join(
        f"""
        <tr>
          <td>{html.escape(device['device_label'])}</td>
          <td><code>{html.escape(device['device_id'])}</code></td>
          <td>{html.escape(device['fcm_token_suffix'] or '-')}</td>
          <td>{html.escape(device['last_seen_at'] or '-')}</td>
          <td>{'Ja' if device['is_active'] else 'Nee'}</td>
          <td>
            <div class="actions">
              <form method="post" action="/status/devices/{html.escape(device['device_id'])}/ping">
                <button type="submit">FCM-ping</button>
              </form>
              <form method="post" action="/status/devices/{html.escape(device['device_id'])}/activate">
                <button type="submit"{' disabled' if device['is_active'] else ''}>Maak actief</button>
              </form>
              <form method="post" action="/status/devices/{html.escape(device['device_id'])}/remove" onsubmit="return confirmRemoveDevice('{html.escape(device['device_label'])}');">
                <button type="submit" class="danger">Verwijder</button>
              </form>
            </div>
          </td>
        </tr>
"""
        for device in devices
    )

    body = f"""
<!doctype html>
<html lang="nl">
<head>
  <meta charset="utf-8">
  <title>ONS Rooster Operatorstatus</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 2rem; background: #f6f8fb; color: #1f2937; }}
    h1, h2 {{ margin-bottom: 0.5rem; }}
    section {{ background: white; border-radius: 12px; padding: 1rem 1.25rem; margin-bottom: 1rem; box-shadow: 0 8px 24px rgba(15, 23, 42, 0.08); }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ text-align: left; padding: 0.6rem; border-bottom: 1px solid #e5e7eb; vertical-align: top; }}
    form {{ display: inline; }}
    .actions {{ display: flex; gap: 0.5rem; flex-wrap: wrap; }}
    button {{ border: 0; border-radius: 999px; padding: 0.6rem 0.95rem; background: #0f766e; color: white; cursor: pointer; }}
    button.danger {{ background: #b91c1c; }}
    button[disabled] {{ opacity: 0.55; cursor: not-allowed; }}
    .flash {{ border-radius: 10px; padding: 0.85rem 1rem; font-weight: 600; margin-bottom: 1rem; }}
    .flash-ok {{ background: #dcfce7; color: #166534; }}
    .flash-error {{ background: #fee2e2; color: #991b1b; }}
    code {{ background: #eef2ff; padding: 0.1rem 0.35rem; border-radius: 4px; }}
    .toolbar {{ display: flex; gap: 0.75rem; flex-wrap: wrap; }}
    a {{ color: #0f766e; }}
  </style>
  <script>
    function confirmRemoveDevice(deviceLabel) {{
      return confirm('Weet je zeker dat je "' + deviceLabel + '" wilt verwijderen? Dit kan niet ongedaan gemaakt worden.');
    }}
  </script>
</head>
<body>
  <h1>ONS Rooster Operatorstatus</h1>
  {flash}
  <section>
    <div class="toolbar">
      <form method="post" action="/status/refresh"><button type="submit">Start sync nu</button></form>
      <form method="post" action="/status/logout"><button type="submit">Uitloggen</button></form>
      <a href="/install">Firebase-installatie</a>
      <a href="/debug?token={html.escape(config.debug_token)}">Debugpagina</a>
    </div>
  </section>
  <section>
    <h2>Overzicht</h2>
    <p><strong>Backend-URL:</strong> {html.escape(status_payload['public_base_url'])}</p>
    <p><strong>Inlogpagina:</strong> {html.escape(status_payload['login_url'])}</p>
    <p><strong>Actief apparaat:</strong> {html.escape(status_payload['active_device_label'] or '-')}</p>
    <p><strong>Aantal apparaten:</strong> {status_payload['device_count']}</p>
    <p><strong>FCM geconfigureerd:</strong> {diagnostics['configured']}</p>
    <p><strong>Laatste status:</strong> {html.escape(str(status_payload['sync']['last_message'] or '-'))}</p>
    <p><strong>Laatste fout:</strong> {html.escape(str(status_payload['sync']['last_error'] or '-'))}</p>
    <p><strong>Huidige fase:</strong> {html.escape(str(status_payload['sync']['current_phase'] or '-'))}</p>
  </section>
  <section>
    <h2>Gekoppelde apparaten</h2>
    <table>
      <thead>
        <tr><th>Label</th><th>Device-ID</th><th>FCM suffix</th><th>Laatst gezien</th><th>Actief</th><th>Acties</th></tr>
      </thead>
      <tbody>{device_rows or '<tr><td colspan="6">Nog geen apparaten gekoppeld.</td></tr>'}</tbody>
    </table>
  </section>
  {challenge_controls}
  <section>
    <h2>Mock HasMoves testflow</h2>
    <p>Gebruik deze URL als ONS-inlog-URL in de app of in backend-tests om de live HasMoves-site te omzeilen.</p>
    <p><strong>Basisflow:</strong> <a href="{html.escape(mock_basic_url)}">{html.escape(mock_basic_url)}</a></p>
    <p><strong>SMS-flow:</strong> <a href="{html.escape(mock_sms_url)}">{html.escape(mock_sms_url)}</a></p>
    <p>Voor de SMS-flow accepteert de mock challenge code <code>{MOCK_SMS_CODE}</code>. Je kunt die via de knop hierboven in de actieve uitdaging injecteren.</p>
  </section>
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


def _require_mobile_auth(request: web.Request) -> str:
    token = _extract_bearer_token(request)
    if not _service(request.app).mobile_token_is_valid(token):
        raise web.HTTPUnauthorized(text="Ongeldige app-token.")
    assert token is not None
    return token