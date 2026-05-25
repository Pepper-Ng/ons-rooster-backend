from __future__ import annotations

import html
import logging
from typing import Any

from aiohttp import web

from .clients import FcmPushClient, PlaywrightAutomationClient
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
    app.router.add_get("/install", handle_install_page)
    app.router.add_post("/install", handle_install_upload)
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
    return web.json_response(
        {
            "service": "ons-rooster-backend",
            "health": "/healthz",
            "mobile_status": "/api/v1/mobile/status",
            "debug": "/debug",
            "install": "/install",
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
        <p><strong>Installatiepagina:</strong> <a href="/install">/install</a></p>
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


async def handle_install_page(request: web.Request) -> web.Response:
    service = _service(request.app)
    token = request.query.get("token") or request.headers.get("X-Admin-Token")
    authorized = service.admin_token_is_valid(token)
    diagnostics = _fcm_diagnostics(request.app) if authorized else None
    error = "Ongeldig admin-token." if token and not authorized else None
    return _render_install_response(
        request.app,
        diagnostics=diagnostics,
        message=None,
        error=error,
        status=200 if error is None else 401,
    )


async def handle_install_upload(request: web.Request) -> web.Response:
    service = _service(request.app)
    form = await request.post()
    token = str(form.get("admin_token", "")).strip() or request.headers.get("X-Admin-Token")
    if not service.admin_token_is_valid(token):
        return _render_install_response(
            request.app,
            diagnostics=None,
            message=None,
            error="Ongeldig admin-token.",
            status=401,
        )

    upload = form.get("firebase_key")
    if upload is None or not hasattr(upload, "file"):
        return _render_install_response(
            request.app,
            diagnostics=_fcm_diagnostics(request.app),
            message=None,
            error="Selecteer een Firebase service-account JSON-bestand om te uploaden.",
            status=400,
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
        )

    diagnostics["device_registered"] = service.has_device()
    diagnostics["device_has_token"] = bool(service.state.device and service.state.device.fcm_token)
    return _render_install_response(
        request.app,
        diagnostics=diagnostics,
        message="De Firebase-sleutel is opgeslagen. De backend kan FCM nu zonder redeploy gebruiken.",
        error=None,
        status=200,
    )


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
    await service.send_test_notification(message)

    diagnostics = FcmPushClient(request.app["config"]).diagnostics()
    return web.json_response(
        {
            "message": "De FCM-testmelding is verzonden.",
            "fcm": diagnostics,
        }
    )


def _service(app: web.Application) -> BackendService:
    return app["service"]


def _fcm_diagnostics(app: web.Application) -> dict[str, Any]:
        service = _service(app)
        diagnostics = FcmPushClient(app["config"]).diagnostics()
        diagnostics["device_registered"] = service.has_device()
        diagnostics["device_has_token"] = bool(service.state.device and service.state.device.fcm_token)
        return diagnostics


def _render_install_response(
        app: web.Application,
        *,
        diagnostics: dict[str, Any] | None,
        message: str | None,
        error: str | None,
        status: int,
) -> web.Response:
        config = app["config"]
        token_required = bool(config.admin_token)
        upload_enabled = config.managed_fcm_upload_enabled
        upload_disabled_attr = " disabled" if not upload_enabled else ""
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
        <p><strong>App gekoppeld:</strong> {diagnostics['device_registered']}</p>
        <p><strong>App heeft FCM-token:</strong> {diagnostics['device_has_token']}</p>
        <p><strong>Configuratiefout:</strong> {html.escape(str(diagnostics['config_error'] or '-'))}</p>
    </section>
"""

        flash = ""
        if message:
                flash += f'<p class="flash flash-ok">{html.escape(message)}</p>'
        if error:
                flash += f'<p class="flash flash-error">{html.escape(error)}</p>'

        upload_note = (
                "De geuploade Firebase-sleutel wordt versleuteld opgeslagen in DATA_DIR met STORAGE_KEY of de lokale secret.key."
                if upload_enabled
                else "Firebase wordt hier al beheerd via stack-omgevingsvariabelen of een vaste bestandsmount. Uploaden via de pagina is daarom uitgeschakeld."
        )
        token_field = ""
        if token_required:
                token_field = """
            <label>
                <span>Admin-token</span>
                <input type="password" name="admin_token" autocomplete="current-password" required>
            </label>
"""

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
        .flash {{ border-radius: 10px; padding: 0.85rem 1rem; font-weight: 600; }}
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
        <p>Open deze pagina via HTTPS. Na het uploaden kun je <code>/api/v1/admin/fcm/test</code> gebruiken om een testmelding te versturen naar de gekoppelde Android-app.</p>
        {flash}
        <form method="post" enctype="multipart/form-data" action="/install">
{token_field}      <label>
                <span>Firebase service-account JSON</span>
                <input type="file" name="firebase_key" accept=".json,application/json" required{upload_disabled_attr}>
            </label>
            <button type="submit"{upload_disabled_attr}>Firebase-sleutel opslaan</button>
        </form>
    </section>
{diagnostics_markup}</body>
</html>
"""
        return web.Response(text=body, content_type="text/html", status=status)


def _extract_bearer_token(request: web.Request) -> str | None:
    authorization = request.headers.get("Authorization", "")
    if authorization.lower().startswith("bearer "):
        return authorization.split(" ", 1)[1].strip()
    return None


def _require_mobile_auth(request: web.Request) -> None:
    token = _extract_bearer_token(request)
    if not _service(request.app).mobile_token_is_valid(token):
        raise web.HTTPUnauthorized(text="Ongeldige app-token.")
