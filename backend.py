"""
ONS Rooster Backend — Raspberry Pi
Vereisten: pip install aiohttp playwright icalendar google-auth requests

FCM sturen via Google's HTTP v1 API:
  pip install google-auth
  Download je Firebase service account JSON via Firebase Console →
  Project Settings → Service Accounts → Generate new private key
"""

import asyncio
import json
import logging
import os
from datetime import datetime
from pathlib import Path

import requests
from aiohttp import web
from playwright.async_api import async_playwright
from icalendar import Calendar, Event
import google.auth.transport.requests
import google.oauth2.service_account

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
log = logging.getLogger(__name__)

# ── Configuratie ──────────────────────────────────────────────────────────────
ONS_URL        = "https://landvanhorne.hasmoves.com"
ONS_USERNAME   = os.getenv("ONS_USERNAME", "lia@landvanhorne.nl")
ONS_PASSWORD   = os.getenv("ONS_PASSWORD", "jouw_wachtwoord")
ICS_PATH       = Path("/home/pi/rooster.ics")
HTTP_PORT      = 8080
SMS_TIMEOUT    = 120   # seconden wachten op SMS-code na FCM-push

# Firebase: sla het service-account JSON-bestand op als firebase_key.json
FIREBASE_KEY_FILE   = Path("/home/pi/firebase_key.json")
FIREBASE_PROJECT_ID = "jouw-project-id"   # te vinden in Firebase Console

# FCM-token van de Android app (wordt automatisch opgeslagen bij registratie)
FCM_TOKEN_FILE = Path("/home/pi/fcm_token.txt")
# ─────────────────────────────────────────────────────────────────────────────

# Event dat wordt gezet zodra de Android-app de SMS-code terugstuurt
sms_event: asyncio.Event = asyncio.Event()
sms_code_received: dict = {}


# ── FCM push sturen ───────────────────────────────────────────────────────────

def get_fcm_access_token() -> str:
    """Haalt een OAuth2-token op voor de FCM HTTP v1 API."""
    credentials = google.oauth2.service_account.Credentials.from_service_account_file(
        str(FIREBASE_KEY_FILE),
        scopes=["https://www.googleapis.com/auth/firebase.messaging"]
    )
    credentials.refresh(google.auth.transport.requests.Request())
    return credentials.token


def send_fcm_push(fcm_token: str) -> bool:
    """Stuurt een data-push naar de Android app via FCM HTTP v1."""
    access_token = get_fcm_access_token()
    url = f"https://fcm.googleapis.com/v1/projects/{FIREBASE_PROJECT_ID}/messages:send"

    payload = {
        "message": {
            "token": fcm_token,
            "data": {
                # data-only push: wekt de app ook als die "gestopt" is
                "type": "listen_sms"
            },
            "android": {
                "priority": "high"   # hoge prioriteit = directe levering
            }
        }
    }

    resp = requests.post(
        url,
        headers={
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        },
        json=payload,
        timeout=10
    )

    if resp.ok:
        log.info(f"FCM push verstuurd: {resp.json()}")
        return True
    else:
        log.error(f"FCM push mislukt: {resp.status_code} {resp.text}")
        return False


# ── HTTP endpoints ────────────────────────────────────────────────────────────

async def handle_sms_code(request: web.Request) -> web.Response:
    """
    Android app POST-t hier de ontvangen SMS-code naartoe.
    Wordt aangeroepen nadat de FCM-push de app heeft gewekt.
    """
    global sms_code_received
    data = await request.json()
    log.info(f"SMS-code ontvangen van Android: {data}")
    sms_code_received = data
    sms_event.set()
    return web.Response(text="OK")


async def handle_register_token(request: web.Request) -> web.Response:
    """Slaat het FCM-token van de Android app op."""
    data = await request.json()
    token = data.get("token", "")
    if token:
        FCM_TOKEN_FILE.write_text(token)
        log.info(f"FCM-token opgeslagen: {token[:20]}...")
    return web.Response(text="OK")


async def serve_ics(request: web.Request) -> web.Response:
    if not ICS_PATH.exists():
        return web.Response(status=404, text="Rooster nog niet gegenereerd. POST /refresh")
    return web.Response(
        body=ICS_PATH.read_bytes(),
        content_type="text/calendar",
        headers={"Content-Disposition": 'attachment; filename="rooster.ics"'}
    )


async def handle_refresh(request: web.Request) -> web.Response:
    """Handmatig of via cron triggeren: POST /refresh"""
    asyncio.create_task(refresh_rooster())
    return web.Response(text="Rooster verversen gestart")


# ── Hoofd flow: push → wacht op SMS → scrape ─────────────────────────────────

async def request_sms_via_fcm() -> str:
    """
    Stuurt FCM-push naar Android, wacht op de teruggestuurde SMS-code.
    Heeft ingebouwde retry: als het netwerk er even uit ligt op de telefoon,
    stuurt Android de code zodra de verbinding terug is (OkHttp retry in de app).
    """
    if not FCM_TOKEN_FILE.exists():
        raise RuntimeError(
            "Geen FCM-token bekend. Open de app op de Android-telefoon, "
            "kopieer het token en sla het op in " + str(FCM_TOKEN_FILE)
        )

    fcm_token = FCM_TOKEN_FILE.read_text().strip()

    # Reset event voor deze run
    sms_event.clear()
    sms_code_received.clear()

    # Stuur push
    if not send_fcm_push(fcm_token):
        raise RuntimeError("FCM push mislukt")

    log.info(f"FCM push verstuurd. Wacht op SMS-code (max {SMS_TIMEOUT}s)...")

    # Wacht tot Android de code terugstuurt via POST /sms_code
    try:
        await asyncio.wait_for(sms_event.wait(), timeout=SMS_TIMEOUT)
    except asyncio.TimeoutError:
        raise RuntimeError("Timeout: Android-app heeft geen SMS-code teruggestuurd")

    code = sms_code_received.get("code", "")
    if not code:
        raise RuntimeError("Lege SMS-code ontvangen")

    log.info(f"SMS-code ontvangen: {code}")
    return code


# ── Scraper ───────────────────────────────────────────────────────────────────

async def scrape_rooster() -> list[dict]:
    diensten = []
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()
        try:
            await page.goto(ONS_URL, wait_until="networkidle")
            await page.fill('input[name="username"], input[type="email"]', ONS_USERNAME)
            await page.fill('input[name="password"], input[type="password"]', ONS_PASSWORD)
            await page.click('button[type="submit"]')

            # Wacht op 2FA-veld
            await page.wait_for_selector(
                'input[name="code"], input[name="otp"], input[name="token"]',
                timeout=15_000
            )

            # Haal code op via FCM → Android → HTTP POST terug
            sms_code = await request_sms_via_fcm()

            await page.fill(
                'input[name="code"], input[name="otp"], input[name="token"]',
                sms_code
            )
            await page.click('button[type="submit"]')
            await page.wait_for_url(f"{ONS_URL}/**", timeout=15_000)
            log.info("Ingelogd op ONS")

            # Navigeer naar rooster (AANPASSEN op basis van echte URL)
            await page.goto(f"{ONS_URL}/rooster/mijn-rooster", wait_until="networkidle")

            # AANPASSEN: pas selectors aan na inspectie van de echte pagina
            dienst_elements = await page.query_selector_all(".dienst-item, .shift-row")
            for el in dienst_elements:
                datum  = await (await el.query_selector(".datum, td:nth-child(1)")).inner_text()
                start  = await (await el.query_selector(".starttijd, td:nth-child(2)")).inner_text()
                eind   = await (await el.query_selector(".eindtijd, td:nth-child(3)")).inner_text()
                omschr_el = await el.query_selector(".omschrijving, td:nth-child(4)")
                omschr = await omschr_el.inner_text() if omschr_el else "Dienst"
                diensten.append({"date": datum, "start": start, "end": eind, "omschrijving": omschr})

            log.info(f"{len(diensten)} diensten gescraped")
        finally:
            await browser.close()
    return diensten


# ── iCal generator ────────────────────────────────────────────────────────────

def generate_ical(diensten: list[dict]) -> bytes:
    cal = Calendar()
    cal.add("prodid", "-//ONS Rooster Relay//NL")
    cal.add("version", "2.0")
    cal.add("x-wr-calname", "Mijn Rooster (ONS)")

    for d in diensten:
        try:
            start = datetime.strptime(f"{d['date'].strip()} {d['start'].strip()}", "%d-%m-%Y %H:%M")
            eind  = datetime.strptime(f"{d['date'].strip()} {d['end'].strip()}",   "%d-%m-%Y %H:%M")
            event = Event()
            event.add("summary", d.get("omschrijving", "Dienst"))
            event.add("dtstart", start)
            event.add("dtend",   eind)
            event.add("dtstamp", datetime.now())
            cal.add_component(event)
        except ValueError as e:
            log.warning(f"Kon dienst niet parsen: {d} — {e}")

    return cal.to_ical()


async def refresh_rooster():
    log.info("=== Rooster verversen ===")
    try:
        diensten = await scrape_rooster()
        ICS_PATH.write_bytes(generate_ical(diensten))
        log.info(f"iCal opgeslagen: {ICS_PATH} ({len(diensten)} diensten)")
    except Exception as e:
        log.error(f"Fout: {e}", exc_info=True)


# ── Start ─────────────────────────────────────────────────────────────────────

async def main():
    app = web.Application()
    app.router.add_get("/rooster.ics",       serve_ics)
    app.router.add_post("/refresh",          handle_refresh)
    app.router.add_post("/sms_code",         handle_sms_code)
    app.router.add_post("/register_token",   handle_register_token)

    runner = web.AppRunner(app)
    await runner.setup()
    await web.TCPSite(runner, "0.0.0.0", HTTP_PORT).start()

    log.info(f"Backend draait op poort {HTTP_PORT}")
    log.info(f"  Abonneer op: http://<pi-ip>:{HTTP_PORT}/rooster.ics")
    log.info(f"  Verversen:   POST http://<pi-ip>:{HTTP_PORT}/refresh")

    await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(main())
