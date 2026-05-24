# ONS Rooster Relay v2 — FCM-architectuur

## Waarom FCM in plaats van een altijd-open WebSocket?

| | WebSocket (v1) | FCM (v2) |
|---|---|---|
| Stroomverbruik | Hoog — service draait continu | Minimaal — OS beheert de verbinding |
| Na reboot | Vereist BootReceiver + foreground service | Automatisch — OS start FCM bij boot |
| Geen netwerk | Retry in de app, maar service kan gekilled worden | Android levert push zodra netwerk terug is |
| Zoals WhatsApp/Telegram | ✗ | ✓ |

FCM houdt één verbinding open op OS-niveau (niet per app). Dat is precies hoe WhatsApp en Telegram het doen.

---

## Architectuur

```
[Cron job op backend host]
      │  POST /refresh
      ▼
[backend service]
      │  1. Start Playwright login bij ONS
      │  2. ONS vraagt om 2FA-code
      │
      │  FCM data-push ("listen_sms")
      ▼
[Google FCM servers]  ──────────────►  [Android OS]
                                              │ wekt OnsFirebaseService
                                              │ registreert tijdelijke SMS-listener
                                              │ SMS van Nedap binnenkomt
                                              │ POST /sms_code naar backend
      ◄─────────────────────────────────────┘
      │  3. 2FA-code invullen, inloggen
      │  4. Rooster scrapen
      │  5. .ics genereren en opslaan
      ▼
[GET /rooster.ics]  ◄──  Google Calendar / Outlook abonnement
```

---

## Eenmalige setup

### Stap 1: Firebase project aanmaken (gratis)

1. Ga naar https://console.firebase.google.com
2. Maak een nieuw project aan (bijv. "ons-relay")
3. Voeg een Android-app toe met package name `nl.landvanhorne.smsrelay`
4. Download `google-services.json` → zet dit in `sms-relay-android/app/`
5. Ga naar Project Settings → Service Accounts → Generate new private key
6. Download het JSON-bestand → sla op op de backend host, bijvoorbeeld als `/opt/ons-backend/firebase_key.json`
7. Noteer je Project ID (staat in Project Settings)

### Stap 2: Backend configureren

Pas in `backend.py` aan:
```python
ONS_USERNAME        = "lia@landvanhorne.nl"
ONS_PASSWORD        = "jouw_wachtwoord"    # of gebruik .env
FIREBASE_PROJECT_ID = "ons-relay-xxxxx"   # je Firebase Project ID
```

Of via environment variabelen (aanbevolen):
```bash
export ONS_USERNAME="lia@landvanhorne.nl"
export ONS_PASSWORD="jouw_wachtwoord"
```

### Stap 3: Backend dependencies installeren

```bash
pip3 install aiohttp playwright icalendar google-auth requests python-dotenv
playwright install chromium
playwright install-deps
```

### Stap 4: Android app bouwen

- Zet `google-services.json` in `sms-relay-android/app/`
- Pas in `OnsFirebaseService.kt` het backend-adres aan:
  ```kotlin
      const val SERVER_CALLBACK_URL = "http://backend-host.local:8080/sms_code"
  ```
- Bouw en installeer de app
- Open de app, verleen SMS-toestemming, zet battery-optimalisatie uit
- Kopieer het FCM-token dat de app toont

### Stap 5: FCM-token op backend host opslaan

```bash
echo "het-gekopieerde-fcm-token" > /opt/ons-backend/fcm_token.txt
```
(De app stuurt het token ook automatisch als `/register_token` bereikbaar is vanaf de backend host.)

### Stap 6: Backend starten

```bash
python3 backend.py
```

Als systemd-service (autostart):
```ini
# /etc/systemd/system/ons-relay.service
[Unit]
Description=ONS Rooster Relay
After=network-online.target

[Service]
ExecStart=/usr/bin/python3 /opt/ons-backend/backend.py
WorkingDirectory=/opt/ons-backend
Restart=always
User=onsrelay
EnvironmentFile=/opt/ons-backend/.env

[Install]
WantedBy=multi-user.target
```
```bash
sudo systemctl enable ons-relay
sudo systemctl start ons-relay
```

### Stap 7: Cron job instellen

```bash
crontab -e
# Elke 1e van de maand om 07:00
0 7 1 * * curl -s -X POST http://localhost:8080/refresh
```

### Stap 8: Kalender abonneren

```
http://<backend-host>:8080/rooster.ics
```

**Google Calendar:** Andere agenda's → Via URL → plak URL
**Outlook:** Agenda toevoegen → Abonneren via internet → plak URL

---

## Beveiliging

De endpoints zijn alleen bedoeld voor intern gebruik. Exposeer ze niet publiek.
Gebruik Tailscale of WireGuard als je de iCal-URL ook buiten je thuisnetwerk wilt bereiken.

Wachtwoord veilig opslaan:
```bash
# /opt/ons-backend/.env
ONS_USERNAME=lia@landvanhorne.nl
ONS_PASSWORD=jouw_wachtwoord
```

---

## Retry-gedrag

**Android → backend (SMS-code terugsturen):**
De app probeert maximaal 5 keer met exponential backoff (3s, 6s, 12s, 24s, 30s).
Als de telefoon tijdelijk geen wifi/4G heeft, blijft de app het proberen.

**Backend wacht op SMS-code:**
De backend wacht standaard 120 seconden. Aanpasbaar via `SMS_TIMEOUT` in `backend.py`.

**FCM levering:**
FCM bewaart een push maximaal 4 weken als het apparaat offline is.
Zodra de telefoon weer verbinding heeft, wordt de push alsnog bezorgd.
