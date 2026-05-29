# ONS Rooster Backend

This repository now contains a deployable backend service for the ONS roster workflow instead of a single Raspberry Pi script.

The backend is designed to run continuously as a Docker stack in Portainer. The Android app is responsible for the one-time setup flow and the SMS-based 2FA step. The backend stores the ONS login credentials securely, submits the username/password step over a server-side HTTP session, checkpoints the OTP page session for the follow-up step, requests the SMS code from the phone through Firebase Cloud Messaging, and exposes operator-facing debug and status endpoints over HTTPS.

## Current architecture

```text
[Android app(s)]
      │  Setup form
      │  - Backend URL
      │  - ONS login URL
      │  - Username
      │  - Password
      ▼
[HTTPS backend API]
      │  Stores credentials encrypted at rest
      │  Tracks paired devices and one active device
      │  Issues per-device bearer tokens
      │  Starts the HTTP login session when setup or sync runs
      │  Stores the OTP checkpoint session for the next step
      │
      │  FCM data push: listen_sms to active device
      ▼
[Firebase Cloud Messaging]
      ▼
[Active Android phone]
      │  Reads incoming ONS SMS
      │  Relays the code back over HTTPS
      ▼
[HTTPS backend API]
      │  Completes login
      │  Scrapes the roster with fallback heuristics
      │  Writes roster.ics
      │  Sends auth_result notification to the phone
      ▼
[Debug and calendar endpoints]
```

## What changed

- The backend is now a Python package under `src/ons_backend`.
- Credentials are stored encrypted in the persistent data directory.
- The Android app drives the initial setup instead of editing backend source code or `.env` credentials manually.
- The backend exposes authenticated mobile endpoints, an install page, an operator status page, a debug page, and a calendar endpoint.
- Multiple Android devices can now be paired at once, while one device remains the active SMS/FCM target.
- A mock HasMoves login flow is included for safe loopback testing without touching the live ONS site.
- A Dockerfile, stack compose file, and environment template are included for Portainer.
- Unit and end-to-end style tests are included for the backend flow without requiring real ONS credentials.

## Local development

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e .[dev]
playwright install chromium
pytest
```

On Windows PowerShell, use the virtual environment under `.venv\Scripts\Activate.ps1` instead.

## Docker and Portainer deployment

The repository root contains `docker-compose.yml` for a Git-backed Portainer stack.
The repository also contains `docker-compose.portainer.secrets.yml`, which is intended as an additional Portainer file when you want to bind-mount the Firebase admin key from the Docker host.

For standalone installs that do not want to touch Portainer stack secrets at all, the backend also exposes an authenticated install page at `/install` that can accept a Firebase admin SDK JSON upload over HTTPS.

### Service defaults

- Container name: `ons-rooster`
- Internal port: `8080`
- Published host port: `18080`
- Persistent volume: `ons_rooster_data`
- Public base URL default: `https://onsrooster.stefhermans.nl`

### Important stack environment values

These values are exposed directly in `docker-compose.yml` and `.env.example`.

| Variable | Purpose |
|---|---|
| `PUBLIC_BASE_URL` | Public HTTPS base URL used by the app and debug links. |
| `DEFAULT_LOGIN_URL` | Default StartMetOns login page shown in the app. |
| `SYNC_INTERVAL_MINUTES` | Automatic sync interval. Set `0` to disable the scheduler. |
| `SMS_TIMEOUT_SECONDS` | How long the backend waits for the Android app to return a code. |
| `LOGIN_TIMEOUT_SECONDS` | How long the server-side login step may wait for state changes. |
| `SETUP_SECRET` | Optional setup code for first-time pairing or credential rotation. |
| `DEBUG_TOKEN` | Optional token for the HTTPS debug page. |
| `ADMIN_TOKEN` | Optional token for `POST /api/v1/admin/refresh`. |
| `STORAGE_KEY` | Optional pre-generated Fernet key. If omitted, one is generated in the data volume. |
| `FCM_PROJECT_ID` | Firebase project ID used for FCM pushes. |
| `FCM_SERVICE_ACCOUNT_HOST_PATH` | Host path for the admin SDK JSON when using `docker-compose.portainer.secrets.yml`. |
| `FCM_SERVICE_ACCOUNT_FILE` | Optional path to a mounted Firebase service account JSON file. |
| `FCM_SERVICE_ACCOUNT_JSON` | Optional raw Firebase service account JSON string. |
| `POST_LOGIN_URL` | Optional URL to open immediately after login. |
| `ROSTER_URL` | Optional explicit roster page URL. |

The current Land van Horne default is:

`https://landvanhorne.startmetons.nl/?jump=https%3A%2F%2Flandvanhorne.hasmoves.com%2F`

### Important note about Firebase

The backend needs a Firebase service account to send FCM data pushes. The Android app already contains the client-side Firebase configuration, but the backend service account key should not be committed to this repository.

Use either:

- `FCM_SERVICE_ACCOUNT_FILE` with a mounted file on the Portainer host, or
- `FCM_SERVICE_ACCOUNT_JSON` as a stack environment value.

There is now a third option for one-off standalone installs:

- upload the Firebase admin SDK JSON through `https://<your-backend>/install`

The safest option on the current standalone Docker host is the mounted file approach. The backend can now derive the Firebase project id directly from the service account JSON, so the admin key file is usually the only secret you need.

### Recommended Portainer workflow for the Firebase admin key

1. Copy the Firebase admin SDK JSON to the Docker host, outside git, for example:
      - `/opt/ons-rooster/secrets/firebase-adminsdk.json`
2. Restrict its permissions on the Docker host:
      - `chmod 600 /opt/ons-rooster/secrets/firebase-adminsdk.json`
3. In the Portainer stack, add `docker-compose.portainer.secrets.yml` as an additional file.
4. Set the stack environment value `FCM_SERVICE_ACCOUNT_HOST_PATH=/opt/ons-rooster/secrets/firebase-adminsdk.json`.
5. Redeploy the stack.

This keeps the private key out of git and out of the Portainer stack JSON itself.

Use `FCM_SERVICE_ACCOUNT_JSON` only as a fallback when you cannot place a file on the Docker host. It works, but it is less secure because the secret is stored directly in Portainer stack configuration.

### Install page upload flow

The `/install` page accepts a Firebase admin SDK JSON file over HTTPS and stores it in `DATA_DIR` as an encrypted blob. The backend reuses the same `STORAGE_KEY` or generated `secret.key` that already protects the saved login credentials, so a redeploy is not required after upload.

Use this when:

- you want to avoid editing Portainer stack variables for the Firebase key
- the backend already has a persistent data volume
- you have an admin token and can open the page over HTTPS

Use the bind-mounted file approach when you want the clearest operational separation between the app container and the Firebase key material.

### FCM diagnostics and test endpoint

The backend now exposes two admin endpoints for Firebase validation:

| Route | Purpose |
|---|---|
| `GET /api/v1/admin/fcm` | Returns FCM configuration diagnostics. |
| `POST /api/v1/admin/fcm/test` | Sends a test notification to the active Android device, or to a specific paired device when `device_id` is supplied in the JSON body. |
| `GET /install` | Shows the operator install page for uploading the Firebase admin key. |
| `GET /status` | Shows the operator status page after admin-token login. |

Both endpoints require the admin token through `?token=...` or `X-Admin-Token`.

Example diagnostics check:

```bash
curl "https://onsrooster.stefhermans.nl/api/v1/admin/fcm?token=<admin-token>"
```

Example test notification:

```bash
curl -X POST \
  -H "Content-Type: application/json" \
  -d '{"message":"Testmelding vanaf de backend."}' \
  "https://onsrooster.stefhermans.nl/api/v1/admin/fcm/test?token=<admin-token>"
```

If the app is paired and FCM is configured correctly, the phone should receive the same lightweight notification path the backend uses after a successful login.

## Operator status page

The operator page is available at `/status`.

It uses the same `ADMIN_TOKEN` as a lightweight web password. After login, the page stores a short-lived HTTP-only cookie and shows:

- all paired devices
- which device is currently active for SMS and auth-result pushes
- a per-device `FCM-ping` button
- a `Maak actief` button to switch the active device
- a manual sync trigger
- a mock OTP submit button for the current challenge
- direct links to the mock HasMoves pages

This page is intended for browser-based operator checks on the live HTTPS host, not for the Android app.

## Mock HasMoves loopback

The backend also exposes mock login pages so you can test the Playwright/login flow without hitting the real ONS website:

- `/sandbox/hasmoves/login`
- `/sandbox/hasmoves/login?mode=sms`

The mock pages deliberately use generic form fields such as `username`, `password`, and `code`, so they match the existing Playwright selectors. The SMS variant accepts the fixed test code `123456` and then serves a roster page with simple date/time rows that the current fallback scraper can parse.

## Android-led setup flow

1. Install the Android app from the sibling repository.
2. Open the app and grant the SMS and notification permissions.
3. Enter:
   - backend base URL
   - ONS login URL
   - ONS username
   - ONS password
   - optional setup code
4. Tap the save button.
5. The backend stores the credentials encrypted, starts a login attempt, and requests the SMS code when ONS triggers 2FA.
6. The phone receives the SMS, relays the code over HTTPS, and gets a small confirmation notification when the backend is ready.

The app does not persist the ONS password locally after submission. The backend becomes the long-running worker and keeps the credentials for future refreshes.

## HTTPS endpoints

| Route | Purpose |
|---|---|
| `GET /healthz` | Basic health check. |
| `GET /rooster.ics` | Calendar output based on the last successful scrape. |
| `GET /status` | Operator page with paired-device overview, per-device FCM ping, and manual controls. |
| `GET /debug` | Operator-facing HTML debug page. Optional `DEBUG_TOKEN` protection is supported. |
| `GET /install` | Operator-facing Firebase admin key upload page. |
| `GET /sandbox/hasmoves/login` | Mock login page for local or live loopback testing. |
| `GET /api/v1/mobile/status` | Authenticated status endpoint for the Android app. |
| `POST /api/v1/mobile/setup` | Android setup and credential update endpoint. |
| `POST /api/v1/mobile/tokens/fcm` | Android FCM token refresh endpoint. |
| `POST /api/v1/mobile/challenges/{id}/sms-code` | Android callback endpoint for a 2FA code. |
| `POST /api/v1/admin/refresh` | Optional authenticated manual refresh trigger. |

## Debug page

The debug page is intended for live verification on `https://onsrooster.stefhermans.nl/debug`.

It shows:

- latest backend status
- last success or failure timestamps
- current login phase
- last HTML snapshot
- roster-like rows detected by the fallback scraper
- recent debug notes from the login flow

If `DEBUG_TOKEN` is set, pass it as `?token=...` or `X-Debug-Token`.

## Tests

Backend tests currently cover:

- encrypted state persistence
- snapshot and ICS persistence
- multi-device state persistence
- Firebase configuration diagnostics
- authenticated mobile setup flow
- end-to-end SMS roundtrip using fake push and fake browser clients
- operator status-page login and per-device actions
- mock HasMoves basic and SMS loopback flow
- debug endpoint access control

Run them with:

```bash
pytest tests/test_storage.py tests/test_app_flow.py -q
```

## Current limitation

The backend already handles the remote login handshake and state management, but the actual roster extraction still uses generic HTML heuristics until real ONS page structure and live credentials are available. That means the authentication loop is in place, while the post-login scraping selectors will likely need one more tuning pass against the live page.
