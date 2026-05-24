# ONS Rooster Backend

This repository now contains a deployable backend service for the ONS roster workflow instead of a single Raspberry Pi script.

The backend is designed to run continuously as a Docker stack in Portainer. The Android app is responsible for the one-time setup flow and the SMS-based 2FA step. The backend stores the ONS login credentials securely, initiates the browser login, requests the SMS code from the phone through Firebase Cloud Messaging, and exposes operator-facing debug endpoints over HTTPS.

## Current architecture

```text
[Android app]
      │  Setup form
      │  - Backend URL
      │  - ONS login URL
      │  - Username
      │  - Password
      ▼
[HTTPS backend API]
      │  Stores credentials encrypted at rest
      │  Issues device bearer token
      │  Starts Playwright login when setup or sync runs
      │
      │  FCM data push: listen_sms
      ▼
[Firebase Cloud Messaging]
      ▼
[Android phone]
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
- The backend exposes authenticated mobile endpoints, a debug page, and a calendar endpoint.
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
| `DEFAULT_LOGIN_URL` | Default ONS login page shown in the app. |
| `SYNC_INTERVAL_MINUTES` | Automatic sync interval. Set `0` to disable the scheduler. |
| `SMS_TIMEOUT_SECONDS` | How long the backend waits for the Android app to return a code. |
| `LOGIN_TIMEOUT_SECONDS` | How long the Playwright login heuristics may wait for state changes. |
| `SETUP_SECRET` | Optional setup code for first-time pairing or credential rotation. |
| `DEBUG_TOKEN` | Optional token for the HTTPS debug page. |
| `ADMIN_TOKEN` | Optional token for `POST /api/v1/admin/refresh`. |
| `STORAGE_KEY` | Optional pre-generated Fernet key. If omitted, one is generated in the data volume. |
| `FCM_PROJECT_ID` | Firebase project ID used for FCM pushes. |
| `FCM_SERVICE_ACCOUNT_FILE` | Optional path to a mounted Firebase service account JSON file. |
| `FCM_SERVICE_ACCOUNT_JSON` | Optional raw Firebase service account JSON string. |
| `POST_LOGIN_URL` | Optional URL to open immediately after login. |
| `ROSTER_URL` | Optional explicit roster page URL. |

### Important note about Firebase

The backend needs a Firebase service account to send FCM data pushes. The Android app already contains the client-side Firebase configuration, but the backend service account key should not be committed to this repository.

Use either:

- `FCM_SERVICE_ACCOUNT_FILE` with a mounted file on the Portainer host, or
- `FCM_SERVICE_ACCOUNT_JSON` as a stack environment value.

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
| `GET /debug` | Operator-facing HTML debug page. Optional `DEBUG_TOKEN` protection is supported. |
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
- authenticated mobile setup flow
- end-to-end SMS roundtrip using fake push and fake browser clients
- debug endpoint access control

Run them with:

```bash
pytest tests/test_storage.py tests/test_app_flow.py -q
```

## Current limitation

The backend already handles the remote login handshake and state management, but the actual roster extraction still uses generic HTML heuristics until real ONS page structure and live credentials are available. That means the authentication loop is in place, while the post-login scraping selectors will likely need one more tuning pass against the live page.
