# NexaShield — Phase 1 Foundation

Phase 1 establishes a testable FastAPI backend, secure configuration, MongoDB Atlas connectivity, and automated tests.

## Requirements
- Python 3.11 or 3.12
- Git (recommended)
- MongoDB Atlas account (optional for local tests; required to verify live DB connectivity)

## Setup

### Windows PowerShell
```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
Copy-Item .env.example .env
```

If PowerShell blocks activation, use:
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

### macOS / Linux / cloud terminal
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
cp .env.example .env
```

## Configure MongoDB Atlas
1. Create a free cluster in MongoDB Atlas.
2. Create a database user with a strong password.
3. In Network Access, allow your cloud development environment's outbound IP. Avoid `0.0.0.0/0` except as a temporary, tightly controlled test setting; remove it afterward.
4. Copy the Python driver connection string from Atlas.
5. Put it in `.env` as `MONGODB_URI=...`. URL-encode special characters in the username/password if needed.
6. Do not commit `.env`.

The application does not require MongoDB for the health endpoint or unit tests. Live connectivity is checked through `GET /health/db`.

## Run the API
```bash
uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000
```
Open:
- http://127.0.0.1:8000/health
- http://127.0.0.1:8000/health/db
- http://127.0.0.1:8000/docs

For a cloud IDE, use its port-forwarding/preview feature for port `8000`. Bind to `0.0.0.0` only when required by that environment:
```bash
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
```

## Verify Phase 1
```bash
pytest -q
```
Expected: all tests pass. The database connectivity test is deliberately not part of the default test suite because it requires a configured Atlas account and network access.

## Test live database connectivity
After configuring `.env` and starting the server:
```bash
curl http://127.0.0.1:8000/health/db
```
PowerShell alternative:
```powershell
Invoke-RestMethod http://127.0.0.1:8000/health/db
```
Expected on success:
```json
{"status":"ok","database":"connected"}
```

If `MONGODB_URI` is missing, the endpoint returns a service-unavailable response with a safe error message. It never returns credentials.

## Security notes
- Never commit `.env`, credentials, tokens, or real user prompts.
- The health endpoint does not reveal environment values.
- Database errors are logged without printing the connection URI.
- Later phases should store redacted audit data, not raw secrets.
