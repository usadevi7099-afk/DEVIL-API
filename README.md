# Vaani API v1

A FastAPI starter project with private API-key generation, daily request limits, expiry, revocation, SQLite storage, and an authorized-media download endpoint.

## Important
- Use the downloader only for content you own or have permission to download, and follow the platform's terms and applicable law.
- This starter is not a managed public service. You are responsible for hosting, security, abuse prevention, costs, and monitoring.
- Put the admin token in an environment variable. Never commit `.env` or share admin credentials.
- The `/download` route returns the media file in the response. Files are retained in `downloads/`; set up a cleanup policy before production.
- For a public API, put it behind HTTPS (for example, a VPS plus Caddy/Nginx) and add rate limiting at the proxy/firewall level.

## Run locally (Android/Termux or computer)

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Edit `.env` and set a long random `ADMIN_TOKEN`. Then run:

```bash
uvicorn main:app --host 0.0.0.0 --port 8000
```

Open `http://127.0.0.1:8000/docs` on the same device.

## Create an API key

Send a POST request to `/admin/keys` with header `X-Admin-Token` set to your admin token and JSON body:

```json
{
  "label": "Vaani test user",
  "daily_limit": 100,
  "expires_in_days": 30
}
```

Example with curl:

```bash
curl -X POST http://127.0.0.1:8000/admin/keys \
  -H "X-Admin-Token: YOUR_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"label":"Vaani test user","daily_limit":100,"expires_in_days":30}'
```

The response includes `api_key` once. Save it securely; only a hash is stored in the database.

## Use the API

Health check:

```text
GET /health
```

Usage status:

```text
GET /me?api_key=YOUR_API_KEY
```

Authorized YouTube media download:

```text
GET /download?url=https%3A%2F%2Fwww.youtube.com%2Fwatch%3Fv%3DVIDEO_ID&type=audio&api_key=YOUR_API_KEY
```

Use `type=video` for video. Depending on the source and chosen format, additional media-processing tools may be needed. The route accepts YouTube URLs only.

## Revoke a key

```bash
curl -X POST http://127.0.0.1:8000/admin/keys/1/revoke \
  -H "X-Admin-Token: YOUR_ADMIN_TOKEN"
```

List keys (keys are shown as prefixes only):

```bash
curl http://127.0.0.1:8000/admin/keys -H "X-Admin-Token: YOUR_ADMIN_TOKEN"
```

## Docker

```bash
cp .env.example .env
# Edit .env and set ADMIN_TOKEN
docker compose up -d --build
```

## Before production
1. Configure a real domain and HTTPS reverse proxy.
2. Restrict `/admin/*` to trusted IPs if possible.
3. Add request-rate limiting, logging/monitoring, disk cleanup, backups, and abuse controls.
4. Consider PostgreSQL for multiple workers/instances; SQLite is for a small starter deployment.
5. Never put your admin token or API keys in public GitHub repositories.
