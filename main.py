import os
import re
import secrets
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

load_dotenv()

APP_NAME = os.getenv("APP_NAME", "Vaani API v1")
DATABASE_PATH = os.getenv("DATABASE_PATH", "data/vaani_api.db")
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "")
DOWNLOAD_DIR = Path(os.getenv("DOWNLOAD_DIR", "downloads"))
MAX_DOWNLOAD_MB = int(os.getenv("MAX_DOWNLOAD_MB", "100"))
DEFAULT_DAILY_LIMIT = int(os.getenv("DEFAULT_DAILY_LIMIT", "100"))
DOWNLOAD_DIR.mkdir(parents=True, exist_ok=True)
Path(DATABASE_PATH).parent.mkdir(parents=True, exist_ok=True)

app = FastAPI(title=APP_NAME, version="1.0.0",
              description="API-key management and authorized media processing starter API.")

def db():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS api_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                label TEXT NOT NULL,
                key_hash TEXT NOT NULL UNIQUE,
                key_prefix TEXT NOT NULL,
                daily_limit INTEGER NOT NULL,
                expires_at INTEGER,
                active INTEGER NOT NULL DEFAULT 1,
                created_at INTEGER NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS usage (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_id INTEGER NOT NULL,
                day TEXT NOT NULL,
                request_count INTEGER NOT NULL DEFAULT 0,
                UNIQUE(key_id, day),
                FOREIGN KEY(key_id) REFERENCES api_keys(id)
            )
        """)

init_db()

def hash_key(key: str) -> str:
    # Hash keys at rest; the plaintext key is shown only once when created.
    import hashlib
    return hashlib.sha256(key.encode("utf-8")).hexdigest()

def require_admin(x_admin_token: Optional[str] = Header(default=None)):
    if not ADMIN_TOKEN:
        raise HTTPException(503, "Admin API is disabled: set ADMIN_TOKEN in .env")
    if not x_admin_token or not secrets.compare_digest(x_admin_token, ADMIN_TOKEN):
        raise HTTPException(401, "Invalid admin token")

def authenticate_key(api_key: str = Query(..., min_length=12)):
    key_hash = hash_key(api_key)
    with db() as conn:
        row = conn.execute("SELECT * FROM api_keys WHERE key_hash=?", (key_hash,)).fetchone()
        if not row or not row["active"]:
            raise HTTPException(401, "Invalid or revoked API key")
        now = int(time.time())
        if row["expires_at"] is not None and row["expires_at"] <= now:
            raise HTTPException(401, "API key has expired")
        day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        usage = conn.execute("SELECT request_count FROM usage WHERE key_id=? AND day=?",
                             (row["id"], day)).fetchone()
        count = usage["request_count"] if usage else 0
        if count >= row["daily_limit"]:
            raise HTTPException(429, "Daily API request limit reached")
        conn.execute("""
            INSERT INTO usage(key_id, day, request_count) VALUES(?,?,1)
            ON CONFLICT(key_id, day) DO UPDATE SET request_count=request_count+1
        """, (row["id"], day))
    return {"id": row["id"], "label": row["label"], "daily_limit": row["daily_limit"]}

class CreateKeyRequest(BaseModel):
    label: str = Field(default="user", min_length=1, max_length=80)
    daily_limit: int = Field(default=DEFAULT_DAILY_LIMIT, ge=1, le=100000)
    expires_in_days: Optional[int] = Field(default=30, ge=1, le=3650)

class RevokeKeyRequest(BaseModel):
    key_id: int = Field(ge=1)

@app.get("/")
def root():
    return {"service": APP_NAME, "status": "online", "docs": "/docs",
            "note": "Only process media you own or are authorized to download."}

@app.get("/health")
def health():
    return {"status": "ok", "time_utc": datetime.now(timezone.utc).isoformat()}

@app.post("/admin/keys", dependencies=[Depends(require_admin)])
def create_key(payload: CreateKeyRequest):
    raw_key = "VANI_" + secrets.token_urlsafe(32)
    now = int(time.time())
    expires_at = now + payload.expires_in_days * 86400 if payload.expires_in_days else None
    with db() as conn:
        cur = conn.execute("""
            INSERT INTO api_keys(label,key_hash,key_prefix,daily_limit,expires_at,active,created_at)
            VALUES(?,?,?,?,?,1,?)
        """, (payload.label, hash_key(raw_key), raw_key[:10], payload.daily_limit, expires_at, now))
        key_id = cur.lastrowid
    return {
        "id": key_id, "label": payload.label, "api_key": raw_key,
        "daily_limit": payload.daily_limit, "expires_at_utc":
        datetime.fromtimestamp(expires_at, timezone.utc).isoformat() if expires_at else None,
        "warning": "Copy this key now. It cannot be retrieved later."
    }

@app.get("/admin/keys", dependencies=[Depends(require_admin)])
def list_keys():
    with db() as conn:
        rows = conn.execute("""
            SELECT id,label,key_prefix,daily_limit,expires_at,active,created_at
            FROM api_keys ORDER BY id DESC
        """).fetchall()
    return {"keys": [dict(r) for r in rows]}

@app.post("/admin/keys/{key_id}/revoke", dependencies=[Depends(require_admin)])
def revoke_key(key_id: int):
    with db() as conn:
        cur = conn.execute("UPDATE api_keys SET active=0 WHERE id=?", (key_id,))
    if cur.rowcount == 0:
        raise HTTPException(404, "API key not found")
    return {"ok": True, "revoked_key_id": key_id}

@app.get("/me")
def my_usage(auth=Depends(authenticate_key), api_key: str = Query(...)):
    day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    with db() as conn:
        row = conn.execute("SELECT request_count FROM usage WHERE key_id=? AND day=?",
                           (auth["id"], day)).fetchone()
    used = row["request_count"] if row else 0
    return {"label": auth["label"], "daily_limit": auth["daily_limit"],
            "used_today_utc": used, "remaining_today": max(0, auth["daily_limit"]-used)}

def validate_youtube_url(url: str):
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    allowed = {"youtube.com", "www.youtube.com", "m.youtube.com", "youtu.be", "music.youtube.com"}
    if parsed.scheme != "https" or host not in allowed:
        raise HTTPException(400, "Only HTTPS YouTube URLs are accepted.")
    return url

@app.get("/download")
def download_media(
    url: str = Query(..., description="HTTPS URL for media you own or are authorized to download"),
    media_type: str = Query("audio", alias="type", pattern="^(audio|video)$"),
    auth=Depends(authenticate_key),
    api_key: str = Query(...)
):
    validate_youtube_url(url)
    # Keep download processing isolated and bounded. yt-dlp is optional until installed.
    try:
        import yt_dlp
    except ImportError:
        raise HTTPException(503, "Downloader dependency unavailable. Install requirements.txt.")
    outtmpl = str(DOWNLOAD_DIR / f"{secrets.token_hex(12)}.%(ext)s")
    opts = {
        "format": "bestaudio/best" if media_type == "audio" else "best[height<=720]/best",
        "outtmpl": outtmpl,
        "noplaylist": True,
        "quiet": True,
        "no_warnings": True,
        "max_filesize": MAX_DOWNLOAD_MB * 1024 * 1024,
        "restrictfilenames": True,
        "socket_timeout": 20,
    }
    try:
        with yt_dlp.YoutubeDL(opts) as ydl:
            info = ydl.extract_info(url, download=True)
            filename = Path(ydl.prepare_filename(info))
            if not filename.exists():
                # yt-dlp may choose a post-processed extension.
                candidates = list(DOWNLOAD_DIR.glob(filename.stem + ".*"))
                if candidates:
                    filename = candidates[0]
            if not filename.exists():
                raise HTTPException(502, "Media processing finished but output file was not found.")
            if filename.stat().st_size > MAX_DOWNLOAD_MB * 1024 * 1024:
                filename.unlink(missing_ok=True)
                raise HTTPException(413, "Output exceeded configured size limit.")
            media_title = re.sub(r"[\r\n]", " ", info.get("title", "media"))[:150]
            response_media_type = "audio/mpeg" if media_type == "audio" else "application/octet-stream"
            return FileResponse(
                path=filename, filename=filename.name, media_type=response_media_type,
                headers={"X-Media-Title": media_title, "X-API-Service": "Vaani"}
            )
    except HTTPException:
        raise
    except Exception as exc:
        # Avoid returning internal stack traces or secrets to API clients.
        raise HTTPException(502, f"Media processing failed: {type(exc).__name__}") from None
