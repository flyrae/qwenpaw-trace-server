# -*- coding: utf-8 -*-
"""Central trace collector: ingest from agent-trace shippers + the
plugin's read-API contract + a standalone UI mount.

Run:
    TRACE_DB=./traces.db uvicorn app:app --port 8790

Environment:
    TRACE_DB     SQLite path (default: <repo>/server/traces.db)
    TRACE_TOKEN  admin token; when set, all endpoints require
                 `Authorization: Bearer <token>`; when unset the
                 server is open (private network / gateway auth)
    TRACE_TOKENS_FILE  JSON map seeding per-user tokens with
                 user/instance read scopes (see auth.py); it only
                 seeds the DB — afterwards the admin console
                 (POST /api/agent-trace/admin/tokens) is the source
                 of truth and issue/revoke apply immediately.
                 Ingest accepts any valid token, reads are filtered
                 by scope
    TRACE_BASE_PATH  mount everything under a URL prefix, e.g.
                 /agent-trace for reverse-proxy deployments that
                 route several services off one host. Every path
                 (/ingest /enroll /healthz /api/... /trace /) moves
                 under it; edges set remote_url to
                 http://host/agent-trace unchanged.
    TRACE_UI_DIR static UI directory (default: <repo>/server/ui)
"""
from __future__ import annotations

import gzip
import json
import logging
import os
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from auth import Scope, TokenStore
from storage import TraceDatabase

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("agent-trace-server")

SERVER_ROOT = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("TRACE_DB") or SERVER_ROOT / "traces.db")
UI_DIR = Path(os.environ.get("TRACE_UI_DIR") or SERVER_ROOT / "ui")


def _normalize_base_path(raw: str) -> str:
    """'' or '/agent-trace' — leading slash, no trailing slash."""
    value = (raw or "").strip().rstrip("/")
    if value and not value.startswith("/"):
        value = "/" + value
    return value


BASE_PATH = _normalize_base_path(
    os.environ.get("TRACE_BASE_PATH") or ""
)

MAX_BATCH_EVENTS = 50_000

app = FastAPI(title="agent-trace collector", version="0.7.4")
db = TraceDatabase(DB_PATH)
tokens = TokenStore.from_env(os.environ, db)
logger.info(
    "agent-trace server: admin token %s, %d active client token(s)",
    "set" if tokens.admin_token else "unset (open mode)",
    tokens.token_count(),
)
if BASE_PATH:
    logger.info(
        "agent-trace server: mounted under base path %s", BASE_PATH
    )

# Standalone-UI deployments serve the bundle from another origin;
# same-origin (default) works without CORS too.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# Path building blocks under the optional TRACE_BASE_PATH prefix.
API = f"{BASE_PATH}/api/agent-trace"
ADMIN = f"{API}/admin"


@app.middleware("http")
async def auth_guard(request: Request, call_next):
    if tokens.auth_enabled and request.url.path != f"{BASE_PATH}/enroll":
        path = request.url.path
        public = (
            path == f"{BASE_PATH}/healthz"
            or path == BASE_PATH
            or path == f"{BASE_PATH}/"
            or path == f"{BASE_PATH}/index.html"
            or path == f"{BASE_PATH}/favicon.ico"
            or path.startswith(f"{BASE_PATH}/trace")
        )
        if not public:
            header = request.headers.get("Authorization") or ""
            supplied = header[7:].strip() if header.startswith(
                "Bearer "
            ) else ""
            scope = tokens.lookup(supplied)
            if scope is None:
                return PlainTextResponse("unauthorized", status_code=401)
            request.state.scope = scope
    return await call_next(request)


def _scope(request: Request) -> Scope:
    """Token scope of the current request (unrestricted when the
    server runs without tokens)."""
    return getattr(request.state, "scope", Scope())


@app.get(f"{BASE_PATH}/healthz")
async def healthz() -> Dict[str, Any]:
    return {
        "status": "ok",
        "instances": len(db.list_instances()),
        "sessions": db.count_sessions(),
    }


# ----------------------------------------------------------------------
# Ingest
# ----------------------------------------------------------------------


async def _read_body(request: Request) -> bytes:
    body = await request.body()
    if request.headers.get("Content-Encoding") == "gzip":
        try:
            body = gzip.decompress(body)
        except OSError as exc:
            raise HTTPException(400, f"bad gzip body: {exc}") from exc
    return body


@app.post(f"{BASE_PATH}/ingest")
async def ingest(request: Request) -> Dict[str, Any]:
    body = await _read_body(request)
    try:
        envelope = json.loads(body)
    except ValueError as exc:
        raise HTTPException(400, f"invalid json: {exc}") from exc
    if not isinstance(envelope, dict):
        raise HTTPException(400, "envelope must be an object")
    instance = envelope.get("instance")
    events = envelope.get("events")
    if not isinstance(instance, dict) or not isinstance(events, list):
        raise HTTPException(400, "envelope requires instance + events")
    if len(events) > MAX_BATCH_EVENTS:
        raise HTTPException(413, "batch too large")
    result = db.ingest(instance, events)
    return result


# ----------------------------------------------------------------------
# Enrollment — edge instances self-register with an admin-issued
# bootstrap key and receive an instance-scoped token (least
# privilege). Re-enrolling an instance rotates its token: the old
# one dies, so a lost edge credential is recovered by re-enrolling.
# ----------------------------------------------------------------------


def _bearer(request: Request) -> str:
    header = request.headers.get("Authorization") or ""
    return header[7:].strip() if header.startswith("Bearer ") else ""


@app.post(f"{BASE_PATH}/enroll")
async def enroll(request: Request) -> Dict[str, Any]:
    key_row = db.get_valid_enroll_key(_bearer(request))
    if key_row is None:
        raise HTTPException(401, "invalid, expired, or exhausted key")
    try:
        body = json.loads(await request.body())
    except ValueError as exc:
        raise HTTPException(400, f"invalid json: {exc}") from exc
    if not isinstance(body, dict):
        raise HTTPException(400, "body must be an object")
    instance_id = str(body.get("instance_id") or "").strip()
    if not instance_id or len(instance_id) > 200:
        raise HTTPException(400, "instance_id required (<= 200 chars)")
    db.revoke_enrolled_tokens(instance_id)
    token = "tok_" + secrets.token_urlsafe(24)
    row_id = db.insert_token(
        token,
        name=instance_id,
        users=None,
        instances=[instance_id],
        source="enroll",
    )
    if row_id is None:  # pragma: no cover — 192-bit random collision
        raise HTTPException(500, "token collision, retry")
    db.consume_enroll_use(key_row["id"])
    return {
        "token": token,
        "name": instance_id,
        "instances": [instance_id],
    }


# ----------------------------------------------------------------------
# Read API — the plugin router contract (mounted under /api/agent-trace)
# ----------------------------------------------------------------------


def _session_or_404(
    session_id: str,
    instance: Optional[str],
    scope: Scope,
):
    row = db.resolve_session(session_id, instance)
    if row is None:
        raise HTTPException(404, "not found")
    if not scope.can_view(
        user_id=row["user_id"],
        instance_id=row["instance_id"],
    ):
        # 404 (not 403): scoped tokens must not learn that the
        # session exists at all.
        raise HTTPException(404, "not found")
    return row


@app.get(f"{API}/sessions")
async def list_sessions(
    request: Request,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    instance: Optional[str] = Query(default=None),
    user: Optional[str] = Query(default=None),
    q: Optional[str] = Query(default=None),
) -> Dict[str, Any]:
    scope = _scope(request)
    sessions = db.list_sessions(
        instance=instance,
        user=user,
        q=q,
        limit=limit,
        offset=offset,
        scope=scope,
    )
    total = db.count_sessions(
        instance=instance, user=user, q=q, scope=scope
    )
    return {
        "sessions": sessions,
        "total": total,
        "offset": offset,
        "has_more": offset + len(sessions) < total,
    }


@app.get(f"{API}/whoami")
async def whoami(request: Request) -> Dict[str, Any]:
    """Identity + scope of the current token (portal header)."""
    return _scope(request).to_dict()


# ----------------------------------------------------------------------
# Admin API — token issuance (unrestricted tokens only; scoped tokens
# get 404 so the surface itself stays unknown)
# ----------------------------------------------------------------------


class TokenCreate(BaseModel):
    name: str
    users: Optional[List[str]] = None
    instances: Optional[List[str]] = None


class EnrollKeyCreate(BaseModel):
    name: str
    max_uses: Optional[int] = None
    expires_days: Optional[int] = None


def _require_admin(request: Request) -> None:
    if not _scope(request).unrestricted:
        raise HTTPException(404, "not found")


def _mask_token(token: str) -> str:
    if len(token) <= 16:
        return token[:8] + "…"
    return f"{token[:12]}…{token[-4:]}"


def _clean_allow_list(value: Optional[List[str]]) -> Optional[List[str]]:
    """Strip blanks; an empty list means unrestricted, not "nothing"."""
    if value is None:
        return None
    items = [str(item).strip() for item in value if str(item).strip()]
    return items or None


@app.get(f"{ADMIN}/tokens")
async def admin_list_tokens(request: Request) -> Dict[str, Any]:
    _require_admin(request)
    return {
        "admin_env": bool(tokens.admin_token),
        "tokens": [
            {
                "id": row["id"],
                "token": _mask_token(row["token"]),
                "name": row["name"],
                "users": row["users"],
                "instances": row["instances"],
                "unrestricted": (
                    row["users"] is None and row["instances"] is None
                ),
                "revoked": row["revoked"],
                "created_at": row["created_at"],
                "source": row["source"],
            }
            for row in db.list_tokens()
        ],
    }


@app.post(
    f"{ADMIN}/tokens",
    status_code=201,
)
async def admin_create_token(
    request: Request, spec: TokenCreate
) -> Dict[str, Any]:
    """Issue a client token. The plaintext token is returned exactly
    once — later views only show a masked form."""
    _require_admin(request)
    name = spec.name.strip()
    if not name:
        raise HTTPException(422, "name is required")
    users = _clean_allow_list(spec.users)
    instances = _clean_allow_list(spec.instances)
    token = "tok_" + secrets.token_urlsafe(24)
    row_id = db.insert_token(token, name, users, instances)
    if row_id is None:  # pragma: no cover — 192-bit random collision
        raise HTTPException(500, "token collision, retry")
    return {
        "id": row_id,
        "token": token,
        "name": name,
        "users": users,
        "instances": instances,
    }


@app.delete(f"{ADMIN}/tokens/{{token_id}}")
async def admin_revoke_token(
    request: Request, token_id: int
) -> Dict[str, Any]:
    """Revoke by row id; effective on the very next request."""
    _require_admin(request)
    if not db.token_exists(token_id):
        raise HTTPException(404, "not found")
    db.revoke_token(token_id)
    return {"ok": True}


# ----------------------------------------------------------------------
# Admin API — enrollment keys (bootstrap credentials for /enroll)
# ----------------------------------------------------------------------


@app.get(f"{ADMIN}/enroll-keys")
async def admin_list_enroll_keys(request: Request) -> Dict[str, Any]:
    _require_admin(request)
    return {
        "enroll_keys": [
            {
                "id": row["id"],
                "key": _mask_token(row["key"]),
                "name": row["name"],
                "max_uses": row["max_uses"],
                "uses": row["uses"],
                "expires_at": row["expires_at"],
                "revoked": bool(row["revoked"]),
                "created_at": row["created_at"],
            }
            for row in db.list_enroll_keys()
        ],
    }


@app.post(
    f"{ADMIN}/enroll-keys",
    status_code=201,
)
async def admin_create_enroll_key(
    request: Request, spec: EnrollKeyCreate
) -> Dict[str, Any]:
    """Issue an enrollment key. The plaintext key is returned
    exactly once; distribute it to edge instances (config
    remote_enroll_key) instead of per-machine tokens."""
    _require_admin(request)
    name = spec.name.strip()
    if not name:
        raise HTTPException(422, "name is required")
    if spec.max_uses is not None and spec.max_uses < 1:
        raise HTTPException(422, "max_uses must be >= 1")
    if spec.expires_days is not None and spec.expires_days < 1:
        raise HTTPException(422, "expires_days must be >= 1")
    expires_at = (
        (
            datetime.now(timezone.utc) + timedelta(days=spec.expires_days)
        ).isoformat(timespec="seconds")
        if spec.expires_days
        else None
    )
    key = "enroll_" + secrets.token_urlsafe(24)
    row_id = db.insert_enroll_key(key, name, spec.max_uses, expires_at)
    if row_id is None:  # pragma: no cover — 192-bit random collision
        raise HTTPException(500, "key collision, retry")
    return {
        "id": row_id,
        "key": key,
        "name": name,
        "max_uses": spec.max_uses,
        "expires_at": expires_at,
    }


@app.delete(f"{ADMIN}/enroll-keys/{{key_id}}")
async def admin_revoke_enroll_key(
    request: Request, key_id: int
) -> Dict[str, Any]:
    """Revoke a bootstrap key; further /enroll calls with it 401.
    Tokens already issued through it keep working."""
    _require_admin(request)
    if not db.enroll_key_exists(key_id):
        raise HTTPException(404, "not found")
    db.revoke_enroll_key(key_id)
    return {"ok": True}


@app.get(f"{API}/instances")
async def list_instances(request: Request) -> Dict[str, Any]:
    return {"instances": db.list_instances(scope=_scope(request))}


@app.get(f"{API}/overview")
async def overview(request: Request) -> Dict[str, Any]:
    """Landing-page aggregate for the portal, scoped to the token."""
    return db.overview(scope=_scope(request))


@app.get(f"{API}/sessions/{{session_id}}")
async def get_session(
    request: Request,
    session_id: str,
    before_seq: Optional[int] = Query(default=None, ge=1),
    limit: int = Query(default=200, ge=1, le=2000),
    type: Optional[str] = Query(default=None),
    q: Optional[str] = Query(default=None),
    instance: Optional[str] = Query(default=None),
) -> Dict[str, Any]:
    row = _session_or_404(session_id, instance, _scope(request))
    events = db.list_events(
        row["instance_id"],
        session_id,
        before_seq=before_seq,
        type_filter=type,
        q=q,
        limit=limit,
    )
    try:
        header = json.loads(row["header"]) if row["header"] else None
    except ValueError:
        header = None
    return {
        "header": header,
        "events": events,
        "total_events": row["event_count"],
        "size_bytes": 0,
        "mtime": 0,
        "instance_id": row["instance_id"],
    }


@app.get(f"{API}/sessions/{{session_id}}/stats")
async def get_session_stats(
    request: Request,
    session_id: str,
    instance: Optional[str] = Query(default=None),
) -> Dict[str, Any]:
    row = _session_or_404(session_id, instance, _scope(request))
    stats = db.stats(row["instance_id"], session_id)
    if stats is None:
        raise HTTPException(404, "not found")
    return stats


@app.get(f"{API}/sessions/{{session_id}}/export")
async def export_session(
    request: Request,
    session_id: str,
    instance: Optional[str] = Query(default=None),
) -> Response:
    row = _session_or_404(session_id, instance, _scope(request))
    try:
        header = json.loads(row["header"]) if row["header"] else None
    except ValueError:
        header = None
    lines = []
    if header:
        lines.append(json.dumps(header, ensure_ascii=False, default=str))
    for event in db.all_events(row["instance_id"], session_id):
        record = {k: v for k, v in event.items() if k != "session_id"}
        lines.append(json.dumps(record, ensure_ascii=False, default=str))
    return Response(
        "\n".join(lines) + "\n",
        media_type="application/x-ndjson",
        headers={
            "Content-Disposition": (
                f'attachment; filename="{session_id}.jsonl"'
            ),
        },
    )


# ----------------------------------------------------------------------
# Static mounts: "/" is the enterprise portal (dashboard + login gate),
# "/trace" is the trajectory viewer shell (same Console bundle).
# ----------------------------------------------------------------------

PORTAL_DIR = Path(
    os.environ.get("TRACE_PORTAL_DIR") or SERVER_ROOT / "portal",
)

# Mount order matters: "/trace" must register before the catch-all "/".
if UI_DIR.exists():
    app.mount(
        f"{BASE_PATH}/trace",
        StaticFiles(directory=UI_DIR, html=True),
        name="ui",
    )
else:
    logger.info(
        "agent-trace server: no UI directory at %s (trace viewer off)",
        UI_DIR,
    )

if PORTAL_DIR.exists():
    app.mount(
        BASE_PATH or "/",
        StaticFiles(directory=PORTAL_DIR, html=True),
        name="portal",
    )
elif UI_DIR.exists():
    app.mount(
        BASE_PATH or "/",
        StaticFiles(directory=UI_DIR, html=True),
        name="ui",
    )
else:
    logger.info(
        "agent-trace server: no static directories under %s (API-only)",
        SERVER_ROOT,
    )
