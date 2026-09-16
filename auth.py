# -*- coding: utf-8 -*-
"""Multi-token scopes for the central collector.

A single shared TRACE_TOKEN makes every holder an admin — fine for
one operator, wrong for a multi-user deployment (anyone with the
token sees everyone's conversations). Tokens instead carry a SCOPE:

- ``TRACE_TOKEN`` (unchanged): the admin token, unrestricted.
- ``TRACE_TOKENS_FILE``: a JSON map seeding per-user tokens on
  startup::

      {
        "tok_alice_9f2c": {"name": "alice", "users": ["alice@wecom"]},
        "tok_shanghai_7d1": {"name": "上海机房", "instances": ["edge-shanghai-01"]},
        "tok_auditor_3e": {"name": "审计", "users": null, "instances": null}
      }

  ``users``/``instances`` are allow-lists matched against the session
  identity columns (channel user_id / instance_id); ``null`` or an
  omitted key means unrestricted for that dimension (both null =
  admin-equivalent). The file only SEEDS the ``tokens`` table — once
  running, the admin console (POST /api/agent-trace/admin/tokens) is
  the source of truth and issue/revoke take effect immediately.
  Ingest accepts any valid token — scopes gate READ access.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import json

logger = logging.getLogger("agent-trace-server")


@dataclass(frozen=True)
class Scope:
    """What a token is allowed to see. ``None`` = unrestricted."""

    name: str = ""
    users: Optional[frozenset] = None
    instances: Optional[frozenset] = None

    @property
    def unrestricted(self) -> bool:
        return self.users is None and self.instances is None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name or "admin",
            "restricted": not self.unrestricted,
            "users": sorted(self.users) if self.users is not None else None,
            "instances": (
                sorted(self.instances)
                if self.instances is not None
                else None
            ),
        }

    def can_view(self, *, user_id, instance_id) -> bool:
        if self.unrestricted:
            return True
        if self.users is not None:
            if not user_id or user_id not in self.users:
                return False
        if self.instances is not None:
            if not instance_id or instance_id not in self.instances:
                return False
        return True


class TokenStore:
    """Live token registry: the env admin token plus the ``tokens``
    table. Lookups hit the DB on every request so admin-console
    issue/revoke apply without a restart."""

    def __init__(self, db: Any, admin_token: str = "") -> None:
        self.db = db
        self.admin_token = admin_token

    @classmethod
    def from_env(cls, env, db: Any) -> "TokenStore":
        admin = (env.get("TRACE_TOKEN") or "").strip()
        store = cls(db=db, admin_token=admin)
        store.seed_from_env(env)
        return store

    def seed_from_env(self, env) -> None:
        """Import TRACE_TOKENS_FILE entries that don't exist yet.
        Existing rows keep their DB state (console edits win)."""
        for token, scope in parse_tokens_file(env).items():
            self.db.insert_token(
                token,
                scope.name,
                _sorted_list(scope.users),
                _sorted_list(scope.instances),
            )

    def lookup(self, token: str) -> Optional[Scope]:
        if not token:
            return None
        if self.admin_token and token == self.admin_token:
            return Scope(name="admin")
        row = self.db.lookup_token(token)
        if row is None:
            return None
        return Scope(
            name=row["name"],
            users=(
                frozenset(row["users"])
                if row["users"] is not None
                else None
            ),
            instances=(
                frozenset(row["instances"])
                if row["instances"] is not None
                else None
            ),
        )

    @property
    def auth_enabled(self) -> bool:
        """Auth is required once any credential exists: the env admin
        token or at least one active DB token."""
        return bool(self.admin_token) or self.db.count_active_tokens() > 0

    def token_count(self) -> int:
        """Active DB tokens (admin console status line)."""
        return self.db.count_active_tokens()


def parse_tokens_file(env) -> Dict[str, Scope]:
    """Read TRACE_TOKENS_FILE into {token: Scope}; unreadable or
    malformed files yield {} with a warning (admin token unaffected)."""
    path = (env.get("TRACE_TOKENS_FILE") or "").strip()
    if not path:
        return {}
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        logger.warning(
            "agent-trace-server: unreadable TRACE_TOKENS_FILE %s"
            " — per-user tokens disabled",
            path,
            exc_info=True,
        )
        return {}
    if not isinstance(raw, dict):
        return {}
    scopes: Dict[str, Scope] = {}
    for token, spec in raw.items():
        if not isinstance(token, str) or not token.strip():
            continue
        spec = spec if isinstance(spec, dict) else {}
        scopes[token.strip()] = Scope(
            name=str(spec.get("name") or ""),
            users=_str_set(spec.get("users")),
            instances=_str_set(spec.get("instances")),
        )
    return scopes


def _str_set(value) -> Optional[frozenset]:
    """Coerce a spec value to an allow-list; null/empty → None
    (unrestricted for that dimension)."""
    if value is None:
        return None
    if isinstance(value, str):
        value = [value]
    if isinstance(value, list):
        items = {str(item).strip() for item in value if str(item).strip()}
        return frozenset(items) if items else None
    return None


def _sorted_list(value: Optional[frozenset]) -> Optional[List[str]]:
    return sorted(value) if value is not None else None
