# -*- coding: utf-8 -*-
"""Multi-token scopes for the central collector.

A single shared TRACE_TOKEN makes every holder an admin — fine for
one operator, wrong for a multi-user deployment (anyone with the
token sees everyone's conversations). Tokens instead carry a SCOPE:

- ``TRACE_TOKEN`` (unchanged): the admin token, unrestricted.
- ``TRACE_TOKENS_FILE``: a JSON map of per-user tokens::

      {
        "tok_alice_9f2c": {"name": "alice", "users": ["alice@wecom"]},
        "tok_shanghai_7d1": {"name": "上海机房", "instances": ["edge-shanghai-01"]},
        "tok_auditor_3e": {"name": "审计", "users": null, "instances": null}
      }

  ``users``/``instances`` are allow-lists matched against the session
  identity columns (channel user_id / instance_id); ``null`` or an
  omitted key means unrestricted for that dimension (both null =
  admin-equivalent). Ingest accepts any valid token — scopes gate
  READ access.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional, Set

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


@dataclass
class TokenStore:
    scopes: Dict[str, Scope] = field(default_factory=dict)

    def lookup(self, token: str) -> Optional[Scope]:
        return self.scopes.get(token)

    def __bool__(self) -> bool:
        return bool(self.scopes)

    @classmethod
    def from_env(cls, env) -> "TokenStore":
        scopes: Dict[str, Scope] = {}
        admin = (env.get("TRACE_TOKEN") or "").strip()
        if admin:
            scopes[admin] = Scope(name="admin")
        path = (env.get("TRACE_TOKENS_FILE") or "").strip()
        if path:
            try:
                raw = json.loads(Path(path).read_text(encoding="utf-8"))
            except (OSError, ValueError):
                logger.warning(
                    "agent-trace-server: unreadable TRACE_TOKENS_FILE %s"
                    " — per-user tokens disabled",
                    path,
                    exc_info=True,
                )
                raw = {}
            if isinstance(raw, dict):
                for token, spec in raw.items():
                    if not isinstance(token, str) or not token.strip():
                        continue
                    spec = spec if isinstance(spec, dict) else {}
                    users = _str_set(spec.get("users"))
                    instances = _str_set(spec.get("instances"))
                    scopes[token.strip()] = Scope(
                        name=str(spec.get("name") or ""),
                        users=users,
                        instances=instances,
                    )
        return cls(scopes=scopes)


def _str_set(value) -> Optional[frozenset]:
    if value is None:
        return None
    if isinstance(value, str):
        value = [value]
    if isinstance(value, list):
        items = {str(item).strip() for item in value if str(item).strip()}
        return frozenset(items) if items else None
    return None
