# -*- coding: utf-8 -*-
"""Multi-token scope isolation (TRACE_TOKEN + TRACE_TOKENS_FILE).

A restricted token must never observe sessions outside its
user/instance allow-list: not in listings, not in aggregates, and
cross-scope detail requests must 404 (not 403) so the existence of
other users' sessions stays unknown. Admin (TRACE_TOKEN) and open
servers stay unrestricted; ingest accepts any valid token.
"""
from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

SERVER_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SERVER_DIR))

ADMIN = "tok-admin"
ALICE = "tok-alice"  # users: ["alice@wecom"]
SH = "tok-sh"  # instances: ["inst-sh"]
BOB_ON_A = "tok-bob-a"  # users: ["bob"] AND instances: ["inst-a"]

TOKENS = {
    ALICE: {"name": "alice", "users": ["alice@wecom"]},
    SH: {"name": "上海机房", "instances": ["inst-sh"]},
    BOB_ON_A: {"name": "bob", "users": ["bob"], "instances": ["inst-a"]},
}


def _fresh_app():
    for name, module in list(sys.modules.items()):
        file = getattr(module, "__file__", "")
        if file and str(SERVER_DIR) in str(file):
            del sys.modules[name]
    import app as app_module

    return importlib.reload(app_module)


def _event(seq, event_type, data=None, session="sess-1"):
    return {
        "session_id": session,
        "seq": seq,
        "t": f"2026-09-16T00:00:{seq % 60:02d}.000+00:00",
        "type": event_type,
        "run_id": "r1",
        "data": data or {},
    }


def _batch(instance_id, events):
    return {
        "schema_version": 1,
        "instance": {
            "instance_id": instance_id,
            "hostname": f"host-{instance_id}",
            "plugin_version": "0.7.0",
        },
        "events": events,
    }


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture()
def scoped(tmp_path, monkeypatch):
    tokens_file = tmp_path / "tokens.json"
    tokens_file.write_text(
        json.dumps(TOKENS, ensure_ascii=False), encoding="utf-8"
    )
    monkeypatch.setenv("TRACE_DB", str(tmp_path / "traces.db"))
    monkeypatch.setenv("TRACE_TOKEN", ADMIN)
    monkeypatch.setenv("TRACE_TOKENS_FILE", str(tokens_file))
    app_module = _fresh_app()
    with TestClient(app_module.app) as client:
        # Seed: two instances, four sessions.
        #   inst-a: alice's chat, bob's chat, a console chat (no user)
        #   inst-sh: carol's chat
        client.post(
            "/ingest",
            json=_batch(
                "inst-a",
                [
                    _event(
                        1,
                        "message/inbound",
                        {"user_id": "alice@wecom", "text": "alice 的会话"},
                        session="sess-alice",
                    ),
                    _event(
                        2,
                        "message/inbound",
                        {"user_id": "bob", "text": "bob 的会话"},
                        session="sess-bob",
                    ),
                    _event(
                        1,
                        "run/start",
                        {"channel": "console"},
                        session="sess-console",
                    ),
                ],
            ),
            headers=_auth(ADMIN),
        )
        client.post(
            "/ingest",
            json=_batch(
                "inst-sh",
                [
                    _event(
                        1,
                        "message/inbound",
                        {"user_id": "carol@wecom", "text": "carol 的会话"},
                        session="sess-carol",
                    ),
                ],
            ),
            headers=_auth(ADMIN),
        )
        yield client


def _session_ids(client, token):
    resp = client.get("/api/agent-trace/sessions", headers=_auth(token))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    return {s["session_id"] for s in body["sessions"]}, body["total"]


class TestListIsolation:
    def test_admin_sees_everything(self, scoped):
        ids, total = _session_ids(scoped, ADMIN)
        assert ids == {"sess-alice", "sess-bob", "sess-console",
                       "sess-carol"}
        assert total == 4
        instances = scoped.get(
            "/api/agent-trace/instances", headers=_auth(ADMIN)
        ).json()["instances"]
        assert {i["instance_id"] for i in instances} == {
            "inst-a",
            "inst-sh",
        }

    def test_user_token_sees_only_own_sessions(self, scoped):
        ids, total = _session_ids(scoped, ALICE)
        assert ids == {"sess-alice"}
        assert total == 1

    def test_user_token_cannot_see_console_sessions(self, scoped):
        # sess-console has no user_id; a user-scoped token has no
        # way to match it, so it must stay invisible.
        ids, _ = _session_ids(scoped, ALICE)
        assert "sess-console" not in ids

    def test_instance_token_scope(self, scoped):
        ids, total = _session_ids(scoped, SH)
        assert ids == {"sess-carol"}
        assert total == 1
        instances = scoped.get(
            "/api/agent-trace/instances", headers=_auth(SH)
        ).json()["instances"]
        assert {i["instance_id"] for i in instances} == {"inst-sh"}

    def test_combined_user_and_instance_scope(self, scoped):
        # bob is on inst-a → visible; bob's rules applied to
        # inst-sh sessions → nothing else leaks through.
        ids, total = _session_ids(scoped, BOB_ON_A)
        assert ids == {"sess-bob"}
        assert total == 1

    def test_filters_cannot_escape_scope(self, scoped):
        # A user filter naming someone else must not reveal them.
        resp = scoped.get(
            "/api/agent-trace/sessions",
            params={"user": "bob"},
            headers=_auth(ALICE),
        )
        assert resp.json()["total"] == 0


class TestDetailIsolation:
    def test_cross_scope_detail_404(self, scoped):
        for path in (
            "",
            "/stats",
            "/export",
        ):
            resp = scoped.get(
                f"/api/agent-trace/sessions/sess-bob{path}",
                headers=_auth(ALICE),
            )
            assert resp.status_code == 404, path

    def test_user_token_blocked_from_console_detail(self, scoped):
        resp = scoped.get(
            "/api/agent-trace/sessions/sess-console", headers=_auth(ALICE)
        )
        assert resp.status_code == 404

    def test_instance_token_blocked_from_other_instance(self, scoped):
        resp = scoped.get(
            "/api/agent-trace/sessions/sess-console", headers=_auth(SH)
        )
        assert resp.status_code == 404

    def test_own_session_readable(self, scoped):
        resp = scoped.get(
            "/api/agent-trace/sessions/sess-alice", headers=_auth(ALICE)
        )
        assert resp.status_code == 200
        assert resp.json()["instance_id"] == "inst-a"


class TestAggregates:
    def test_overview_scoped_to_user(self, scoped):
        body = scoped.get(
            "/api/agent-trace/overview", headers=_auth(ALICE)
        ).json()
        assert body["totals"]["sessions"] == 1
        assert body["totals"]["instances"] == 1
        assert {i["instance_id"] for i in body["instances"]} == {"inst-a"}

    def test_overview_admin_totals(self, scoped):
        body = scoped.get(
            "/api/agent-trace/overview", headers=_auth(ADMIN)
        ).json()
        assert body["totals"]["sessions"] == 4
        assert body["totals"]["instances"] == 2

    def test_whoami(self, scoped):
        body = scoped.get(
            "/api/agent-trace/whoami", headers=_auth(ALICE)
        ).json()
        assert body == {
            "name": "alice",
            "restricted": True,
            "users": ["alice@wecom"],
            "instances": None,
        }
        admin = scoped.get(
            "/api/agent-trace/whoami", headers=_auth(ADMIN)
        ).json()
        assert admin["restricted"] is False


class TestIngest:
    def test_any_valid_token_may_ingest(self, scoped):
        resp = scoped.post(
            "/ingest",
            json=_batch(
                "inst-sh",
                [_event(1, "run/start", {}, session="sess-new")],
            ),
            headers=_auth(ALICE),
        )
        assert resp.status_code == 200, resp.text

    def test_unknown_token_401(self, scoped):
        assert (
            scoped.get(
                "/api/agent-trace/sessions", headers=_auth("nope")
            ).status_code
            == 401
        )

    def test_missing_token_401(self, scoped):
        assert (
            scoped.get("/api/agent-trace/sessions").status_code == 401
        )


class TestTokenStoreUnit:
    """auth.py parsing rules, without HTTP."""

    def _store(self, tmp_path, spec, admin="admin-tok"):
        path = tmp_path / "tokens.json"
        path.write_text(spec, encoding="utf-8")
        import auth

        return auth.TokenStore.from_env(
            {
                "TRACE_TOKEN": admin,
                "TRACE_TOKENS_FILE": str(path),
            }
        )

    def test_spec_shapes(self, tmp_path):
        store = self._store(
            tmp_path,
            json.dumps(
                {
                    "t1": {"name": "u", "users": "solo@wecom"},
                    "t2": {"name": "i", "instances": ["edge-1", "edge-2"]},
                    "t3": {"name": "x", "users": []},
                    "": {"name": "empty key dropped"},
                }
            ),
        )
        assert set(store.scopes) == {"admin-tok", "t1", "t2", "t3"}
        assert store.scopes["t1"].users == frozenset({"solo@wecom"})
        assert store.scopes["t2"].instances == frozenset(
            {"edge-1", "edge-2"}
        )
        # An empty allow-list means unrestricted, not "see nothing".
        assert store.scopes["t3"].unrestricted

    def test_unreadable_file_keeps_admin_only(self, tmp_path):
        store = self._store(tmp_path, "{ not json")
        assert set(store.scopes) == {"admin-tok"}
        assert store.scopes["admin-tok"].unrestricted

    def test_can_view_semantics(self):
        from auth import Scope

        admin = Scope()
        assert admin.can_view(user_id=None, instance_id=None)
        user = Scope(users=frozenset({"a"}))
        assert user.can_view(user_id="a", instance_id="any")
        assert not user.can_view(user_id=None, instance_id="any")
        both = Scope(users=frozenset({"a"}), instances=frozenset({"i"}))
        assert both.can_view(user_id="a", instance_id="i")
        assert not both.can_view(user_id="a", instance_id="other")
