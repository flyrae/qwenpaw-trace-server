# -*- coding: utf-8 -*-
"""Edge enrollment: instances self-register with an admin-issued
bootstrap key and receive an instance-scoped token.

Covers: happy path + immediate usability, rotation semantics (a
re-enroll kills the previous token), key validity gates (unknown /
expired / exhausted / revoked), admin-surface visibility, and that
an enroll key never authorizes anything besides /enroll.
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


def _fresh_app():
    for name, module in list(sys.modules.items()):
        file = getattr(module, "__file__", "")
        if file and str(SERVER_DIR) in str(file):
            del sys.modules[name]
    import app as app_module

    return importlib.reload(app_module)


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("TRACE_DB", str(tmp_path / "traces.db"))
    monkeypatch.setenv("TRACE_TOKEN", ADMIN)
    app_module = _fresh_app()
    with TestClient(app_module.app) as test_client:
        yield test_client


def _new_key(client, **spec):
    resp = client.post(
        "/api/agent-trace/admin/enroll-keys",
        json={"name": spec.pop("name", "机房批次") , **spec},
        headers=_auth(ADMIN),
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def _enroll(client, key, instance_id, expect=200):
    resp = client.post(
        "/enroll",
        json={"instance_id": instance_id, "hostname": "h-" + instance_id},
        headers=_auth(key),
    )
    assert resp.status_code == expect, resp.text
    return resp.json() if expect == 200 else None


class TestEnroll:
    def test_issued_token_is_instance_scoped(self, client):
        key = _new_key(client)["key"]
        body = _enroll(client, key, "edge-01")
        assert body["token"].startswith("tok_")
        # Token works immediately and only sees its own instance.
        client.post(
            "/ingest",
            json={
                "instance": {"instance_id": "edge-01"},
                "events": [
                    {
                        "session_id": "s1",
                        "seq": 1,
                        "t": "2026-09-16T00:00:01.000+00:00",
                        "type": "run/end",
                        "data": {"status": "success"},
                    }
                ],
            },
            headers=_auth(body["token"]),
        )
        client.post(
            "/ingest",
            json={
                "instance": {"instance_id": "other"},
                "events": [
                    {
                        "session_id": "s2",
                        "seq": 1,
                        "t": "2026-09-16T00:00:02.000+00:00",
                        "type": "run/end",
                        "data": {"status": "success"},
                    }
                ],
            },
            headers=_auth(ADMIN),
        )
        rows = client.get(
            "/api/agent-trace/sessions", headers=_auth(body["token"])
        ).json()["sessions"]
        assert {r["instance_id"] for r in rows} == {"edge-01"}

    def test_reenroll_rotates_previous_token(self, client):
        key = _new_key(client)["key"]
        first = _enroll(client, key, "edge-01")
        second = _enroll(client, key, "edge-01")
        assert first["token"] != second["token"]
        assert (
            client.get(
                "/api/agent-trace/sessions", headers=_auth(first["token"])
            ).status_code
            == 401
        )
        assert (
            client.get(
                "/api/agent-trace/sessions",
                headers=_auth(second["token"]),
            ).status_code
            == 200
        )

    def test_unknown_key_401(self, client):
        _enroll(client, "enroll_nope", "edge-01", expect=401)

    def test_max_uses_exhausted(self, client):
        key = _new_key(client, name="one-shot", max_uses=1)["key"]
        _enroll(client, key, "edge-01")
        _enroll(client, key, "edge-02", expect=401)

    def test_expired_key_401(self, client, tmp_path):
        created = _new_key(client, name="short-lived", expires_days=1)
        # Fast-forward the expiry directly in the DB.
        app_module = sys.modules["app"]
        app_module.db._db.execute(
            "UPDATE enroll_keys SET expires_at='2000-01-01T00:00:00+00:00'"
            " WHERE id=?",
            (created["id"],),
        )
        app_module.db._db.commit()
        _enroll(client, created["key"], "edge-01", expect=401)

    def test_revoked_key_401(self, client):
        created = _new_key(client)
        assert (
            client.delete(
                f"/api/agent-trace/admin/enroll-keys/{created['id']}",
                headers=_auth(ADMIN),
            ).status_code
            == 200
        )
        _enroll(client, created["key"], "edge-01", expect=401)

    def test_revoked_key_leaves_issued_tokens_alive(self, client):
        created = _new_key(client)
        body = _enroll(client, created["key"], "edge-01")
        client.delete(
            f"/api/agent-trace/admin/enroll-keys/{created['id']}",
            headers=_auth(ADMIN),
        )
        assert (
            client.get(
                "/api/agent-trace/sessions", headers=_auth(body["token"])
            ).status_code
            == 200
        )

    def test_bad_instance_id_400(self, client):
        key = _new_key(client)["key"]
        resp = client.post(
            "/enroll", json={"instance_id": "  "}, headers=_auth(key)
        )
        assert resp.status_code == 400

    def test_enroll_key_is_not_a_bearer_token(self, client):
        created = _new_key(client)
        # The bootstrap key must not unlock regular API endpoints.
        for path in (
            "/api/agent-trace/sessions",
            "/api/agent-trace/admin/tokens",
            "/ingest",
        ):
            resp = client.post(
                path, json={}, headers=_auth(created["key"])
            ) if path == "/ingest" else client.get(
                path, headers=_auth(created["key"])
            )
            assert resp.status_code == 401, path


class TestEnrollKeyAdmin:
    def test_scoped_token_gets_404(self, client):
        key = _new_key(client)
        scoped = client.post(
            "/api/agent-trace/admin/tokens",
            json={"name": "user", "users": ["u@x"]},
            headers=_auth(ADMIN),
        ).json()["token"]
        resp = client.get(
            "/api/agent-trace/admin/enroll-keys", headers=_auth(scoped)
        )
        assert resp.status_code == 404

    def test_list_masks_key_and_counts_uses(self, client):
        created = _new_key(client, name="batch-1", max_uses=10)
        _enroll(client, created["key"], "edge-01")
        body = client.get(
            "/api/agent-trace/admin/enroll-keys", headers=_auth(ADMIN)
        ).json()
        assert created["key"] not in json.dumps(body)
        entry = next(
            k for k in body["enroll_keys"] if k["id"] == created["id"]
        )
        assert entry["key"].startswith("enroll_")
        assert entry["uses"] == 1
        assert entry["max_uses"] == 10

    def test_validation(self, client):
        for bad in (
            {"name": "  "},
            {"name": "x", "max_uses": 0},
            {"name": "x", "expires_days": 0},
        ):
            resp = client.post(
                "/api/agent-trace/admin/enroll-keys",
                json=bad,
                headers=_auth(ADMIN),
            )
            assert resp.status_code == 422, bad

    def test_tokens_list_shows_enroll_source(self, client):
        key = _new_key(client)["key"]
        _enroll(client, key, "edge-09")
        body = client.get(
            "/api/agent-trace/admin/tokens", headers=_auth(ADMIN)
        ).json()
        entry = next(
            t for t in body["tokens"] if t["name"] == "edge-09"
        )
        assert entry["source"] == "enroll"
        assert entry["instances"] == ["edge-09"]
