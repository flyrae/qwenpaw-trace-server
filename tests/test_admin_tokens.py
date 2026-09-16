# -*- coding: utf-8 -*-
"""Admin console: token issuance/revocation via the API.

Issued tokens must work on the very next request and revoked ones
must die on the very next request (DB is the live source of truth).
The admin surface itself must 404 for scoped tokens, and list views
must never leak a plaintext token.
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


def _event(seq, event_type, data=None, session="sess-1"):
    return {
        "session_id": session,
        "seq": seq,
        "t": f"2026-09-16T00:00:{seq % 60:02d}.000+00:00",
        "type": event_type,
        "run_id": "r1",
        "data": data or {},
    }


@pytest.fixture()
def admin_client(tmp_path, monkeypatch):
    monkeypatch.setenv("TRACE_DB", str(tmp_path / "traces.db"))
    monkeypatch.setenv("TRACE_TOKEN", ADMIN)
    app_module = _fresh_app()
    with TestClient(app_module.app) as client:
        # Two users' sessions to prove issued scopes filter reads.
        client.post(
            "/ingest",
            json={
                "instance": {"instance_id": "inst-a"},
                "events": [
                    _event(
                        1,
                        "message/inbound",
                        {"user_id": "alice@wecom", "text": "alice"},
                        session="sess-alice",
                    ),
                    _event(
                        1,
                        "message/inbound",
                        {"user_id": "bob@wecom", "text": "bob"},
                        session="sess-bob",
                    ),
                ],
            },
            headers=_auth(ADMIN),
        )
        yield client


def _issue(client, name, **scope):
    resp = client.post(
        "/api/agent-trace/admin/tokens",
        json={"name": name, **scope},
        headers=_auth(ADMIN),
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


class TestIssueAndRevoke:
    def test_issued_token_works_immediately(self, admin_client):
        body = _issue(
            admin_client, "alice", users=["alice@wecom"]
        )
        assert body["token"].startswith("tok_")
        assert body["users"] == ["alice@wecom"]
        # Same request cycle, no restart: the token is valid and
        # scoped.
        resp = admin_client.get(
            "/api/agent-trace/sessions", headers=_auth(body["token"])
        )
        assert resp.status_code == 200
        ids = {s["session_id"] for s in resp.json()["sessions"]}
        assert ids == {"sess-alice"}

    def test_revoked_token_dies_immediately(self, admin_client):
        body = _issue(admin_client, "bob", users=["bob@wecom"])
        assert (
            admin_client.get(
                "/api/agent-trace/sessions", headers=_auth(body["token"])
            ).status_code
            == 200
        )
        resp = admin_client.delete(
            f"/api/agent-trace/admin/tokens/{body['id']}",
            headers=_auth(ADMIN),
        )
        assert resp.status_code == 200
        assert (
            admin_client.get(
                "/api/agent-trace/sessions", headers=_auth(body["token"])
            ).status_code
            == 401
        )

    def test_revoke_is_idempotent_and_unknown_404(self, admin_client):
        body = _issue(admin_client, "temp")
        assert (
            admin_client.delete(
                f"/api/agent-trace/admin/tokens/{body['id']}",
                headers=_auth(ADMIN),
            ).status_code
            == 200
        )
        # Revoking again still 200; an unused id is a 404.
        assert (
            admin_client.delete(
                f"/api/agent-trace/admin/tokens/{body['id']}",
                headers=_auth(ADMIN),
            ).status_code
            == 200
        )
        assert (
            admin_client.delete(
                "/api/agent-trace/admin/tokens/99999",
                headers=_auth(ADMIN),
            ).status_code
            == 404
        )

    def test_issue_unrestricted_token(self, admin_client):
        body = _issue(admin_client, "second-admin")
        assert body["users"] is None and body["instances"] is None
        whoami = admin_client.get(
            "/api/agent-trace/whoami", headers=_auth(body["token"])
        ).json()
        assert whoami["restricted"] is False

    def test_name_required(self, admin_client):
        resp = admin_client.post(
            "/api/agent-trace/admin/tokens",
            json={"name": "   "},
            headers=_auth(ADMIN),
        )
        assert resp.status_code == 422
        # pydantic validation also rejects a missing name outright
        resp = admin_client.post(
            "/api/agent-trace/admin/tokens",
            json={"users": ["x"]},
            headers=_auth(ADMIN),
        )
        assert resp.status_code == 422

    def test_empty_allow_list_means_unrestricted(self, admin_client):
        body = _issue(admin_client, "wide", users=[])
        assert body["users"] is None


class TestAdminSurfaceVisibility:
    def test_scoped_token_gets_404_on_admin_api(self, admin_client):
        body = _issue(admin_client, "alice", users=["alice@wecom"])
        resp = admin_client.get(
            "/api/agent-trace/admin/tokens",
            headers=_auth(body["token"]),
        )
        assert resp.status_code == 404
        resp = admin_client.post(
            "/api/agent-trace/admin/tokens",
            json={"name": "x"},
            headers=_auth(body["token"]),
        )
        assert resp.status_code == 404
        resp = admin_client.delete(
            "/api/agent-trace/admin/tokens/1",
            headers=_auth(body["token"]),
        )
        assert resp.status_code == 404

    def test_list_masks_tokens(self, admin_client):
        issued = _issue(admin_client, "alice", users=["alice@wecom"])
        body = admin_client.get(
            "/api/agent-trace/admin/tokens", headers=_auth(ADMIN)
        ).json()
        assert body["admin_env"] is True
        entry = next(t for t in body["tokens"] if t["id"] == issued["id"])
        assert issued["token"] not in json.dumps(body)
        assert entry["token"].startswith("tok_")
        assert "…" in entry["token"]
        assert entry["users"] == ["alice@wecom"]
        assert entry["revoked"] is False

    def test_list_marks_revoked(self, admin_client):
        issued = _issue(admin_client, "shortlived")
        admin_client.delete(
            f"/api/agent-trace/admin/tokens/{issued['id']}",
            headers=_auth(ADMIN),
        )
        body = admin_client.get(
            "/api/agent-trace/admin/tokens", headers=_auth(ADMIN)
        ).json()
        entry = next(t for t in body["tokens"] if t["id"] == issued["id"])
        assert entry["revoked"] is True


class TestSeeding:
    def test_tokens_file_seeds_db(self, tmp_path, monkeypatch):
        seed = {
            "tok-seed": {
                "name": "seeded",
                "users": ["alice@wecom"],
            }
        }
        seed_file = tmp_path / "tokens.json"
        seed_file.write_text(json.dumps(seed), encoding="utf-8")
        monkeypatch.setenv("TRACE_DB", str(tmp_path / "t.db"))
        monkeypatch.setenv("TRACE_TOKEN", ADMIN)
        monkeypatch.setenv("TRACE_TOKENS_FILE", str(seed_file))
        app_module = _fresh_app()
        with TestClient(app_module.app) as client:
            # Seeded token resolves with its file scope.
            resp = client.get(
                "/api/agent-trace/whoami", headers=_auth("tok-seed")
            )
            assert resp.json() == {
                "name": "seeded",
                "restricted": True,
                "users": ["alice@wecom"],
                "instances": None,
            }

    def test_seed_never_overwrites_console_edits(
        self, tmp_path, monkeypatch
    ):
        # Seed a token, revoke it via the console, then "restart":
        # the file still lists it, but the DB verdict (revoked)
        # wins.
        seed_file = tmp_path / "tokens.json"
        seed_file.write_text(
            json.dumps({"tok-seed": {"name": "seeded"}}),
            encoding="utf-8",
        )
        monkeypatch.setenv("TRACE_DB", str(tmp_path / "t.db"))
        monkeypatch.setenv("TRACE_TOKEN", ADMIN)
        monkeypatch.setenv("TRACE_TOKENS_FILE", str(seed_file))
        app_module = _fresh_app()
        with TestClient(app_module.app) as client:
            listed = client.get(
                "/api/agent-trace/admin/tokens", headers=_auth(ADMIN)
            ).json()["tokens"]
            seeded = next(
                t for t in listed if t["name"] == "seeded"
            )
            client.delete(
                f"/api/agent-trace/admin/tokens/{seeded['id']}",
                headers=_auth(ADMIN),
            )
            assert (
                client.get(
                    "/api/agent-trace/sessions",
                    headers=_auth("tok-seed"),
                ).status_code
                == 401
            )
        # Simulated restart: same env, same DB.
        app_module = _fresh_app()
        with TestClient(app_module.app) as client:
            assert (
                client.get(
                    "/api/agent-trace/sessions",
                    headers=_auth("tok-seed"),
                ).status_code
                == 401
            )


class TestOpenModeTransition:
    def test_first_issued_token_turns_auth_on(self, tmp_path, monkeypatch):
        monkeypatch.setenv("TRACE_DB", str(tmp_path / "t.db"))
        monkeypatch.delenv("TRACE_TOKEN", raising=False)
        monkeypatch.delenv("TRACE_TOKENS_FILE", raising=False)
        app_module = _fresh_app()
        with TestClient(app_module.app) as client:
            # Open mode: no credentials, admin API usable.
            assert (
                client.get("/api/agent-trace/sessions").status_code == 200
            )
            issued = client.post(
                "/api/agent-trace/admin/tokens",
                json={"name": "first", "users": ["u"]},
            ).json()
            # Issuing a token flips the server into auth mode —
            # anonymous access stops immediately.
            assert (
                client.get("/api/agent-trace/sessions").status_code == 401
            )
            assert (
                client.get(
                    "/api/agent-trace/sessions",
                    headers=_auth(issued["token"]),
                ).status_code
                == 200
            )
