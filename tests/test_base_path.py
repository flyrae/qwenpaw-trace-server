# -*- coding: utf-8 -*-
"""TRACE_BASE_PATH: mount the whole server under a URL prefix for
reverse-proxy deployments (nginx routing several services off one
host). Every path moves under the prefix and the unprefixed ones
must not answer."""
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
BASE = "/agent-trace"


def _fresh_app():
    for name, module in list(sys.modules.items()):
        file = getattr(module, "__file__", "")
        if file and str(SERVER_DIR) in str(file):
            del sys.modules[name]
    import app as app_module

    return importlib.reload(app_module)


@pytest.fixture()
def prefixed(tmp_path, monkeypatch):
    monkeypatch.setenv("TRACE_DB", str(tmp_path / "traces.db"))
    monkeypatch.setenv("TRACE_TOKEN", ADMIN)
    monkeypatch.setenv("TRACE_BASE_PATH", BASE)
    app_module = _fresh_app()
    assert app_module.BASE_PATH == BASE
    with TestClient(app_module.app) as client:
        yield client


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


class TestPrefixedRoutes:
    def test_healthz_under_prefix(self, prefixed):
        assert prefixed.get(f"{BASE}/healthz").status_code == 200
        # Unprefixed paths no longer serve; the auth middleware
        # answers 401 before routing even sees them.
        assert prefixed.get("/healthz").status_code == 401

    def test_read_api_under_prefix(self, prefixed):
        assert (
            prefixed.get(
                f"{BASE}/api/agent-trace/sessions", headers=_auth(ADMIN)
            ).status_code
            == 200
        )
        assert (
            prefixed.get(
                "/api/agent-trace/sessions", headers=_auth(ADMIN)
            ).status_code
            == 404
        )

    def test_ingest_and_session_roundtrip(self, prefixed):
        resp = prefixed.post(
            f"{BASE}/ingest",
            json={
                "instance": {"instance_id": "inst-a"},
                "events": [
                    {
                        "session_id": "sess-1",
                        "seq": 1,
                        "t": "2026-09-16T00:00:01.000+00:00",
                        "type": "run/end",
                        "run_id": "r1",
                        "data": {"status": "success"},
                    }
                ],
            },
            headers=_auth(ADMIN),
        )
        assert resp.status_code == 200
        body = prefixed.get(
            f"{BASE}/api/agent-trace/sessions", headers=_auth(ADMIN)
        ).json()
        assert body["total"] == 1

    def test_enroll_under_prefix(self, prefixed):
        key = prefixed.post(
            f"{BASE}/api/agent-trace/admin/enroll-keys",
            json={"name": "batch"},
            headers=_auth(ADMIN),
        ).json()["key"]
        resp = prefixed.post(
            f"{BASE}/enroll",
            json={"instance_id": "edge-1"},
            headers=_auth(key),
        )
        assert resp.status_code == 200
        assert resp.json()["instances"] == ["edge-1"]

    def test_auth_guard_uses_prefixed_public_paths(self, prefixed):
        # Anonymous: the portal shell loads (public), the API 401s.
        assert prefixed.get(f"{BASE}/").status_code == 200
        assert (
            prefixed.get(f"{BASE}/api/agent-trace/sessions").status_code
            == 401
        )

    def test_normalization_strips_trailing_slash(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.setenv("TRACE_DB", str(tmp_path / "t.db"))
        monkeypatch.delenv("TRACE_TOKEN", raising=False)
        monkeypatch.setenv("TRACE_BASE_PATH", "agent-trace/")
        app_module = _fresh_app()
        assert app_module.BASE_PATH == "/agent-trace"


class TestFrontendPrefixInference:
    """The static pages must derive the API base from their own URL
    so an nginx location block needs zero per-page configuration."""

    def test_portal_html_contains_relative_api_boot(self, prefixed):
        html = prefixed.get(f"{BASE}/").text
        # The API base is derived from the page URL, not hardcoded.
        assert 'const API = "/api/agent-trace"' not in html
        assert 'BASE + "/api/agent-trace"' in html

    def test_trace_shell_infers_base_from_path(self, prefixed):
        html = prefixed.get(f"{BASE}/trace/").text
        assert "/^(.*)\\/trace(\\/|$)/" in html
