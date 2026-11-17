"""Dashboard API tests: auth, CSRF, live approval flow, stop/repair, verdicts, memory, audit."""

from __future__ import annotations

import json
import re
import sys
import time
from pathlib import Path

import pytest
from starlette.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_harness import ScriptedBackend, write_config  # noqa: E402

from mordecai import agent as agent_mod  # noqa: E402
from mordecai.config import load_config  # noqa: E402
from mordecai.web.app import Dashboard, create_app  # noqa: E402

H = {"X-CA-Request": "1"}


def wait_for(client, kind, after=0, timeout=15):
    deadline = time.time() + timeout
    while time.time() < deadline:
        evs = client.get(f"/api/events/poll?after={after}").json()
        hit = [e for e in evs if e["kind"] == kind]
        if hit:
            return hit[0], evs
        time.sleep(0.1)
    raise AssertionError(f"no {kind} event")


def login(c, token="test-token", consent=None, username=None, password=None):
    from test_harness import TEST_PASSWORD, TEST_USER
    body = {"token": token, "username": TEST_USER if username is None else username,
            "password": TEST_PASSWORD if password is None else password}
    if consent is not None:
        body["consent"] = consent
    return c.post("/api/login", json=body, headers=H)


def make(tmp_path, monkeypatch, scripts):
    cfg = load_config(write_config(tmp_path))
    fake = ScriptedBackend(scripts)
    monkeypatch.setattr(agent_mod, "make_backend", lambda profile: fake)
    dash = Dashboard(cfg, "WEB-1", token="test-token")
    return dash, create_app(dash)


def test_auth_csrf_and_headers(tmp_path, monkeypatch):
    dash, app = make(tmp_path, monkeypatch, {})
    with TestClient(app) as c:
        assert c.get("/api/state").status_code == 401
        assert c.get("/", follow_redirects=False).headers["location"] == "/login"  # unauthenticated -> sign-in page
        page = c.get("/login?token=test-token")
        assert page.status_code == 200 and "set-cookie" not in page.headers  # a GET never signs you in
        assert c.get("/api/state").status_code == 401
        assert c.post("/api/login", json={"token": "test-token", "username": "analyst",
                                          "password": "correct horse battery"}).status_code == 403  # CSRF header required
        assert login(c, "nope").status_code == 401
        r = login(c)
        assert r.status_code == 200 and "httponly" in r.headers["set-cookie"].lower() and "samesite=strict" in r.headers["set-cookie"].lower()
        assert c.get("/api/state").status_code == 200
        page = c.get("/")
        assert page.status_code == 200 and "script-src 'self'" in page.headers["content-security-policy"]
        v = re.search(r'/static/app\.js\?v=([0-9a-f]{12})"', page.text).group(1)  # assets versioned by content
        assert f"/static/logo.svg?v={v}" in c.get("/login").text and c.get(f"/static/app.js?v={v}").status_code == 200
        for asset in ("app.js", "app.css", "login.js", "logo.svg", "favicon.svg"):
            r = c.get(f"/static/{asset}")
            assert r.status_code == 200 and r.headers["cache-control"] == "no-cache"  # a new logo or script shows at once
        assert c.get("/static/../app.py").status_code == 404
        # state-changing call without the CSRF header is refused
        assert c.post("/api/message", json={"text": "hi"}).status_code == 403
        st = c.get("/api/state").json()
        assert st["case"]["id"] == "WEB-1" and st["connectors"]["velociraptor"].startswith("connected")
        assert {e["name"] for e in st["experts"]} >= {"threat_hunter", "incident_responder"}
        assert c.post("/api/logout", json={}, headers=H).json()["ok"]
        assert c.get("/api/state").status_code == 401
        audit = (tmp_path / "cases" / "WEB-1" / "audit.jsonl").read_text()
        assert '"event":"dashboard_login"' in audit


def test_consent_banner_and_login_throttle(tmp_path, monkeypatch):
    cfg = load_config(write_config(tmp_path))
    cfg.raw["dashboard"] = {"consent_text": "This system is monitored and use is recorded."}
    monkeypatch.setattr(agent_mod, "make_backend", lambda profile: ScriptedBackend({}))
    app = create_app(Dashboard(cfg, "WEB-2", token="test-token"))
    with TestClient(app) as c:
        info = c.get("/api/public").json()
        assert info["consent_text"].startswith("This system is monitored") and "classification" not in info
        assert not info["authed"]
        assert login(c).status_code == 400  # consent not acknowledged
        assert login(c, consent=True).status_code == 200
        assert "classification" not in c.get("/api/state").json()["ui"]
        for _ in range(10):
            assert login(c, "wrong", True).status_code == 401
        assert login(c, "test-token", True).status_code == 429  # throttled after repeated failures


def test_login_throttle_holds_for_parallel_tries(tmp_path, monkeypatch):
    """A try is counted before it waits for the password check, so tries sent at the same time get no more than the
    ten a client is allowed (and cannot keep the password hashing busy without limit)."""
    import asyncio

    import httpx

    _, app = make(tmp_path, monkeypatch, {})

    async def burst() -> list[int]:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as c:
            rs = await asyncio.gather(*[c.post("/api/login", json={"token": "wrong", "username": "u", "password": "p"},
                                               headers=H) for _ in range(20)])
        return sorted(r.status_code for r in rs)

    assert asyncio.run(burst()) == [401] * 10 + [429] * 10


def test_investigation_with_browser_approval(tmp_path, monkeypatch):
    scripts = {
        "lead": [("Isolating ws01.", [("subagent_spawn", {"expert": "incident_responder", "task": "isolate ws01"})]),
                 ("Containment was denied by the analyst; monitoring instead.", [])],
        "Incident Responder (containment / eradication / recovery)": [
            ("Action summary: quarantine ws01 - active C2.", [("velociraptor__quarantine_host", {"client_id": "C.1111111111111111"})]),
            ("Denied; recommending monitoring.", [])],
    }
    dash, app = make(tmp_path, monkeypatch, scripts)
    with TestClient(app) as c:
        login(c)
        assert c.post("/api/message", json={"text": "contain ws01"}, headers=H).json()["ok"]
        assert c.post("/api/message", json={"text": "again"}, headers=H).status_code == 409  # one op at a time
        ev, _ = wait_for(c, "approval_request")
        req = ev["data"]
        assert req["tool"] == "velociraptor__quarantine_host" and "Action summary" in req["rationale"]
        assert c.get("/api/state").json()["pending"][0]["id"] == req["id"]
        r = c.post(f"/api/approvals/{req['id']}", json={"approve": False, "note": "change window"}, headers=H)
        assert r.json()["ok"]
        end, evs = wait_for(c, "run_end")
        assert end["data"]["ok"]
        kinds = [e["kind"] for e in evs]
        assert {"analyst_message", "subagent_spawn", "decision", "subagent_report", "approval_resolved"} <= set(kinds)
        audit = c.get("/api/audit").json()
        assert audit["verified"]
        denied = [r for r in audit["records"] if r["event"] == "policy_decision" and r["data"]["tool"] == "velociraptor__quarantine_host"]
        assert denied and not denied[0]["data"]["allowed"] and "change window" in denied[0]["data"]["reason"]


def test_stop_repairs_history(tmp_path, monkeypatch):
    scripts = {"lead": [("Quarantining.", [("velociraptor__quarantine_host", {"client_id": "C.1111111111111111"})])]}
    dash, app = make(tmp_path, monkeypatch, scripts)
    dash.cfg.orchestration["lead_tools"] = ["*"]  # this test has the lead act directly (the default lead delegates)
    with TestClient(app) as c:
        login(c)
        c.post("/api/message", json={"text": "contain"}, headers=H)
        wait_for(c, "approval_request")
        assert c.post("/api/stop", json={}, headers=H).json()["ok"]
        end, _ = wait_for(c, "run_end")
        assert end["data"]["stopped"] or not end["data"]["ok"] or "denied" in str(end["data"]).lower()
        msgs = dash.harness.lead.messages
        calls = {tc["id"] for m in msgs if m.get("tool_calls") for tc in m["tool_calls"]}
        answered = {m["tool_call_id"] for m in msgs if m["role"] == "tool"}
        assert calls <= answered  # no dangling tool calls -> next turn is valid
        assert not dash.pending


def test_verdict_memory_and_tools(tmp_path, monkeypatch):
    dash, app = make(tmp_path, monkeypatch, {})
    with TestClient(app) as c:
        login(c)
        dash.harness.case.add_finding("Odd PowerShell", "medium", "encoded command from backup agent")
        fid = dash.harness.case.data["findings"][0]["id"]
        assert c.post("/api/verdict", json={"finding_id": fid, "verdict": "benign", "note": "backup software"}, headers=H).json()["ok"]
        assert c.post("/api/verdict", json={"finding_id": fid, "verdict": "bogus"}, headers=H).status_code == 400
        mem = c.get("/api/memory?status=approved").json()
        assert any(m["kind"] == "false_positive" for m in mem)
        r = c.post("/api/remember", json={"kind": "environment", "title": "DCs", "content": "10.1.1.5 and 10.1.1.6"}, headers=H)
        assert r.json()["ok"]
        cand = dash.harness.memory.add("lesson", "agent lesson", "x", source="agent")
        assert c.post(f"/api/memory/{cand}", json={"action": "promote"}, headers=H).json()["ok"]
        tools = c.get("/api/tools").json()
        assert any(t["name"] == "velociraptor__quarantine_host" and t["tier"] == "approve" for t in tools)
        assert c.post("/api/rate", json={"rating": 9}, headers=H).status_code == 400
        assert c.post("/api/rate", json={"rating": 5, "note": "good"}, headers=H).json()["ok"]


def test_playbook_names_are_plain_names(tmp_path, monkeypatch):
    """A playbook is chosen by its plain name. A path to the vulnerability assessment playbook would load it without
    matching the gate-everything floor, which knows playbooks by name, so it is refused."""
    dash, app = make(tmp_path, monkeypatch, {})
    with TestClient(app) as c:
        login(c)
        for pb in ("../playbooks/vulnerability_assessment", "../prompts/core", "Triage"):
            r = c.post("/api/message", json={"text": "go", "playbook": pb}, headers=H)
            assert r.status_code == 400 and "unknown playbook" in r.json()["error"], pb
