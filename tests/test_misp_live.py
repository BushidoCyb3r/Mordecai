"""Live checks of the MISP connector against your MISP: one call of every read tool, plus the account check, and
optionally the two writes.

Skipped unless MORDECAI_LIVE_MISP=1. The MISP_* settings come from config/.env (or the environment):
    MORDECAI_LIVE_MISP=1 .venv/bin/python -m pytest -q tests/test_misp_live.py
    MORDECAI_LIVE_MISP_FEED_VALUE=<a value in one of your cached feeds> also checks the feed-cache search.
Read-only by default. MORDECAI_LIVE_MISP_WRITE=1 also checks the writes on a throwaway event: one unpublished,
organization-only event holding a single made-up .invalid domain, a sighting and a false-positive sighting of that
value only, then the event is deleted (its sightings go with it).
"""

from __future__ import annotations

import importlib
import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
pytestmark = pytest.mark.skipif(os.environ.get("MORDECAI_LIVE_MISP") != "1", reason="set MORDECAI_LIVE_MISP=1 to test against MISP")


@pytest.fixture(scope="module")
def m():
    from mordecai.config import parse_env_file

    env = ROOT / "config" / ".env"
    saved = dict(os.environ)
    if env.exists():
        for k, v in parse_env_file(env).items():
            if k.startswith("MISP_"):
                os.environ.setdefault(k, v)
    try:
        yield importlib.reload(importlib.import_module("mordecai.servers.misp"))
    finally:
        os.environ.clear()
        os.environ.update(saved)


def test_1_the_key_works_and_its_role(m):
    """The key reaches MISP over verified TLS (MISP_VERIFY). A site-admin key works but is far more than the harness
    needs: warn, so it gets swapped for a User-role key (SETUP.md section 6)."""
    me = m._req("GET", "/users/view/me")
    role = me.get("Role") or {}
    assert me.get("User", {}).get("id"), "the key does not resolve to a user"
    if role.get("perm_site_admin") or role.get("perm_admin"):
        pytest.skip(f"WARNING: the MISP key has the {role.get('name')!r} role (admin rights); use a User-role key")


def test_2_feeds_are_listed_with_cache_age(m):
    r = json.loads(m.list_feeds())
    assert r["feeds"], "MISP has no enabled or cached feeds"
    for f in r["feeds"]:
        assert f["name"] and f["format"] and f["stale"] in (True, False, None)
    if any(f["stale"] is None for f in r["feeds"]):
        assert "site admins only" in r["note"]  # a non-admin key: cache age unknown, said so
    print("\nfeeds:", len(r["feeds"]), "stale:", [f["name"] for f in r["feeds"] if f["stale"]],
          "warninglists enabled:", r["enabled_warninglists"])


def test_3_search_ioc_covers_events_feed_caches_and_warninglists(m):
    """Set MORDECAI_LIVE_MISP_FEED_VALUE to a value you know sits in a cached feed (a Tor exit node, say): search_ioc must
    find it there whether or not the feed is imported as events. (Not looked up here: MISP's feed preview downloads
    the feed again.)"""
    value = os.environ.get("MORDECAI_LIVE_MISP_FEED_VALUE", "")
    out = json.loads(m.search_ioc([value or "8.8.8.8"]))
    v = out[value or "8.8.8.8"]
    assert {"hits", "attributes", "feed_hits", "feeds", "warninglists"} <= set(v)
    if value:
        assert v["feed_hits"] >= 1, f"{value} is in a feed cache but search_ioc did not find it"
    if not json.loads(m.warninglist_check(["8.8.8.8"]))["enabled_warninglists"]:
        assert "no warninglists enabled" in out["_note"]


def test_4_events_attributes_and_event_detail(m):
    ev = json.loads(m.search_events(limit=2))
    assert ev and ev[0]["id"]
    d = json.loads(m.get_event(ev[0]["id"], max_attributes=5))
    assert d["id"] == ev[0]["id"] and "galaxies" in d and len(d["attributes"]) <= 5
    a = json.loads(m.search_attributes(since="3650d", to_ids_only=False, limit=3))
    assert a["count"] >= 1 and a["attributes"][0]["value"]


@pytest.mark.skipif(os.environ.get("MORDECAI_LIVE_MISP_WRITE") != "1", reason="set MORDECAI_LIVE_MISP_WRITE=1 to check the writes")
def test_5_writes_on_a_throwaway_event(m):
    """create_event stores what it promises (unpublished, organization only, the tag and threat level given), and
    add_sighting records both types with source Mordecai, on a made-up value no real intelligence holds."""
    import uuid

    value = f"mordecai-live-test-{uuid.uuid4().hex[:8]}.invalid"
    tags = [t["name"] for t in (m._req("GET", "/tags/index/searchall:tlp:clear").get("Tag") or [])][:1]  # if it exists
    made = json.loads(m.create_event(info=f"Mordecai live test - safe to delete ({value})", threat_level="low",
                                     attributes=[{"type": "domain", "value": value, "comment": "made-up test value"}],
                                     tags=tags))
    try:
        assert made["published"] is False and str(made["distribution"]) == "0"
        ev = m._req("GET", f"/events/view/{made['id']}")["Event"]
        assert ev["published"] is False and str(ev["distribution"]) == "0" and str(ev["threat_level_id"]) == "3"
        assert [a["value"] for a in ev["Attribute"]] == [value] and str(ev["Attribute"][0]["distribution"]) == "5"
        assert [t["name"] for t in ev.get("Tag", [])] == tags
        m.add_sighting(value)
        m.add_sighting(value, sighting_type="false_positive")
        r = m._req("POST", "/sightings/restSearch", {"returnFormat": "json", "value": value})
        got = sorted((str(x["Sighting"]["type"]), x["Sighting"]["source"], str(x["Sighting"]["event_id"])) for x in r["response"])
        assert got == [("0", "Mordecai", str(made["id"])), ("1", "Mordecai", str(made["id"]))]
        assert value in m.get_event(str(made["id"])) and json.loads(m.search_ioc([value]))[value]["hits"] == 1
    finally:
        m._req("POST", f"/events/delete/{made['id']}")
        assert not m._req("POST", "/sightings/restSearch", {"returnFormat": "json", "value": value})["response"]
