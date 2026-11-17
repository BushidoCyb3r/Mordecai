"""Live checks of the MISP connector against your MISP: one call of every read tool, plus the account check.

Skipped unless MORDECAI_LIVE_MISP=1. The MISP_* settings come from config/.env (or the environment):
    MORDECAI_LIVE_MISP=1 .venv/bin/python -m pytest -q tests/test_misp_live.py
    MORDECAI_LIVE_MISP_FEED_VALUE=<a value in one of your cached feeds> also checks the feed-cache search.
Read-only: nothing here adds a sighting or creates an event.
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
