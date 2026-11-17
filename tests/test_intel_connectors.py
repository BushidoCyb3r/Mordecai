"""MISP and OpenCTI connector tests against mock HTTP servers (request shapes per the MISP REST API and
the official pycti GraphQL queries)."""

from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path

from mcp.server.mcpserver.exceptions import ToolError

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def load(monkeypatch, module, env):
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    mod = importlib.import_module(f"mordecai.servers.{module}")
    return importlib.reload(mod)


def test_misp(monkeypatch):
    m = load(monkeypatch, "misp", {"MISP_URL": "https://misp.invalid", "MISP_KEY": "k123"})
    seen = []

    def handler(req: httpx.Request):
        seen.append(req)
        assert req.headers["authorization"] == "k123"
        body = json.loads(req.content or b"null")
        if req.url.path == "/attributes/restSearch":
            assert body["value"] == "185.220.101.47" and body["returnFormat"] == "json"
            return httpx.Response(200, json={"response": {"Attribute": [{
                "value": "185.220.101.47", "type": "ip-dst", "category": "Network activity", "to_ids": True, "event_id": "42",
                "Event": {"info": "CS beacon infra", "threat_level_id": "1", "Orgc": {"name": "CERT"}},
                "Tag": [{"name": 'misp-galaxy:mitre-attack-pattern="Application Layer Protocol - T1071"'}]}]}})
        if req.url.path == "/warninglists/checkValue":
            assert body in (["8.8.8.8"], ["185.220.101.47"])
            if body == ["185.220.101.47"]:
                return httpx.Response(200, json=[])  # MISP answers a list when nothing matched
            return httpx.Response(200, json={"8.8.8.8": [{"id": 1, "name": "List of known IPv4 public DNS resolvers"}]})
        if req.url.path == "/warninglists/index":
            return httpx.Response(200, json={"Warninglists": [{"Warninglist": {"id": "1", "enabled": True}}]})
        if req.url.path == "/feeds/index":
            return httpx.Response(200, json=[{"Feed": {"id": "5", "name": "Tor exit nodes", "source_format": "csv",
                                                       "enabled": False, "caching_enabled": True, "cache_timestamp": "1"}}])
        if req.url.path == "/feeds/searchCaches":
            assert body == {"value": "185.220.101.47"}
            return httpx.Response(200, json=[{"Feed": {"id": "5", "name": "Tor exit nodes", "source_format": "csv",
                                                       "direct_urls": [{"url": "https://misp.invalid/feeds/previewIndex/5"}]}}])
        if req.url.path == "/events/add":
            ev = body["Event"]
            assert ev["distribution"] == 0 and ev["published"] is False  # org-only, never auto-published
            return httpx.Response(200, json={"Event": {"id": "77", "uuid": "u", "published": False, "distribution": "0"}})
        if req.url.path == "/sightings/add":
            assert body["type"] == "0"
            return httpx.Response(200, json={"Sighting": {"id": "9"}})
        return httpx.Response(404, text="nope")

    m.http = httpx.Client(base_url="https://misp.invalid", headers={"Authorization": "k123"},
                          transport=httpx.MockTransport(handler))
    hits = json.loads(m.search_ioc(["185.220.101.47"]))
    a = hits["185.220.101.47"]["attributes"][0]
    assert a["event_info"] == "CS beacon infra" and "T1071" in a["tags"][0]
    # feed caches are searched too (a feed that is cached but not imported never shows up in an event search)
    feed = hits["185.220.101.47"]["feeds"][0]
    assert feed["feed"] == "Tor exit nodes" and feed["stale"] is True and feed["imported_as_events"] is False
    assert "direct_urls" not in feed and hits["185.220.101.47"]["warninglists"] == [] and "_note" not in hits
    w = json.loads(m.warninglist_check(["8.8.8.8"]))
    assert "public DNS" in w["hits"]["8.8.8.8"][0]["name"] and w["enabled_warninglists"] == 1
    assert json.loads(m.create_event("IR-0042 C2", [{"type": "ip-dst", "value": "185.220.101.47"}]))["published"] is False
    assert "9" in m.add_sighting("185.220.101.47")
    with pytest.raises(ToolError, match="Error"):
        m.add_sighting("x", sighting_type="delete")
    with pytest.raises(ToolError, match="Error"):
        m.get_event("../../users")


def test_misp_without_warninglists_and_attribute_search(monkeypatch):
    """No warninglists enabled: say so, so silence is never read as 'not benign'. search_attributes builds a
    filtered restSearch and refuses odd types and ages."""
    m = load(monkeypatch, "misp", {"MISP_URL": "https://misp.invalid", "MISP_KEY": "k123"})
    bodies = []

    def handler(req: httpx.Request):
        body = json.loads(req.content or b"null")
        if req.url.path == "/warninglists/index":
            return httpx.Response(200, json={"Warninglists": [{"Warninglist": {"id": "1", "enabled": False}}]})
        if req.url.path == "/warninglists/checkValue":
            return httpx.Response(200, json=[])
        if req.url.path == "/attributes/restSearch":
            bodies.append(body)
            return httpx.Response(200, json={"response": {"Attribute": [{"value": "1.2.3.4", "type": "ip-dst",
                                                                         "to_ids": True, "event_id": "8", "Event": {"info": "C2"}}]}})
        return httpx.Response(404, text="nope")

    m.http = httpx.Client(base_url="https://misp.invalid", transport=httpx.MockTransport(handler))
    w = json.loads(m.warninglist_check(["8.8.8.8"]))
    assert w["hits"] == {} and w["enabled_warninglists"] == 0 and "no warninglists enabled" in w["note"]
    r = json.loads(m.search_attributes(types=["ip-dst", "domain"], tags=["tlp:white"], since="7d", limit=1))
    assert r["count"] == 1 and r["more"] is True and r["attributes"][0]["event_info"] == "C2"
    b = bodies[-1]
    assert b["type"] == ["ip-dst", "domain"] and b["tags"] == ["tlp:white"] and b["timestamp"] == "7d" and b["to_ids"] is True
    m.search_attributes(since="2026-11-01", to_ids_only=False)
    assert bodies[-1]["timestamp"] == "1793491200" and "to_ids" not in bodies[-1]
    for bad in ({"since": "7 days"}, {"since": "1d; drop"}, {"types": ["ip-dst/../admin"]}):
        with pytest.raises(ToolError, match="Error"):
            m.search_attributes(**bad)


def test_misp_lookup_survives_a_failing_part(monkeypatch):
    """Seen live: with a million-entry warninglist enabled, MISP answers checkValue with a 500. The event hits must
    still come back, and the parts MISP could not answer are null (unknown) with the reason, never an empty 'no hit'."""
    m = load(monkeypatch, "misp", {"MISP_URL": "https://misp.invalid", "MISP_KEY": "k123"})

    def handler(req: httpx.Request):
        if req.url.path == "/attributes/restSearch":
            return httpx.Response(200, json={"response": {"Attribute": [{"value": "198.51.100.7", "type": "ip-dst",
                                                                         "event_id": "3", "Event": {"info": "C2"}}]}})
        if req.url.path in ("/warninglists/checkValue", "/feeds/searchCaches"):
            return httpx.Response(500, json={"name": "An Internal Error Has Occurred."})
        if req.url.path == "/feeds/index":  # as a non-admin sees it: no cache_timestamp
            return httpx.Response(200, json=[{"Feed": {"id": "5", "name": "Tor exit nodes", "source_format": "csv",
                                                       "enabled": False, "caching_enabled": True}}])
        if req.url.path == "/warninglists/index":
            return httpx.Response(200, json={"Warninglists": []})
        return httpx.Response(404, text="nope")

    m.http = httpx.Client(base_url="https://misp.invalid", transport=httpx.MockTransport(handler))
    feeds = json.loads(m.list_feeds())
    assert feeds["feeds"][0]["stale"] is None and "site admins only" in feeds["note"]
    out = json.loads(m.search_ioc(["198.51.100.7", "203.0.113.9"]))
    v = out["198.51.100.7"]
    assert v["hits"] == 1 and v["feeds"] is None and v["feed_hits"] is None and v["warninglists"] is None
    assert out["203.0.113.9"]["warninglists"] is None
    assert "500" in out["_errors"]["warninglists"] and "500" in out["_errors"]["feed_caches"]


def test_opencti(monkeypatch):
    m = load(monkeypatch, "opencti", {"OPENCTI_URL": "https://octi.invalid", "OPENCTI_TOKEN": "t0k"})

    def handler(req: httpx.Request):
        assert req.url.path == "/graphql" and req.headers["authorization"] == "Bearer t0k"
        q = json.loads(req.content)
        query, var = q["query"], q["variables"]
        if "stixCyberObservables(" in query:
            assert var["search"] == "185.220.101.47"
            return httpx.Response(200, json={"data": {"stixCyberObservables": {"edges": [{"node": {
                "id": "obs-1", "entity_type": "IPv4-Addr", "observable_value": "185.220.101.47", "x_opencti_score": 80,
                "objectLabel": [{"value": "c2"}], "indicators": {"edges": [{"node": {"id": "ind-1", "pattern": "[ipv4-addr:value = '185.220.101.47']", "pattern_type": "stix"}}]}}}]}}})
        if "indicators(" in query:
            return httpx.Response(200, json={"data": {"indicators": {"edges": [{"node": {
                "id": "ind-1", "name": "185.220.101.47", "pattern": "[ipv4-addr:value = '185.220.101.47']", "pattern_type": "stix",
                "x_opencti_score": 80, "valid_from": "2026-10-01", "valid_until": None,
                "killChainPhases": [{"kill_chain_name": "mitre-attack", "phase_name": "command-and-control"}], "objectLabel": []}}]}}})
        if "stixCoreRelationships(" in query:
            assert "fromOrToId" in query
            return httpx.Response(200, json={"data": {"stixCoreRelationships": {"edges": [{"node": {
                "id": "rel-1", "relationship_type": "indicates", "confidence": 75,
                "from": {"id": "ind-1", "entity_type": "Indicator", "name": "185.220.101.47"},
                "to": {"id": "is-1", "entity_type": "Intrusion-Set", "name": "APT-EXAMPLE"}}}]}}})
        if "stixDomainObjects(" in query:
            return httpx.Response(200, json={"data": {"stixDomainObjects": {"edges": [{"node": {
                "id": "is-1", "entity_type": "Intrusion-Set", "name": "APT-EXAMPLE", "aliases": ["EX"], "description": "d"}}]}}})
        return httpx.Response(200, json={"errors": [{"message": "unknown"}]})

    m.http = httpx.Client(base_url="https://octi.invalid", headers={"Authorization": "Bearer t0k"},
                          transport=httpx.MockTransport(handler))
    r = json.loads(m.lookup_ioc(["185.220.101.47"]))["185.220.101.47"]
    assert r["observables"][0]["score"] == 80 and r["indicators"][0]["kill_chain"] == ["mitre-attack:command-and-control"]
    assert r["related"][0]["to"]["name"] == "APT-EXAMPLE"
    assert "APT-EXAMPLE" in m.search_entities("APT", ["Intrusion-Set"])
    with pytest.raises(ToolError, match="Error"):
        m.graphql_query("mutation { stixDomainObjectEdit(id: \"x\") { delete } }")
    with pytest.raises(ToolError, match="ValueError"):  # a '#' inside a string must not hide the mutation after it
        m.graphql_query('fragment F on StixCyberObservable { id stixCoreRelationships(search: "#") { edges { node { id } } } } '
                        'mutation { stixCyberObservableAdd(type: "IPv4-Addr", IPv4Addr: {value: "203.0.113.9"}) { ...F } }')
    with pytest.raises(ToolError, match="Error"):
        m.search_entities("x", ["Intrusion-Set; drop"])
    with pytest.raises(ToolError, match="RuntimeError"):
        m.graphql_query("query { nothing }")
