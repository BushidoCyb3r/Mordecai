"""MCP server: MISP threat intelligence platform (your organisation's instance).

Env: MISP_URL (https://misp.example), MISP_KEY (auth key), MISP_VERIFY (true|false|/path/ca.pem),
     MISP_MAX_RESULTS (default 100), MISP_FEED_STALE_DAYS (default 7)
An indicator lookup covers MISP's events, its feed caches (feeds that are cached but not imported as events, such as
Tor exit nodes or blocklists, are invisible to an event search) and its warninglists, in one call.
Read tools run freely; writes are deliberately narrow:
  - add_sighting: record that an indicator was seen in your network
  - create_event: always created UNPUBLISHED with distribution "your organisation only" - an analyst publishes
"""

from __future__ import annotations

import calendar
import re
import time
from typing import Any

import httpx
from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

from .common import ACTION, READ, dumps, env, tls_context, tls_verify, tool_factory

mcp = MCPServer("misp", instructions="MISP threat intel: IOC lookups, events, warninglists (known-benign), sightings.")
tool = tool_factory(mcp)
CHANGE = ToolAnnotations(read_only_hint=False, destructive_hint=False, open_world_hint=False)
http = httpx.Client(base_url=env("MISP_URL", required=True).rstrip("/"),
                    headers={"Authorization": env("MISP_KEY", required=True), "Accept": "application/json",
                             "Content-Type": "application/json"},
                    verify=tls_context(tls_verify(env("MISP_VERIFY", "true"))), timeout=float(env("MISP_TIMEOUT", "120")))
MAX = int(env("MISP_MAX_RESULTS", "100"))
STALE_DAYS = float(env("MISP_FEED_STALE_DAYS", "7"))
THREAT = {"high": 1, "medium": 2, "low": 3, "undefined": 4}
_TYPE = re.compile(r"[a-z0-9|-]{1,40}")  # MISP attribute types: ip-dst, domain|ip, sha256, ...
_SINCE = re.compile(r"[0-9]{1,4}[dhm]|[0-9]{4}-[0-9]{2}-[0-9]{2}")
NO_WARNINGLISTS = ("MISP has no warninglists enabled, so a value that is not on one may still be known-benign (public "
                   "resolvers, CDNs, cloud ranges, top domains). Judge it yourself, and ask the MISP admin to enable them.")
_cache: dict[str, tuple[float, Any]] = {}
_EVENT_ID = re.compile(r"[0-9]{1,12}|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")


def _req(method: str, path: str, body: Any = None) -> Any:
    r = http.request(method, path, json=body)
    if r.status_code >= 400:
        raise RuntimeError(f"MISP HTTP {r.status_code}: {r.text[:1500]}")
    return r.json()


def _cached(key: str, fetch: Any, ttl: float = 600) -> Any:
    hit = _cache.get(key)
    if hit and time.monotonic() - hit[0] < ttl:
        return hit[1]
    val = fetch()
    _cache[key] = (time.monotonic(), val)
    return val


def _feeds() -> dict[str, dict[str, Any]]:
    """Every feed MISP knows, by id: name, format, enabled (imported as events), caching (searchable), cache age."""
    def fetch() -> dict[str, dict[str, Any]]:
        now, out = time.time(), {}
        for x in _req("GET", "/feeds/index") or []:
            f = x.get("Feed", x)
            ts = str(f.get("cache_timestamp") or "")
            age = round((now - int(ts)) / 86400, 1) if ts.isdigit() and int(ts) > 0 else None
            # MISP shows cache times to site admins only: without the field the age is unknown (null), not stale
            stale = (age is None or age > STALE_DAYS) if "cache_timestamp" in f else None
            out[str(f.get("id"))] = {"id": f.get("id"), "name": f.get("name"), "provider": f.get("provider"),
                                     "format": f.get("source_format"), "enabled": bool(f.get("enabled")),
                                     "caching": bool(f.get("caching_enabled")),
                                     "cached": time.strftime("%Y-%m-%dT%H:%MZ", time.gmtime(int(ts))) if age is not None else None,
                                     "cache_age_days": age, "stale": stale}
        return out
    return _cached("feeds", fetch)


def _enabled_warninglists() -> int:
    def fetch() -> int:
        res = _req("GET", "/warninglists/index")
        lists = res.get("Warninglists", []) if isinstance(res, dict) else res or []
        return sum(1 for w in lists if (w.get("Warninglist") or w).get("enabled") in (True, 1, "1"))
    return _cached("warninglists", fetch)


def _warninglist_hits(values: list[str]) -> dict[str, list[dict[str, Any]]]:
    res = _req("POST", "/warninglists/checkValue", values) if values else {}
    if not isinstance(res, dict):  # MISP answers [] when nothing matched
        return {}
    return {v: [{"id": w.get("id"), "name": w.get("name"), "matched": w.get("matched")} for w in hits or []]
            for v, hits in res.items() if hits}


def _feed_hits(value: str) -> tuple[list[dict[str, Any]], list[str]]:
    """Feed caches holding the value (the feed and how old its cache is), and the MISP-format feed events that hold
    it. MISP keys that event lookup by value, not by feed, so the UUIDs belong to the value, not to one feed;
    get_event takes them when the feed is also imported."""
    feeds = _feeds()
    hits, uuids = [], []
    for x in _req("POST", "/feeds/searchCaches", {"value": value}) or []:
        f = x.get("Feed", x)
        meta = feeds.get(str(f.get("id")), {})
        hits.append({"feed": f.get("name"), "feed_id": f.get("id"), "format": f.get("source_format"),
                     "cached": meta.get("cached"), "stale": meta.get("stale", True),
                     "imported_as_events": meta.get("enabled")})
        uuids += [u for u in (f.get("uuid") if isinstance(f.get("uuid"), list) else []) if u not in uuids]
    return hits, uuids


def _attr(a: dict[str, Any]) -> dict[str, Any]:
    ev = a.get("Event") or {}
    return {"value": a.get("value"), "type": a.get("type"), "category": a.get("category"), "to_ids": a.get("to_ids"),
            "comment": a.get("comment"), "first_seen": a.get("first_seen"), "last_seen": a.get("last_seen"),
            "event_id": a.get("event_id"), "event_info": ev.get("info"), "event_date": ev.get("date"),
            "threat_level_id": ev.get("threat_level_id"), "org": (ev.get("Orgc") or {}).get("name"),
            "tags": sorted({t.get("name") for t in (a.get("Tag") or []) + (ev.get("Tag") or []) if t.get("name")})}


@tool(READ)
def search_ioc(values: list[str], to_ids_only: bool = False, limit_per_value: int = 20) -> str:
    """Look up indicators (IP, domain, URL, hash, filename, email...) in MISP, in one call per batch: matching
    attributes with their events, threat level, tags (incl. ATT&CK/galaxy tags) and IDS flag; the feed caches that
    hold each value (blocklists, Tor exit nodes... with how old each cache is); and warninglist hits (known-benign).
    Use to enrich every IOC you find. A hit is context, not proof (to_ids false = seen in a report, not a detection);
    no hit is not proof of benign."""
    vals = [str(v).strip() for v in values[:50] if str(v).strip()]
    out: dict[str, Any] = {}
    errors: dict[str, str] = {}  # a part MISP could not answer: its hits are unknown (null), not "none"
    for v in vals:
        body: dict[str, Any] = {"returnFormat": "json", "value": v, "limit": min(limit_per_value, MAX), "page": 1,
                                "includeEventTags": True, "includeContext": True}
        if to_ids_only:
            body["to_ids"] = True
        res = _req("POST", "/attributes/restSearch", body)
        attrs = (res.get("response") or {}).get("Attribute", [])
        feeds: list[dict[str, Any]] | None = None
        uuids: list[str] = []
        if "feed_caches" not in errors:
            try:
                feeds, uuids = _feed_hits(v)
            except (RuntimeError, httpx.HTTPError) as x:
                errors["feed_caches"] = f"not searched: {x}"[:300]
        out[v] = {"hits": len(attrs), "attributes": [_attr(a) for a in attrs],
                  "feed_hits": None if feeds is None else len(feeds), "feeds": feeds}
        if uuids:
            out[v]["feed_event_uuids"] = uuids[:10]
    warn: dict[str, list[dict[str, Any]]] | None = None
    try:
        warn = _warninglist_hits(vals)
    except (RuntimeError, httpx.HTTPError) as x:
        errors["warninglists"] = f"not checked: {x}"[:300]
    for v in vals:
        out[v]["warninglists"] = None if warn is None else warn.get(v, [])
    try:
        if warn is not None and not _enabled_warninglists():
            out["_note"] = NO_WARNINGLISTS
    except (RuntimeError, httpx.HTTPError):
        pass
    if errors:
        out["_errors"] = {**errors, "meaning": "null = that part was not searched, so no hit there proves nothing"}
    return dumps(out)


@tool(READ)
def warninglist_check(values: list[str]) -> str:
    """Check values against MISP warninglists (known-benign: public DNS resolvers, CDNs, cloud ranges, top domains...).
    A hit is strong false-positive evidence - check before escalating or blocking an indicator."""
    out: dict[str, Any] = {"hits": _warninglist_hits([str(v).strip() for v in values[:100]]),
                           "enabled_warninglists": _enabled_warninglists()}
    if not out["enabled_warninglists"]:
        out["note"] = NO_WARNINGLISTS
    return dumps(out)


@tool(READ)
def list_feeds(include_unused: bool = False) -> str:
    """The intel feeds this MISP holds: name, provider, format, whether it is imported as events (enabled) or only
    cached (searchable through search_ioc), and when its cache was last refreshed (stale = older than
    MISP_FEED_STALE_DAYS or never; null = unknown). Use it to say what an IOC lookup did and did not cover. Only the
    feeds this account may look up are listed (MISP's per-feed "lookup visible" setting)."""
    feeds = [f for f in _feeds().values() if include_unused or f["enabled"] or f["caching"]]
    out: dict[str, Any] = {"feeds": sorted(feeds, key=lambda f: int(f["id"] or 0)), "stale_after_days": STALE_DAYS,
                           "enabled_warninglists": _enabled_warninglists()}
    if any(f["stale"] is None for f in feeds):
        out["note"] = ("MISP shows feed cache times to site admins only, so cache age is unknown (null) for this "
                       "account: ask the MISP admin how fresh the caches are before relying on an old indicator.")
    return dumps(out)


@tool(READ)
def search_attributes(types: list[str] | None = None, tags: list[str] | None = None, since: str = "7d",
                      to_ids_only: bool = True, event_info: str = "", limit: int = 100, page: int = 1) -> str:
    """Pull indicators out of MISP by type, tag and age, for a sweep across the sensors: e.g. types ['ip-dst',
    'domain'], tags ['tlp:white', 'misp-galaxy:threat-actor="APT28"'], since '7d' / '24h' / '2026-10-01' (attribute
    timestamp). Compact rows (value, type, event, tags); page through with page."""
    if not _SINCE.fullmatch(since or ""):
        raise ValueError("since: a relative age such as 7d, 24h or 90m, or a date YYYY-MM-DD")
    for t in types or []:
        if not _TYPE.fullmatch(t):
            raise ValueError(f"types: MISP attribute types such as ip-dst, domain, sha256; got {t!r}")
    body: dict[str, Any] = {"returnFormat": "json", "limit": max(1, min(limit, MAX)), "page": max(1, page),
                            "includeEventTags": True, "includeContext": True}
    body["timestamp"] = since if since[-1] in "dhm" else str(calendar.timegm(time.strptime(since, "%Y-%m-%d")))
    if types:
        body["type"] = types
    if tags:
        body["tags"] = tags
    if to_ids_only:
        body["to_ids"] = True
    if event_info:
        body["eventinfo"] = f"%{event_info}%"
    attrs = (_req("POST", "/attributes/restSearch", body).get("response") or {}).get("Attribute", [])
    rows = [{k: a[k] for k in ("value", "type", "category", "to_ids", "event_id", "event_info", "org", "tags") if a.get(k) not in (None, "", [])}
            for a in map(_attr, attrs)]
    return dumps({"count": len(rows), "page": body["page"], "more": len(rows) == body["limit"], "attributes": rows})


@tool(READ)
def search_events(query: str = "", tags: list[str] | None = None, since: str = "", limit: int = 25) -> str:
    """Search MISP events by text in the event info, tags (e.g. 'misp-galaxy:threat-actor="APT28"', 'tlp:amber'),
    and a since-date (e.g. '30d' or '2026-10-01')."""
    body: dict[str, Any] = {"returnFormat": "json", "limit": min(limit, MAX), "page": 1, "metadata": True}
    if query:
        body["eventinfo"] = f"%{query}%"
    if tags:
        body["tags"] = tags
    if since:
        body["date"] = since
    res = _req("POST", "/events/restSearch", body)
    events = res.get("response", []) if isinstance(res, dict) else res
    return dumps([{"id": e["Event"].get("id"), "info": e["Event"].get("info"), "date": e["Event"].get("date"),
                   "threat_level_id": e["Event"].get("threat_level_id"), "published": e["Event"].get("published"),
                   "org": (e["Event"].get("Orgc") or {}).get("name"), "attribute_count": e["Event"].get("attribute_count"),
                   "tags": [t.get("name") for t in e["Event"].get("Tag") or []]} for e in events])


@tool(READ)
def get_event(event_id: str, max_attributes: int = 200) -> str:
    """Full MISP event: description, tags/galaxies (actors, ATT&CK), objects and attributes (indicators)."""
    eid = str(event_id).strip()
    if not _EVENT_ID.fullmatch(eid):  # it goes into the request path: nothing else may reach it (../admin/...)
        raise ValueError("event_id must be a numeric id or a UUID")
    ev = _req("GET", f"/events/view/{eid}").get("Event", {})
    galaxies = [{"galaxy": g.get("name"), "clusters": [c.get("value") for c in g.get("GalaxyCluster") or []]}
                for g in ev.get("Galaxy") or []]
    attrs = [_attr({**a, "Event": {}}) for a in (ev.get("Attribute") or [])]
    for o in ev.get("Object") or []:
        attrs += [{**_attr({**a, "Event": {}}), "object": o.get("name")} for a in o.get("Attribute") or []]
    return dumps({"id": ev.get("id"), "uuid": ev.get("uuid"), "info": ev.get("info"), "date": ev.get("date"),
                  "threat_level_id": ev.get("threat_level_id"), "analysis": ev.get("analysis"),
                  "org": (ev.get("Orgc") or {}).get("name"), "tags": [t.get("name") for t in ev.get("Tag") or []],
                  "galaxies": galaxies, "attribute_count": len(attrs), "attributes": attrs[:max_attributes]})


@tool(CHANGE)
def add_sighting(value: str, source: str = "Mordecai", sighting_type: str = "sighting") -> str:
    """Record that an indicator was observed in the defended network (type: sighting | false_positive)."""
    t = {"sighting": "0", "false_positive": "1"}.get(sighting_type)
    if t is None:
        raise ValueError("sighting_type must be sighting or false_positive")
    return dumps(_req("POST", "/sightings/add", {"value": value, "source": source, "type": t}))


@tool(ACTION)
def create_event(info: str, attributes: list[dict[str, Any]], threat_level: str = "medium", tags: list[str] | None = None) -> str:
    """Create a MISP event for this incident, UNPUBLISHED and restricted to your organisation (an analyst reviews
    and publishes it in MISP). attributes: [{type: ip-dst|domain|url|sha256|filename|..., value, category?, to_ids?, comment?}]"""
    if threat_level not in THREAT:
        raise ValueError(f"threat_level must be one of {list(THREAT)}")
    event = {"info": info[:500], "distribution": 0, "threat_level_id": THREAT[threat_level], "analysis": 1,
             "published": False,
             "Attribute": [{"type": a["type"], "value": a["value"], "category": a.get("category", "Network activity"),
                            "to_ids": bool(a.get("to_ids", True)), "comment": str(a.get("comment", ""))[:500],
                            "distribution": 5} for a in attributes[:500]],
             "Tag": [{"name": t} for t in (tags or [])]}
    res = _req("POST", "/events/add", {"Event": event})
    ev = res.get("Event", res)
    return dumps({"id": ev.get("id"), "uuid": ev.get("uuid"), "published": ev.get("published"),
                  "distribution": ev.get("distribution"), "attributes": len(event["Attribute"])})


if __name__ == "__main__":
    mcp.run()
