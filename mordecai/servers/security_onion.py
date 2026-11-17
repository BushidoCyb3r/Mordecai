"""MCP server: Security Onion 3 (read-only, via its Elasticsearch backend).

Field layout verified against a live Security Onion 3.4.0 grid:
  - Zeek: data stream logs-zeek-so, event.module:zeek, event.dataset:zeek.<log> (zeek.conn, zeek.dns, zeek.http,
    zeek.ssl, zeek.file, zeek.x509, zeek.notice, zeek.weird...), plus client.bytes/server.bytes, log.id.uid.
  - Alerts: logs-suricata.alerts-so (event.dataset:suricata.alert, rule.name, rule.uuid = SID, rule.severity 1-3)
    and logs-detections.alerts-so (SO Detections: event.dataset:sigma.alert..., the matched event under event_data.*).
    Both carry event.severity_label (low|medium|high|critical).
  - network.community_id joins Suricata alerts with Zeek records.

Access: authenticate with an encoded read-only Elasticsearch API key (or a local SOC account with ES access).
Use the standalone/managersearch node or distributed manager endpoint. For remote direct access, allow TCP
9200 via the destination node's firewall.hostgroups.elasticsearch_rest override if needed; see SETUP.md section 2.
TLS: the default grid CA is /etc/pki/ca.crt on the manager/single node; the URL must match the endpoint certificate.
A read-only key without view_index_metadata works: list_data_streams falls back to a read-only aggregation.
Security Onion Pro also ships an official MCP server (Connect API / OQL) - it can be added to harness.yaml
alongside this connector.

Env: SO_URL (https://<manager>:9200), SO_API_KEY | SO_USER + SO_PASS, SO_VERIFY (path to ca.crt | true | false),
     SO_INDEX (default "logs-*-so"), SO_ALERT_INDEX (default "logs-*.alerts-so"), SO_ZEEK_INDEX (default
     "logs-zeek-so"), SO_DETECTION_INDEX (SO's detection store, default "so-detection"), SO_ALERT_QUERY (extra filter
     on alerts, default none), SO_SEVERITY_FIELD (default "event.severity_label"), SO_MAX_HITS, SO_SEARCH_TIMEOUT
     (the limit the cluster enforces on each search, default 60s), SO_TIMEOUT (seconds the client waits, 120)
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from typing import Any

from mcp.server.mcpserver import MCPServer

from .common import tool_factory, READ, ESClient, ESHTTPError, dumps, env, check_index

mcp = MCPServer("security_onion", instructions="Read-only Security Onion NSM/alert data: Suricata, Zeek, Strelka, endpoint logs.")
tool = tool_factory(mcp)
es = ESClient("SO")
INDEX = env("SO_INDEX", "logs-*-so")
ALERT_INDEX = env("SO_ALERT_INDEX", "logs-*.alerts-so")
ZEEK_INDEX = env("SO_ZEEK_INDEX", "logs-zeek-so")
ALERT_Q = env("SO_ALERT_QUERY", "")
SEV = env("SO_SEVERITY_FIELD", "event.severity_label")
ALERT_FIELDS = ["@timestamp", "event.module", "event.dataset", "rule.name", "rule.uuid", "rule.category", SEV, "rule.severity",
                "source.ip", "source.port", "destination.ip", "destination.port", "network.community_id", "observer.name",
                "event_data.host.name", "event_data.user.name", "event_data.source.ip", "event_data.process.command_line",
                "event_data.message"]


def _alert_query(extra: str) -> str:
    parts = [p for p in (ALERT_Q, "" if extra.strip() in ("", "*") else extra) if p]
    return " AND ".join(f"({p})" for p in parts) or "*"


def _rule_row(b: dict) -> dict:
    pairs = sorted(((x["key"], y["key"], y["doc_count"]) for x in b.get("pairs", {}).get("buckets", [])
                    for y in x.get("dst", {}).get("buckets", [])), key=lambda t: -t[2])
    row = {"rule": b["key"], "count": b["doc_count"], "severity": [s["key"] for s in b["sev"]["buckets"]],
           "source": [m["key"] for m in b["module"]["buckets"]],
           "distinct_src": b["src"]["value"], "distinct_dst": b["dst"]["value"],
           "top_pairs": [f"{x} -> {y}: {c}" for x, y, c in pairs[:5]], "last_seen": b["last"].get("value_as_string")}
    covered = sum(c for _, _, c in pairs[:5])
    if pairs and covered < b["doc_count"]:
        row["pairs_cover"] = f"{covered} of {b['doc_count']} (use pair_counts for the rest)"
    return row


@tool(READ)
def alerts_summary(start: str = "now-24h", end: str = "now") -> str:
    """Alerts (Suricata + SO Detections/Sigma) grouped by rule over the WHOLE window: severity, source module,
    count, distinct source/destination IPs, the top source -> destination pairs with counts, and last seen.
    Start triage here; it answers "which hosts" without sampling."""
    body: dict = {"size": 0, "query": {"bool": {"filter": [es.time_filter(start, end)]}},
                  "aggs": {"rule": {"terms": {"field": "rule.name", "size": 75},
                                    "aggs": {"sev": {"terms": {"field": SEV, "size": 3}},
                                             "module": {"terms": {"field": "event.module", "size": 3}},
                                             "src": {"cardinality": {"field": "source.ip"}},
                                             "dst": {"cardinality": {"field": "destination.ip"}},
                                             "pairs": {"terms": {"field": "source.ip", "size": 5},
                                                       "aggs": {"dst": {"terms": {"field": "destination.ip", "size": 5}}}},
                                             "last": {"max": {"field": "@timestamp"}}}}}}
    if (q := _alert_query("")) != "*":
        body["query"]["bool"]["must"] = [{"query_string": {"query": q}}]
    res = es.req("POST", f"/{ALERT_INDEX}/_search", body, params={"ignore_unavailable": "true"})
    return dumps([_rule_row(b) for b in res["aggregations"]["rule"]["buckets"]])


@tool(READ)
def alerts(query: str = "*", start: str = "now-24h", end: str = "now", size: int = 50) -> str:
    """Individual alerts (Suricata, SO Detections Sigma/YARA) newest first, optionally narrowed by a query such as
    'rule.name:"ET HUNTING*"', 'event.severity_label:high', 'source.ip:10.1.2.3' or 'event.module:sigma'.
    Sigma alerts hold the matched log under event_data.* (event_data.host.name, event_data.message...).
    Returns a SAMPLE when more alerts match than `size` - good for reading; verify any conclusion about hosts or
    counts with alerts_summary or pair_counts, which count the whole window."""
    return es.search(ALERT_INDEX, _alert_query(query), start, end, size, ALERT_FIELDS)


@tool(READ)
def pair_counts(query: str = "*", start: str = "now-24h", end: str = "now", source_field: str = "source.ip",
                destination_field: str = "destination.ip", alerts_only: bool = False, size: int = 20) -> str:
    """Who talked to whom over the WHOLE window: event counts per source -> destination pair for any query, e.g.
    query='rule.name:"ET MALWARE BPFDoor*"' alerts_only=true, or query='event.dataset:zeek.conn AND destination.port:22'.
    Use it to verify what you concluded from a sample of events. Also works for other field pairs
    (e.g. source_field=source.ip destination_field=dns.query.name)."""
    return es.pair_counts(ALERT_INDEX if alerts_only else INDEX, _alert_query(query) if alerts_only else query,
                          start, end, source_field, destination_field, size)


@tool(READ)
def search(query: str, start: str = "now-24h", end: str = "now", size: int = 50, fields: list[str] | None = None,
           index: str = "") -> str:
    """Search any Security Onion data with Lucene/query_string. Zeek logs are event.dataset:zeek.<log>, e.g.
    'event.dataset:zeek.dns AND dns.query.name:*.xyz', 'event.dataset:zeek.conn AND destination.port:3389',
    'event.dataset:zeek.ssl AND NOT ssl.established:true'. Zeek datasets: zeek.conn, zeek.dns, zeek.http, zeek.ssl,
    zeek.file, zeek.x509, zeek.notice, zeek.weird, zeek.smb_files, zeek.kerberos... Alerts: event.dataset:suricata.alert
    (or use the alerts tool). Common fields: source.ip/port, destination.ip/port, network.community_id, log.id.uid,
    client.bytes, server.bytes, observer.name. `index` defaults to all SO data (logs-*-so); logs-zeek-so is faster
    for Zeek-only searches. Use list_data_streams to see which sources exist."""
    return es.search(index or INDEX, query, start, end, size, fields)


@tool(READ)
def search_dsl(body_json: str, index: str = "") -> str:
    """Raw Elasticsearch DSL (JSON string) against Security Onion indices, for aggregations."""
    return es.search_dsl(index or INDEX, json.loads(body_json))


@tool(READ)
def esql(query: str) -> str:
    """ES|QL against Security Onion data (Elasticsearch 9.x), e.g. 'FROM logs-zeek-so | WHERE event.dataset == "zeek.conn"
    AND @timestamp > NOW() - 1 day | STATS c = COUNT(*) BY destination.ip | SORT c DESC | LIMIT 20'.
    For raw rows always KEEP the columns you need (e.g. | KEEP @timestamp, source.ip, destination.ip) - SO data has
    thousands of fields."""
    return es.esql(query)


@tool(READ)
def community_id_pivot(community_id: str, start: str = "now-7d", end: str = "now") -> str:
    """Pull every record (alerts, Zeek conn/dns/http/ssl/files, Strelka) sharing a network.community_id - full flow context."""
    return es.search(INDEX, f'network.community_id:"{community_id}"', start, end, 100, None, sort_desc=False)


@tool(READ)
def field_values(field: str, query: str = "*", start: str = "now-24h", end: str = "now", size: int = 25,
                 rarest: bool = False) -> str:
    """Stack a field (top or rarest values), e.g. field=dns.query.name query='event.dataset:zeek.dns' rarest=true,
    or field=rule.name query='event.dataset:suricata.alert'."""
    return es.field_values(INDEX, field, query, start, end, size, rarest)


@tool(READ)
def ioc_sweep(values: list[str], start: str = "now-30d", end: str = "now") -> str:
    """Sweep IOCs across all Security Onion data: hits, first/last seen, top source IPs."""
    return es.ioc_sweep(INDEX, values, start, end, "source.ip")


@tool(READ)
def beacon_candidates(start: str = "now-24h", end: str = "now", min_connections: int = 50, size: int = 25) -> str:
    """Find beaconing candidates in Zeek conn logs: src->dst:port pairs with many connections; returns count, distinct
    hours active and average bytes so the analyst/agent can examine interval regularity next (expect DNS to the
    local resolver and other infrastructure chatter near the top - judge, don't assume)."""
    body = {"size": 0, "query": {"bool": {"filter": [es.time_filter(start, end), {"term": {"event.dataset": "zeek.conn"}}]}},
            "aggs": {"pair": {"multi_terms": {"terms": [{"field": "source.ip"}, {"field": "destination.ip"}, {"field": "destination.port"}],
                                              "size": 500, "min_doc_count": max(min_connections, 2)},
                              "aggs": {"hours": {"date_histogram": {"field": "@timestamp", "fixed_interval": "1h", "min_doc_count": 1}},
                                       "avg_bytes": {"avg": {"field": "client.bytes"}}}}}}
    # Zeek stream only: multi_terms fails at reduce when some indices in the pattern lack a field (SOC/Kratos streams)
    res = es.req("POST", f"/{ZEEK_INDEX}/_search", body)
    rows = [{"src": b["key"][0], "dst": b["key"][1], "dport": b["key"][2], "connections": b["doc_count"],
             "hours_active": len(b["hours"]["buckets"]), "avg_client_bytes": b["avg_bytes"]["value"]}
            for b in res["aggregations"]["pair"]["buckets"]]
    rows.sort(key=lambda r: (-r["hours_active"], -r["connections"]))
    return dumps(rows[:size])


@tool(READ)
def list_data_streams(pattern: str = "logs-*") -> str:
    """List the data streams that hold data (where SO3 stores each log source), with doc counts and newest event -
    verify a source exists before hunting in it."""
    try:
        res = es.req("GET", f"/_data_stream/{check_index(pattern or '*')}")
        return dumps([{"name": d["name"], "indices": len(d.get("indices", [])), "status": d.get("status")}
                      for d in res.get("data_streams", [])][:500])
    except ESHTTPError as e:
        if e.status != 403:
            raise
    return dumps({"source": "aggregation on _index (API key lacks view_index_metadata - expected for read-only keys)",
                  "streams": es.inventory(pattern)[:500]})


@tool(READ)
def sigma_backtest(rule: str, pipelines: list[str] | None = None, index: str = "", days: int = 30, start: str = "",
                   end: str = "", sample: int = 3) -> str:
    """Back-test a Sigma rule (YAML text) against Security Onion history before proposing it. Converted locally with
    pySigma (Lucene backend) using the processing `pipelines` you name - e.g. ["ecs_windows"] for Elastic Agent /
    Winlogbeat Windows events, ["ecs_zeek_beats"] for Zeek; wrong pipeline = wrong field names = no hits. Returns
    the query, total hits, hits per day, the top hosts / users / processes / event codes and a few sample events.
    Run it twice: over the window where the real activity happened (start/end, ISO; it must catch it) and over a
    normal recent window (days, default 30, at most 90; its noise). Read-only. `index` defaults to all SO data (logs-*-so); Windows endpoint data
    from Elastic Agent sits in logs-windows* / logs-system* streams (see list_data_streams)."""
    from .sigma_backtest import backtest
    return dumps(backtest(es, INDEX, rule, pipelines, index, days, start, end, sample))


DETECTION_INDEX = env("SO_DETECTION_INDEX", "so-detection")
ENGINES = {"sigma": "elastalert", "suricata": "suricata", "yara": "strelka"}
_SIGMA_TAG = re.compile(r"attack\.(t\d{4}(?:\.\d{3})?)\b", re.I)
_SURICATA_TAG = re.compile(r"mitre_technique_id\s+(T\d{4}(?:\.\d{3})?)\b")
_ANY_TAG = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b")


def _techniques(engine: str, content: str) -> set[str]:
    if engine == "elastalert":
        return {m.upper() for m in _SIGMA_TAG.findall(content)}
    if engine == "suricata":
        return set(_SURICATA_TAG.findall(content))
    # YARA: only technique ids on lines that talk about ATT&CK (a bare T1234 elsewhere could be anything)
    return {m for line in content.splitlines() if re.search(r"(?i)mitre|att&?ck", line) for m in _ANY_TAG.findall(line)}


def _enabled_detections(engine: str, extra: dict[str, Any] | None = None, fields: list[str] | None = None):
    """Every enabled SO detection of one engine (paged), as so_detection dicts."""
    flt: list[dict[str, Any]] = [{"term": {"so_detection.isEnabled": True}}, {"term": {"so_detection.engine": engine}}]
    if extra:
        flt.append(extra)
    after = None
    while True:
        body: dict[str, Any] = {"size": 1000, "sort": ["_doc"], "query": {"bool": {"filter": flt}},
                                "_source": fields or ["so_detection.content", "so_detection.publicId", "so_detection.title"]}
        if after:
            body["search_after"] = after
        hits = es.req("POST", f"/{check_index(DETECTION_INDEX)}/_search", body)["hits"]["hits"]
        for h in hits:
            yield (h.get("_source") or {}).get("so_detection") or {}
        if len(hits) < 1000:
            return
        after = hits[-1]["sort"]


@tool(READ)
def detection_coverage(engines: list[str] | None = None) -> str:
    """Which ATT&CK techniques your ENABLED Security Onion detections cover, from SO's own detection store: Sigma
    rules (their attack.tXXXX tags), Suricata rules (mitre_technique_id metadata) and YARA rules (ATT&CK ids in
    their meta). Per technique: how many enabled rules of each engine; plus how many enabled rules carry no ATT&CK
    id at all (coverage you cannot see in a layer). Feed `techniques` to attack_coverage_layer. Read-only."""
    want = engines or list(ENGINES)
    bad = [e for e in want if e not in ENGINES]
    if bad:
        raise ValueError(f"engines: any of {list(ENGINES)}")
    techniques: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    totals: dict[str, dict[str, int]] = {}
    for name in want:
        eng = ENGINES[name]
        enabled = es.req("POST", f"/{check_index(DETECTION_INDEX)}/_count", {"query": {"bool": {"filter": [
            {"term": {"so_detection.isEnabled": True}}, {"term": {"so_detection.engine": eng}}]}}})["count"]
        # Suricata: only rules that carry ATT&CK metadata are fetched (tens of thousands otherwise)
        extra = {"match_phrase": {"so_detection.content": "mitre_technique_id"}} if eng == "suricata" else None
        mapped = 0
        for d in _enabled_detections(eng, extra, ["so_detection.content"]):
            t = _techniques(eng, str(d.get("content", "")))
            mapped += bool(t)
            for tid in t:
                techniques[tid][name] += 1
        totals[name] = {"enabled": enabled, "with_attack_ids": mapped, "without": enabled - mapped}
    flat = {tid: dict(v) for tid, v in sorted(techniques.items())}
    return dumps({"rules": totals, "technique_count": len(flat), "techniques": flat,
                  "note": "Counts are enabled rules, not proof they fire on your data: back-test with sigma_backtest "
                          "and compare with alert_techniques (what actually fired)."})


@tool(READ)
def alert_techniques(start: str = "now-30d", end: str = "now") -> str:
    """Which ATT&CK techniques your Security Onion alerts point at over a window: Suricata alerts by their
    rule.metadata.mitre_technique_id, and SO Detections alerts (Sigma, YARA) by their rule's ATT&CK ids in the
    detection store. Per technique: alert count and the top rules. A technique that fires without matching
    coverage, or coverage that never fires, is what a coverage layer is for. Read-only."""
    out: dict[str, dict[str, Any]] = defaultdict(lambda: {"alerts": 0, "rules": defaultdict(int)})
    flt = [es.time_filter(start, end)]
    sur = es.req("POST", f"/{check_index(ALERT_INDEX)}/_search", {"size": 0, "query": {"bool": {"filter": flt}},
        "aggs": {"t": {"terms": {"field": "rule.metadata.mitre_technique_id", "size": 1000},
                       "aggs": {"r": {"terms": {"field": "rule.name", "size": 3}}}}}},
        params={"ignore_unavailable": "true"})
    for b in sur.get("aggregations", {}).get("t", {}).get("buckets", []):
        tid = str(b["key"]).upper()
        if not _ANY_TAG.fullmatch(tid):
            continue
        out[tid]["alerts"] += b["doc_count"]
        for r in b["r"]["buckets"]:
            out[tid]["rules"][r["key"]] += r["doc_count"]
    det = es.req("POST", f"/{check_index(ALERT_INDEX)}/_search", {"size": 0, "query": {"bool": {"filter": flt + [
        {"exists": {"field": "rule.uuid"}}], "must_not": [{"term": {"event.module": "suricata"}}]}},
        "aggs": {"u": {"terms": {"field": "rule.uuid", "size": 2000}, "aggs": {"n": {"terms": {"field": "rule.name", "size": 1}}}}}},
        params={"ignore_unavailable": "true"})
    buckets = det.get("aggregations", {}).get("u", {}).get("buckets", [])
    if buckets:
        ids = [b["key"] for b in buckets]
        docs = es.req("POST", f"/{check_index(DETECTION_INDEX)}/_search", {"size": len(ids), "_source": [
            "so_detection.publicId", "so_detection.engine", "so_detection.content"],
            "query": {"terms": {"so_detection.publicId": ids}}})["hits"]["hits"]
        tags = {}
        for h in docs:
            d = (h.get("_source") or {}).get("so_detection") or {}
            tags[d.get("publicId")] = _techniques(str(d.get("engine")), str(d.get("content", "")))
        for b in buckets:
            name = (b["n"]["buckets"] or [{"key": b["key"]}])[0]["key"]
            for tid in tags.get(b["key"], ()):
                out[tid]["alerts"] += b["doc_count"]
                out[tid]["rules"][name] += b["doc_count"]
    flat = {tid: {"alerts": v["alerts"], "top_rules": sorted(v["rules"].items(), key=lambda x: -x[1])[:3]}
            for tid, v in sorted(out.items())}
    return dumps({"window": {"start": start, "end": end}, "technique_count": len(flat), "techniques": flat})


if __name__ == "__main__":
    mcp.run()
