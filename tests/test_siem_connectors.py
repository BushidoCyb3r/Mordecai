"""Security Onion and Elastic connector tests against a mock Elasticsearch. Request and response shapes follow
what a live Security Onion 3.4.0 grid returned (synthetic values): Zeek datasets are zeek.<log>, alerts live in
logs-*.alerts-so, and read-only API keys get 403 from the metadata APIs."""

from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path

import httpx
import pytest
from mcp.server.mcpserver.exceptions import ToolError

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

FORBIDDEN = {"error": {"type": "security_exception", "reason": "action [indices:admin/data_stream/get] is unauthorized for API key"}, "status": 403}
INVENTORY = {"hits": {"total": {"value": 10000, "relation": "gte"}, "hits": []}, "aggregations": {"i": {"buckets": [
    {"key": ".ds-logs-zeek-so-2026.10.25-000016", "doc_count": 900, "last": {"value_as_string": "2026-11-09T23:59:00.000Z"}},
    {"key": ".ds-logs-zeek-so-2026.09.25-000014", "doc_count": 600, "last": {"value_as_string": "2026-10-25T17:00:00.000Z"}},
    {"key": ".ds-logs-suricata.alerts-so-2026.11.09-000443", "doc_count": 40, "last": {"value_as_string": "2026-11-09T22:00:00.000Z"}},
    {"key": "elastalert_status", "doc_count": 7, "last": {}}]}}}


def load(monkeypatch, module, env):
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    mod = importlib.import_module(f"mordecai.servers.{module}")
    return importlib.reload(mod)


def mock(m, base, handler, seen):
    def wrapped(req: httpx.Request):
        body = json.loads(req.content) if req.content else None
        seen.append((req.method, req.url.path, dict(req.url.params), body))
        assert req.headers["authorization"] == "ApiKey k3y"
        return handler(req.method, req.url.path, body)
    m.es.http = httpx.Client(base_url=base, headers={"Authorization": "ApiKey k3y"}, transport=httpx.MockTransport(wrapped))


def test_security_onion(monkeypatch):
    so = load(monkeypatch, "security_onion", {"SO_URL": "https://so.invalid:9200", "SO_API_KEY": "k3y"})
    seen: list = []

    def handler(method, path, body):
        if path == "/logs-*.alerts-so/_search" and "aggs" in body:
            return httpx.Response(200, json={"hits": {"total": {"value": 43}, "hits": []}, "aggregations": {"rule": {"buckets": [
                {"key": "ET MALWARE Example Beacon", "doc_count": 27, "sev": {"buckets": [{"key": "high"}]},
                 "module": {"buckets": [{"key": "suricata"}]}, "src": {"value": 1}, "dst": {"value": 2},
                 "last": {"value_as_string": "2026-11-09T19:34:59.343Z"}},
                {"key": "Security Onion - Grid Node Login Failure (SSH)", "doc_count": 16, "sev": {"buckets": [{"key": "high"}]},
                 "module": {"buckets": [{"key": "sigma"}]}, "src": {"value": 0}, "dst": {"value": 0}, "last": {}}]}}})
        if path == "/logs-*.alerts-so/_search":
            return httpx.Response(200, json={"hits": {"total": {"value": 1}, "hits": [{"_index": ".ds-logs-suricata.alerts-so-2026.11.09-000443", "_id": "a1",
                "_source": {"@timestamp": "2026-11-09T19:34:59Z", "event": {"dataset": "suricata.alert", "module": "suricata", "severity_label": "high"},
                            "rule": {"name": "ET MALWARE Example Beacon", "uuid": "2069174"}, "source": {"ip": "10.0.0.1"}, "destination": {"ip": "10.0.0.47"},
                            "network": {"community_id": "1:abc="}}}]}})
        if path == "/logs-zeek-so/_search":
            return httpx.Response(200, json={"hits": {"total": {"value": 5000}, "hits": []}, "aggregations": {"pair": {"buckets": [
                {"key": ["10.0.0.5", "10.0.0.1", 53], "doc_count": 12000, "hours": {"buckets": [{}] * 7}, "avg_bytes": {"value": 40.0}},
                {"key": ["10.0.0.9", "203.0.113.7", 443], "doc_count": 1400, "hours": {"buckets": [{}] * 24}, "avg_bytes": {"value": 3100.0}}]}}})
        if path == "/_data_stream/logs-*":
            return httpx.Response(403, json=FORBIDDEN)
        if path == "/logs-*/_search" and "i" in (body.get("aggs") or {}):
            return httpx.Response(200, json=INVENTORY)
        if path == "/_query":
            return httpx.Response(200, json={"columns": [{"name": "c", "type": "long"}, {"name": "destination.port", "type": "long"}],
                                             "values": [[4000, 443], [900, 53]]})
        return httpx.Response(404, json={"error": f"unexpected {method} {path}"})

    mock(so, "https://so.invalid:9200", handler, seen)

    summary = json.loads(so.alerts_summary())
    assert summary[0]["rule"] == "ET MALWARE Example Beacon" and summary[0]["severity"] == ["high"] and summary[0]["source"] == ["suricata"]
    assert summary[1]["source"] == ["sigma"]  # SO Detections alerts come from the same alert streams
    _, path, params, body = seen[-1]
    assert path == "/logs-*.alerts-so/_search" and params.get("ignore_unavailable") == "true"
    assert "must" not in body["query"]["bool"]  # no stale event.dataset:alert filter: everything in the alert streams is an alert
    assert body["aggs"]["rule"]["aggs"]["sev"]["terms"]["field"] == "event.severity_label"

    hits = json.loads(so.alerts('source.ip:"10.0.0.1"'))
    assert hits["hits"][0]["rule"]["uuid"] == "2069174"
    q = seen[-1][3]["query"]["bool"]["must"][0]["query_string"]["query"]
    assert q == '(source.ip:"10.0.0.1")' and "event_data.message" in seen[-1][3]["_source"]

    beacons = json.loads(so.beacon_candidates(min_connections=50))
    assert beacons[0]["dst"] == "203.0.113.7" and beacons[0]["hours_active"] == 24  # most persistent pair ranks first
    _, path, _, body = seen[-1]
    assert path == "/logs-zeek-so/_search"  # zeek stream only: multi_terms breaks on streams that lack the fields
    assert {"term": {"event.dataset": "zeek.conn"}} in body["query"]["bool"]["filter"]

    streams = json.loads(so.list_data_streams())
    assert "read-only" in streams["source"]
    zeek = streams["streams"][0]
    assert zeek == {"name": "logs-zeek-so", "docs": 1500, "backing_indices": 2, "last_event": "2026-11-09T23:59:00.000Z"}
    assert {s["name"] for s in streams["streams"]} == {"logs-zeek-so", "logs-suricata.alerts-so", "elastalert_status"}

    rows = json.loads(so.esql('FROM logs-zeek-so | WHERE event.dataset == "zeek.conn" | STATS c = COUNT(*) BY destination.port'))
    assert rows["columns"] == ["c", "destination.port"] and rows["rows"][0] == [4000, 443]
    assert seen[-1][2] == {"format": "json", "drop_null_columns": "true"}

    # the field layout reaches the model through the tool descriptions
    assert "event.dataset:zeek.dns" in so.search.__doc__ and "event.dataset:conn" not in so.search.__doc__


def test_security_onion_errors(monkeypatch):
    so = load(monkeypatch, "security_onion", {"SO_URL": "https://so.invalid:9200", "SO_API_KEY": "k3y"})

    def handler(method, path, body):
        if path.startswith("/_data_stream"):
            return httpx.Response(500, json={"error": "boom"})
        return httpx.Response(401, json={"error": {"type": "security_exception", "reason": "unable to authenticate with provided credentials"}})

    mock(so, "https://so.invalid:9200", handler, [])
    with pytest.raises(ToolError, match="HTTP 401.*unable to authenticate"):
        so.alerts()
    with pytest.raises(ToolError, match="HTTP 500"):  # only 403 falls back; other failures surface
        so.list_data_streams()
    with pytest.raises(ToolError, match="JSONDecodeError"):
        so.search_dsl("{not json")


def test_elastic(monkeypatch):
    el = load(monkeypatch, "elastic", {"ES_URL": "https://es.invalid:9200", "ES_API_KEY": "k3y"})
    seen: list = []
    cat_status = {"code": 403}

    def handler(method, path, body):
        if path.startswith("/_cat/indices"):
            if cat_status["code"] == 200:
                return httpx.Response(200, json=[{"index": "logs-x", "docs.count": "5", "store.size": "1kb", "health": "green"}])
            return httpx.Response(403, json=FORBIDDEN)
        if path == "/logs-*/_search" and "i" in (body.get("aggs") or {}):
            return httpx.Response(200, json=INVENTORY)
        if path.endswith("/_eql/search"):
            return httpx.Response(200, json={"hits": {"total": {"value": 1, "relation": "eq"}, "sequences": [{"events": [
                {"_source": {"process": {"name": "winword.exe"}}}, {"_source": {"process": {"name": "powershell.exe"}}}]}]}})
        if path == "/_query":
            return httpx.Response(200, json={"columns": [{"name": "c"}, {"name": "unused.field"}, {"name": "host.name"}],
                                             "values": [[3, None, "ws01"]]})  # older ES ignores drop_null_columns
        if path.startswith("/.alerts-security.alerts-*"):
            return httpx.Response(200, json={"hits": {"hits": []}, "aggregations": {"rule": {"buckets": [
                {"key": "Suspicious PowerShell", "doc_count": 3, "hosts": {"value": 2}, "sev": {"buckets": [{"key": "high"}]}}]}}})
        if path.endswith("/_search") and "ioc" in (body.get("aggs") or {}):
            return httpx.Response(200, json={"hits": {"hits": []}, "aggregations": {"ioc": {"buckets": {
                "evil.example": {"doc_count": 2, "first": {"value_as_string": "2026-11-01T00:00:00Z"}, "last": {"value_as_string": "2026-11-02T00:00:00Z"},
                                 "where": {"buckets": [{"key": "ws01", "doc_count": 2}]}, "idx": {"buckets": [{"key": ".ds-logs-x"}]}},
                "absent.example": {"doc_count": 0}}}}})
        return httpx.Response(404, json={"error": f"unexpected {method} {path}"})

    mock(el, "https://es.invalid:9200", handler, seen)

    inv = json.loads(el.list_indices("logs-*"))  # read-only key: _cat is forbidden -> aggregation fallback
    assert inv["streams"][0]["name"] == "logs-zeek-so" and seen[-1][1] == "/logs-*/_search"
    cat_status["code"] = 200
    assert json.loads(el.list_indices("logs-*"))[0]["index"] == "logs-x"  # privileged key: _cat passthrough

    seq = json.loads(el.eql('sequence by host.name [process where process.name == "winword.exe"] [process where process.name == "powershell.exe"]'))
    assert [e["process"]["name"] for e in seq["sequences"][0]] == ["winword.exe", "powershell.exe"]
    assert seen[-1][3]["filter"]["range"]["@timestamp"]["gte"] == "now-24h"

    out = json.loads(el.esql("FROM logs-* | STATS c = COUNT(*) BY host.name"))
    assert out["columns"] == ["c", "host.name"] and out["rows"] == [[3, "ws01"]]  # all-null column dropped client-side

    sweep = json.loads(el.ioc_sweep(["evil.example", "absent.example"]))
    assert sweep["evil.example"]["top_hosts"] == [["ws01", 2]] and sweep["absent.example"] == {"hits": 0}
    assert seen[-1][3]["aggs"]["ioc"]["aggs"]["where"]["terms"]["field"] == "host.name"

    summary = json.loads(el.alerts_summary())
    assert summary == [{"rule": "Suspicious PowerShell", "count": 3, "hosts": 2, "severity": ["high"]}]
    assert {"term": {"kibana.alert.workflow_status": "open"}} in seen[-1][3]["query"]["bool"]["filter"]


def test_samples_are_flagged_and_pairs_count_the_whole_window(monkeypatch):
    """A 4B model once reported 'all alerts come from X' after reading 10 of 40. Sampling is fine, but a sample must
    say it is one, and the summary / pair_counts must give whole-window host pairs to verify conclusions against."""
    so = load(monkeypatch, "security_onion", {"SO_URL": "https://so.invalid:9200", "SO_API_KEY": "k3y"})
    seen: list = []
    pairs = {"buckets": [
        {"key": "10.99.1.1", "doc_count": 30, "dst": {"buckets": [{"key": "10.99.1.47", "doc_count": 24}, {"key": "10.99.1.6", "doc_count": 6}]}},
        {"key": "172.31.5.1", "doc_count": 10, "dst": {"buckets": [{"key": "172.31.5.17", "doc_count": 10}]}}]}

    def handler(method, path, body):
        aggs = body.get("aggs") or {}
        if "rule" in aggs:
            return httpx.Response(200, json={"hits": {"total": {"value": 40}, "hits": []}, "aggregations": {"rule": {"buckets": [
                {"key": "ET MALWARE BPFDoor ICMP Echo Reply", "doc_count": 40, "sev": {"buckets": [{"key": "high"}]},
                 "module": {"buckets": [{"key": "suricata"}]}, "src": {"value": 2}, "dst": {"value": 3}, "pairs": pairs,
                 "last": {"value_as_string": "2026-11-10T09:12:15Z"}}]}}})
        if "a" in aggs:  # pair_counts
            return httpx.Response(200, json={"hits": {"total": {"value": 45}, "hits": []}, "aggregations": {
                "a_n": {"value": 2}, "b_n": {"value": 3},
                "a": {"buckets": [{**x, "b": x["dst"]} for x in pairs["buckets"]]}}})
        hit = {"_index": "i", "_id": "1", "_source": {"source": {"ip": "172.31.5.1"}, "destination": {"ip": "172.31.5.17"}}}
        return httpx.Response(200, json={"hits": {"total": {"value": 40}, "hits": [hit] * 10}})

    mock(so, "https://so.invalid:9200", handler, seen)
    sample = json.loads(so.alerts('rule.name:"ET MALWARE BPFDoor*"', size=10))
    assert sample["returned"] == 10 and sample["total"] == 40 and sample["sample"].startswith("SAMPLE: 10 of 40")
    assert "verify over the full window" in sample["sample"]
    assert list(sample)[:3] == ["total", "returned", "sample"]  # the warning comes before the rows

    row = json.loads(so.alerts_summary())[0]
    assert row["top_pairs"] == ["10.99.1.1 -> 10.99.1.47: 24", "172.31.5.1 -> 172.31.5.17: 10", "10.99.1.1 -> 10.99.1.6: 6"]
    assert "pairs_cover" not in row  # the pairs account for all 40

    out = json.loads(so.pair_counts('rule.name:"ET MALWARE BPFDoor*"', alerts_only=True))
    assert out["pairs"][0] == "10.99.1.1 -> 10.99.1.47: 24" and out["distinct_source.ip"] == 2
    assert "5 of 45 events are not in these pairs" in out["not_in_pairs"]
    _, path, params, body = seen[-1]
    assert path == "/logs-*.alerts-so/_search" and body["track_total_hits"] is True
    assert body["query"]["bool"]["must"][0]["query_string"]["query"] == '(rule.name:"ET MALWARE BPFDoor*")'
    so.pair_counts("event.dataset:zeek.conn")
    assert seen[-1][1] == "/logs-*-so/_search"  # not alerts_only: all SO data

    # full results are not flagged
    def full(method, path, body):
        return httpx.Response(200, json={"hits": {"total": {"value": 1}, "hits": [{"_index": "i", "_id": "1", "_source": {}}]}})
    mock(so, "https://so.invalid:9200", full, seen)
    assert "sample" not in json.loads(so.search("x"))


def test_security_onion_detection_coverage_and_alert_techniques(monkeypatch):
    """Coverage from SO's own detection store (enabled rules only, ATT&CK ids from Sigma tags, Suricata metadata and
    YARA meta lines) and the techniques alerts pointed at (Suricata metadata, SO Detections via the rule's tags)."""
    so = load(monkeypatch, "security_onion", {"SO_URL": "https://so.invalid:9200", "SO_API_KEY": "k3y"})
    seen: list = []
    sigma = "title: x\ntags:\n  - attack.execution\n  - attack.t1059.001\n  - attack.T1105\n"
    suri = 'alert http any any -> any any (msg:"ET x"; metadata:mitre_technique_id T1071, mitre_technique_id T1105;)'
    yara = 'rule r { meta:\n  mitre_attack = "T1027"\n  author = "T1234 is not a technique here"\n condition: true }'
    docs = {"elastalert": [sigma, "title: untagged"], "suricata": [suri], "strelka": [yara]}

    def handler(method, path, body):
        if path == "/so-detection/_count":
            eng = body["query"]["bool"]["filter"][1]["term"]["so_detection.engine"]
            return httpx.Response(200, json={"count": {"elastalert": 2, "suricata": 50, "strelka": 1}[eng]})
        if path == "/so-detection/_search" and "sort" in body:
            flt = body["query"]["bool"]["filter"]
            assert flt[0] == {"term": {"so_detection.isEnabled": True}}   # enabled rules only
            eng = flt[1]["term"]["so_detection.engine"]
            if eng == "suricata":
                assert flt[2] == {"match_phrase": {"so_detection.content": "mitre_technique_id"}}
            return httpx.Response(200, json={"hits": {"hits": [{"_source": {"so_detection": {"content": c}}, "sort": [i]}
                                                               for i, c in enumerate(docs[eng])]}})
        if path == "/so-detection/_search":   # the rules behind SO Detections alerts
            assert body["query"] == {"terms": {"so_detection.publicId": ["u-1"]}}
            return httpx.Response(200, json={"hits": {"hits": [{"_source": {"so_detection": {
                "publicId": "u-1", "engine": "elastalert", "content": sigma}}}]}})
        if path == "/logs-*.alerts-so/_search" and "t" in body.get("aggs", {}):
            return httpx.Response(200, json={"aggregations": {"t": {"buckets": [
                {"key": "T1071", "doc_count": 12, "r": {"buckets": [{"key": "ET C2 x", "doc_count": 12}]}},
                {"key": "not-an-id", "doc_count": 3, "r": {"buckets": []}}]}}})
        if path == "/logs-*.alerts-so/_search" and "u" in body.get("aggs", {}):
            return httpx.Response(200, json={"aggregations": {"u": {"buckets": [
                {"key": "u-1", "doc_count": 5, "n": {"buckets": [{"key": "Encoded PowerShell", "doc_count": 5}]}}]}}})
        return httpx.Response(404, json={"error": path})

    mock(so, "https://so.invalid:9200", handler, seen)
    cov = json.loads(so.detection_coverage())
    assert cov["rules"]["sigma"] == {"enabled": 2, "with_attack_ids": 1, "without": 1}
    assert cov["rules"]["suricata"] == {"enabled": 50, "with_attack_ids": 1, "without": 49}
    assert cov["techniques"] == {"T1027": {"yara": 1}, "T1059.001": {"sigma": 1}, "T1071": {"suricata": 1},
                                 "T1105": {"sigma": 1, "suricata": 1}}
    with pytest.raises(ToolError, match="Error"):
        so.detection_coverage(["splunk"])
    obs = json.loads(so.alert_techniques("now-7d"))
    assert obs["techniques"]["T1071"]["alerts"] == 12 and "NOT-AN-ID" not in obs["techniques"]
    assert obs["techniques"]["T1059.001"] == {"alerts": 5, "top_rules": [["Encoded PowerShell", 5]]}
    assert obs["techniques"]["T1105"]["alerts"] == 5


def test_sigma_backtest(monkeypatch):
    """Converted locally (pySigma), run as one read-only search with the window, top values and samples."""
    pytest.importorskip("sigma.backends.elasticsearch")
    so = load(monkeypatch, "security_onion", {"SO_URL": "https://so.invalid:9200", "SO_API_KEY": "k3y"})
    seen: list = []
    rule = ("title: curl run\nid: 0f6c2c55-9a43-4f1e-8d7b-3b2e1c4d5a66\nlevel: low\ntags: [attack.t1105]\n"
            "logsource: {product: linux, category: process_creation}\n"
            "detection:\n  sel:\n    process.executable|endswith: /curl\n  condition: sel\n")

    def handler(method, path, body):
        assert path == "/logs-endpoint.events.process-default/_search" and method == "POST"
        return httpx.Response(200, json={"hits": {"total": {"value": 30}, "hits": [{"_source": {"host.name": "h1"}}]},
                                         "aggregations": {"per_day": {"buckets": [
                                             {"key_as_string": "2026-11-01T00:00:00.000Z", "doc_count": 20},
                                             {"key_as_string": "2026-11-02T00:00:00.000Z", "doc_count": 10}]},
                                             "first": {"value_as_string": "2026-11-01T01:00:00Z"},
                                             "last": {"value_as_string": "2026-11-02T09:00:00Z"},
                                             "host.name": {"buckets": [{"key": "h1", "doc_count": 30}]}}})

    mock(so, "https://so.invalid:9200", handler, seen)
    r = json.loads(so.sigma_backtest(rule, [], "logs-endpoint.events.process-default", start="2026-11-01",
                                     end="2026-11-11"))["rules"][0]
    assert r["title"] == "curl run" and "curl" in r["query"] and r["total"] == 30 and r["avg_per_day"] == 3.0
    assert r["per_day"] == {"2026-11-01": 20, "2026-11-02": 10} and r["top"] == {"host.name": [["h1", 30]]}
    body = seen[-1][3]
    assert body["query"]["bool"]["filter"][1] == {"range": {"@timestamp": {"gte": "2026-11-01T00:00:00+00:00",
                                                                            "lte": "2026-11-11T00:00:00+00:00"}}}
    for bad in ({"days": 30, "start": "last week"}, {"start": "2026-01-01", "end": "2026-11-01"},
                {"pipelines": ["no_such_pipeline"]}, {"index": "logs/_delete_by_query"}):
        with pytest.raises(ToolError, match="Error"):
            so.sigma_backtest(rule, **{"pipelines": [], **bad})
    with pytest.raises(ToolError, match="did not convert"):
        so.sigma_backtest("title: broken\ndetection: {}\n")


def test_search_timeout_is_enforced_by_the_cluster(monkeypatch):
    """Every _search carries the cluster-side limit (an agent's own body cannot raise it), and a search that hit it
    is an error, never partial counts read as facts."""
    so = load(monkeypatch, "security_onion", {"SO_URL": "https://so.invalid:9200", "SO_API_KEY": "k3y",
                                              "SO_SEARCH_TIMEOUT": "45s"})
    seen: list = []
    timed_out = {"v": False}

    def handler(method, path, body):
        return httpx.Response(200, json={"timed_out": timed_out["v"], "hits": {"total": {"value": 3}, "hits": []}})

    mock(so, "https://so.invalid:9200", handler, seen)
    so.search("event.dataset:zeek.conn")
    so.search_dsl(json.dumps({"query": {"match_all": {}}, "timeout": "1h"}))
    assert [b["timeout"] for _, p, _, b in seen if p.endswith("/_search")] == ["45s", "45s"]
    timed_out["v"] = True
    with pytest.raises(ToolError, match="hit the 45s limit"):
        so.search("*")
    with pytest.raises(ValueError, match="SO_SEARCH_TIMEOUT"):
        load(monkeypatch, "security_onion", {"SO_URL": "https://so.invalid:9200", "SO_SEARCH_TIMEOUT": "1h; x"})
