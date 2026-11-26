"""Rules and reference data kept on this host (config/rules.yaml, mordecai rules): fetched once into data/, used from
there, carried to an air-gapped host as a bundle. No test touches the network: sources are local files."""

from __future__ import annotations

import asyncio
import io
import json
import sys
import zipfile
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_harness import ROOT, write_config  # noqa: E402

from mordecai import rulesets  # noqa: E402

ATTACK = {"type": "bundle", "objects": [{"type": "x-mitre-collection", "name": "Enterprise ATT&CK", "x_mitre_version": "1"}]}


def make_zip(path: Path, members: dict[str, str]) -> Path:
    with zipfile.ZipFile(path, "w") as z:
        for name, text in members.items():
            z.writestr(name, text)
    return path


def test_shipped_sets_are_well_formed():
    sets = rulesets.sources(ROOT / "config")
    assert {"attack", "yara", "sigma", "capa", "volatility-windows"} <= set(sets)
    for name, s in sets.items():
        assert s["url"] and s["dest"] and s["what"] and isinstance(s.get("default", False), bool), name
        rulesets._dest(Path("/x"), s["dest"])  # relative, under data/


def test_fetch_installs_a_set_once_and_replaces_it_whole(tmp_path):
    data = tmp_path / "data"
    src = make_zip(tmp_path / "rules.zip", {"repo-main/a/one.yar": "rule a { condition: true }",
                                            "repo-main/two.yar": "rule b { condition: true }",
                                            "../escape.yar": "x", "/abs.yar": "x"})
    spec = {"url": str(src), "dest": "rules/yara", "strip": "*"}
    e = rulesets.fetch(data, "yara", spec)
    got = sorted(p.relative_to(data / "rules/yara").as_posix() for p in (data / "rules/yara").rglob("*") if p.is_file())
    assert got == ["a/one.yar", "two.yar"]  # top folder dropped; nothing written outside the set
    assert not (tmp_path / "escape.yar").exists() and not (data / "escape.yar").exists()
    assert rulesets.lock(data)["yara"]["sha256"] == e["sha256"] and rulesets.installed(data, spec)
    make_zip(src, {"repo-main/three.yar": "rule c { condition: true }"})
    rulesets.fetch(data, "yara", spec)  # a newer release replaces the set; nothing old is left behind
    assert [p.name for p in (data / "rules/yara").rglob("*.yar")] == ["three.yar"]


def test_attack_is_checked_before_it_replaces_anything(tmp_path):
    data, good, bad = tmp_path / "data", tmp_path / "good.json", tmp_path / "bad.json"
    good.write_text(json.dumps(ATTACK))
    bad.write_text(json.dumps({"type": "bundle", "objects": []}))
    spec = {"url": str(good), "dest": "attack/enterprise-attack.json", "format": "file", "check": "attack"}
    rulesets.fetch(data, "attack", spec)
    with pytest.raises(ValueError, match="not an ATT&CK"):
        rulesets.fetch(data, "attack", {**spec, "url": str(bad)})
    assert json.loads((data / "attack/enterprise-attack.json").read_text()) == ATTACK  # the good copy stays


def test_bundle_carries_sets_to_an_air_gapped_host(tmp_path):
    connected, airgapped = tmp_path / "connected", tmp_path / "airgapped"
    (tmp_path / "a.json").write_text(json.dumps(ATTACK))
    sets = {"attack": {"url": str(tmp_path / "a.json"), "dest": "attack/enterprise-attack.json", "check": "attack"},
            "sigma": {"url": str(make_zip(tmp_path / "s.zip", {"rules/windows/r.yml": "title: r"})), "dest": "rules/sigma"},
            "capa": {"url": "unused", "dest": "rules/capa"}}
    for n in ("attack", "sigma"):
        rulesets.fetch(connected, n, sets[n])
    with pytest.raises(ValueError, match="not installed here"):
        rulesets.bundle(connected, sets, tmp_path / "x.tar.gz", ["capa"])
    chosen, sha = rulesets.bundle(connected, sets, tmp_path / "rules.tar.gz")
    assert chosen == ["attack", "sigma"]
    with pytest.raises(ValueError, match="SHA-256"):
        rulesets.import_bundle(airgapped, tmp_path / "rules.tar.gz", "0" * 64)
    assert not airgapped.exists()
    assert rulesets.import_bundle(airgapped, tmp_path / "rules.tar.gz", sha) == ["attack", "sigma"]
    assert json.loads((airgapped / "attack/enterprise-attack.json").read_text()) == ATTACK  # a one-file set stays a file
    assert (airgapped / "rules/sigma/rules/windows/r.yml").read_text() == "title: r"
    assert rulesets.lock(airgapped)["sigma"]["sha256"] == rulesets.lock(connected)["sigma"]["sha256"]


def test_setup_asks_about_each_missing_set_and_stops_when_offline(tmp_path):
    data = tmp_path / "data"
    zips = {n: make_zip(tmp_path / f"{n}.zip", {f"{n}.txt": n}) for n in ("a", "b", "c")}
    sets = {"a": {"url": str(zips["a"]), "dest": "rules/a", "default": True},
            "b": {"url": str(zips["b"]), "dest": "rules/b", "default": True},
            "c": {"url": str(zips["c"]), "dest": "rules/c", "default": False}}
    answers, said = iter(["", "n", ""]), []  # Enter takes the default: a yes, b no (asked), c no (default)
    assert rulesets.setup(data, sets, lambda q: next(answers), said.append) == 0
    assert [rulesets.installed(data, s) for s in sets.values()] == [True, False, False]
    assert rulesets.setup(data, {"a": sets["a"]}, lambda q: pytest.fail("asked about an installed set"), said.append) == 0

    def offline(request):
        raise httpx.ConnectError("no route to host", request=request)
    web = {"x": {"url": "https://rules.example/x.zip", "dest": "rules/x", "default": True},
           "y": {"url": "https://rules.example/y.zip", "dest": "rules/y", "default": True}}
    asked: list[str] = []
    said.clear()
    assert rulesets.setup(data, web, lambda q: asked.append(q) or "y", said.append, httpx.MockTransport(offline)) == 1
    assert len(asked) == 1 and any("rules bundle" in s for s in said)  # no internet: stop asking, say how instead


def test_fetched_rule_folders_are_used_when_none_is_configured(tmp_path):
    from mordecai.config import load_config

    (tmp_path / "config").mkdir()
    (tmp_path / "data/rules/yara").mkdir(parents=True)
    (tmp_path / "data/rules/volatility-symbols/windows").mkdir(parents=True)
    cfg = load_config(write_config(tmp_path / "config"))
    assert cfg.forensics["yara_rules_dir"] == str(tmp_path / "data/rules/yara")
    assert cfg.forensics["volatility_symbols_dir"] == str(tmp_path / "data/rules/volatility-symbols")
    assert cfg.forensics["sigma_rules_dir"] == ""  # not fetched, not configured


def test_volatility_reads_local_symbols_and_never_goes_online(tmp_path, monkeypatch):
    from test_hardening import _fake_bin

    from mordecai.case import Case
    from mordecai.tools.forensics import Forensics

    (tmp_path / "evidence").mkdir()
    (tmp_path / "evidence/mem.raw").write_bytes(b"x")
    _fake_bin(tmp_path, monkeypatch, "vol", '#!/bin/sh\n[ "$1" = -h ] && echo "  --offline  Do not search online"\necho "$@"\n')
    f = Forensics({"volatility_symbols_dir": str(tmp_path / "symbols")}, [tmp_path / "evidence"],
                  Case(tmp_path / "cases", "VOL-1"))
    out = asyncio.run(f.volatility(str(tmp_path / "evidence/mem.raw"), "windows.pslist"))
    args = out.split("\n", 1)[1].split()
    assert "--offline" in args and args[args.index("-s") + 1] == str(tmp_path / "symbols")


# Slow, stalled and interrupted downloads: each ends that set with a reason, never a silent wait

class _Body(httpx.SyncByteStream):
    """A response body that sends `first`, then calls `then` (which stalls, trickles or raises)."""

    def __init__(self, first: bytes, then):
        self.first, self.then = first, then

    def __iter__(self):
        yield self.first
        yield from self.then()


def _serve(body_then, length=10_000_000):
    def handler(request):
        return httpx.Response(200, headers={"content-length": str(length)}, stream=_Body(b"x" * 1000, body_then))
    return httpx.MockTransport(handler)


def test_a_stalled_download_fails_that_set_and_setup_goes_on(tmp_path):
    def stall():
        raise httpx.ReadTimeout("no data for 60 s")
        yield b""  # unreachable: makes this a generator
    data, zips = tmp_path / "data", make_zip(tmp_path / "ok.zip", {"ok.txt": "ok"})
    sets = {"stuck": {"url": "https://rules.example/stuck.zip", "dest": "rules/stuck", "default": True},
            "local": {"url": str(zips), "dest": "rules/local", "default": True}}
    said: list[str] = []
    assert rulesets.setup(data, sets, lambda q: "", said.append, _serve(stall)) == 1
    assert any(s.startswith("  FAIL  stuck: ReadTimeout") for s in said)
    assert rulesets.installed(data, sets["local"]) and not rulesets.installed(data, sets["stuck"])
    assert not list(data.glob(".fetch-*"))  # nothing half-written is left behind


def test_a_trickle_is_cut_off_at_the_sets_timeout(tmp_path):
    import time

    def trickle():
        while True:  # a byte now and then: each read succeeds, so only the overall limit can end it
            time.sleep(0.05)
            yield b"x"
    spec = {"url": "https://rules.example/slow.zip", "dest": "rules/slow", "timeout": 0.5}
    t = time.monotonic()
    with pytest.raises(rulesets.TooSlow, match="not done after 0 s.*rules.local.yaml"):
        rulesets.fetch(tmp_path / "data", "slow", spec, _serve(trickle), out=io.StringIO())
    assert time.monotonic() - t < 5
    assert not rulesets.installed(tmp_path / "data", spec)


def test_ctrl_c_during_a_download_skips_that_set_only(tmp_path):
    def interrupted():
        raise KeyboardInterrupt
        yield b""  # unreachable: makes this a generator
    data, zips = tmp_path / "data", make_zip(tmp_path / "ok.zip", {"ok.txt": "ok"})
    sets = {"big": {"url": "https://rules.example/big.zip", "dest": "rules/big", "default": True},
            "local": {"url": str(zips), "dest": "rules/local", "default": True}}
    said: list[str] = []
    assert rulesets.setup(data, sets, lambda q: "", said.append, _serve(interrupted)) == 1
    assert any("skip  big: stopped (Ctrl-C)" in s for s in said)
    assert rulesets.installed(data, sets["local"]) and not list(data.glob(".fetch-*"))


def test_ctrl_c_at_a_question_ends_the_questions(tmp_path):
    def ask(q):
        raise KeyboardInterrupt
    said: list[str] = []
    sets = {"a": {"url": "unused", "dest": "rules/a", "default": True}}
    assert rulesets.setup(tmp_path / "data", sets, ask, said.append) == 0
    assert any("no more sets asked about" in s for s in said)


def test_capa_rules_are_passed_over_without_capa(tmp_path, monkeypatch):
    from importlib import metadata

    def no_capa(name):
        raise metadata.PackageNotFoundError(name)
    monkeypatch.setattr(metadata, "version", no_capa)
    spec = rulesets.sources(ROOT / "config")["capa"]
    assert "install it first" in rulesets.unavailable(spec)
    said: list[str] = []
    assert rulesets.setup(tmp_path / "data", {"capa": spec}, lambda q: pytest.fail("asked about capa"), said.append) == 0
    assert said and said[0].startswith("  skip  capa: needs the installed capa")


def test_progress_is_shown_and_ends_its_line(tmp_path):
    out = io.StringIO()
    data = make_zip(tmp_path / "x.zip", {"a.txt": "a"})
    rulesets.fetch(tmp_path / "data", "x", {"url": str(data), "dest": "rules/x"}, out=out)
    text = out.getvalue()
    assert "x: 0 of 0 MiB" in text and "x: extracting" in text  # not a terminal: plain lines, one per step
