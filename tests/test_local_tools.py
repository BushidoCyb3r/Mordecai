"""Local programs (config/local-tools.yaml, mordecai local-tools): the status check says how to get each missing one;
the third-party downloads are optional, never fetched by the installer, pinned to a SHA-256, and their program must be
a Linux program for this machine. No test touches the network: sources are local files."""

from __future__ import annotations

import asyncio
import io
import json
import os
import re
import shutil
import sys
import tarfile
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_harness import ROOT, write_config  # noqa: E402
from test_rules import make_zip  # noqa: E402

from mordecai import cli, localtools, rulesets  # noqa: E402
from mordecai.toolspecs import sha256_file  # noqa: E402


def elf(machine: int) -> bytes:
    """The start of an ELF program header for a CPU (62 x86_64, 183 aarch64)."""
    return b"\x7fELF\x02\x01\x01" + b"\0" * 11 + machine.to_bytes(2, "little") + b"\0" * 40


def test_shipped_downloads_are_optional_pinned_and_cover_the_ez_wrapper():
    from mordecai.tools.forensics import Forensics

    sets = localtools.catalog(ROOT / "config")["sets"]
    assert set(sets) == {"hayabusa", "chainsaw", "ez-tools"}
    for name, s in sets.items():
        assert s["default"] is False and s["dest"].startswith("tools/") and s["what"] and s["license"], name
        for item in rulesets._items(s):
            urls = item["url"] if isinstance(item["url"], dict) else {"": item["url"]}
            shas = item["sha256"] if isinstance(item["sha256"], dict) else {"": item["sha256"]}
            assert set(urls) == set(shas) and all(u.startswith("https://") for u in urls.values()), name
            assert all(re.fullmatch(r"[0-9a-f]{64}", h) for h in shas.values()), name
    ez = {Path(f["url"]).stem for f in sets["ez-tools"]["files"]}
    assert ez == set(Forensics.EZ_TOOLS)  # one pinned download for every parser the wrapper runs


def test_the_installer_never_fetches_a_local_tool():
    lines = [line for line in (ROOT / "scripts" / "install.sh").read_text().splitlines()
             if not line.lstrip().startswith(("#", "info ", "warn ", "ok "))]
    assert re.findall(r"mordecai local-tools (\w+)", "\n".join(lines)) == ["status"]


def test_a_download_that_differs_from_its_pin_installs_nothing(tmp_path):
    data, src = tmp_path / "data", make_zip(tmp_path / "t.zip", {"t/README": "x"})
    spec = {"url": str(src), "dest": "tools/t", "sha256": "0" * 64, "require_sha256": True}
    with pytest.raises(ValueError, match="not the pinned"):
        rulesets.fetch(data, "t", spec)
    assert not (data / "tools/t").exists() and "t" not in rulesets.lock(data)
    del spec["sha256"]
    with pytest.raises(ValueError, match="no pinned sha256"):
        rulesets.fetch(data, "t", spec)
    spec["sha256"] = sha256_file(src)
    assert rulesets.fetch(data, "t", spec)["sha256"] == spec["sha256"] and (data / "tools/t/t/README").is_file()


def test_the_program_must_be_for_this_machine_and_is_the_only_executable(tmp_path, monkeypatch):
    monkeypatch.setattr(rulesets.platform, "machine", lambda: "x86_64")
    data = tmp_path / "data"
    src = make_zip(tmp_path / "hb.zip", {"hb-1.0-lin-x64-gnu": elf(62), "rules/a.yml": "x"})
    spec = {"url": {"x86_64": str(src), "aarch64": "/none"}, "sha256": {"x86_64": sha256_file(src), "aarch64": "0" * 64},
            "version": "1.0", "dest": "tools/hb", "bin": "hb-{version}-lin-*-gnu", "require_sha256": True}
    e = rulesets.fetch(data, "hb", spec)
    assert e["bin"] == "tools/hb/hb-1.0-lin-x64-gnu" and e["version"] == "1.0"
    assert os.access(data / e["bin"], os.X_OK) and not os.access(data / "tools/hb/rules/a.yml", os.X_OK)
    for body, why in ((elf(183), "another CPU"), (b"#!/bin/sh\necho hi\n", "not a Linux program")):
        make_zip(src, {"hb-1.0-lin-x64-gnu": body})
        spec["sha256"]["x86_64"] = sha256_file(src)
        with pytest.raises(ValueError, match=why):
            rulesets.fetch(data, "hb", spec)
        assert os.access(data / e["bin"], os.X_OK)  # the installed one stays as it was
    monkeypatch.setattr(rulesets.platform, "machine", lambda: "ppc64le")
    assert "no download for this machine (ppc64le)" in rulesets.unavailable(spec)


def test_a_set_of_several_archives_unpacks_each_into_its_own_folder(tmp_path):
    data = tmp_path / "data"
    a = make_zip(tmp_path / "MFTECmd.zip", {"MFTECmd.dll": "a"})
    b = make_zip(tmp_path / "RECmd.zip", {"RECmd/RECmd.dll": "b", "RECmd/BatchExamples/x.reb": "c"})
    spec = {"files": [{"url": str(a), "sha256": sha256_file(a)}, {"url": str(b), "sha256": sha256_file(b)}],
            "dest": "tools/ez", "require_sha256": True}
    e = rulesets.fetch(data, "ez-tools", spec)
    assert (data / "tools/ez/MFTECmd/MFTECmd.dll").is_file() and (data / "tools/ez/RECmd/RECmd/RECmd.dll").is_file()
    assert e["sha256"] == [sha256_file(a), sha256_file(b)]
    make_zip(b, {"RECmd/RECmd.dll": "changed upstream"})  # an updated tool: refused, the installed set kept
    with pytest.raises(ValueError, match="not the pinned"):
        rulesets.fetch(data, "ez-tools", spec)
    assert (data / "tools/ez/RECmd/RECmd/RECmd.dll").read_text() == "b"


def test_a_bundle_carries_the_program_and_checks_it_again(tmp_path, monkeypatch):
    monkeypatch.setattr(rulesets.platform, "machine", lambda: "x86_64")
    data, there = tmp_path / "data", tmp_path / "airgapped"
    src = make_zip(tmp_path / "cs.tar.zip", {"chainsaw/chainsaw": elf(62), "chainsaw/mappings/m.yml": "x"})
    spec = {"url": str(src), "sha256": sha256_file(src), "format": "zip", "strip": "chainsaw", "dest": "tools/chainsaw",
            "bin": "chainsaw", "require_sha256": True}
    rulesets.fetch(data, "chainsaw", spec)
    rulesets.bundle(data, {"chainsaw": spec}, tmp_path / "tools.tar.gz")
    assert rulesets.import_bundle(there, tmp_path / "tools.tar.gz") == ["chainsaw"]
    assert os.access(there / "tools/chainsaw/chainsaw", os.X_OK) and (there / "tools/chainsaw/mappings/m.yml").is_file()
    forged = tmp_path / "forged.tar.gz"  # a bundle whose program is outside its set is refused
    with tarfile.open(forged, "w:gz") as tf:
        tf.add(data / "tools/chainsaw", arcname="data/tools/chainsaw")
        raw = json.dumps({"chainsaw": {"dest": "tools/chainsaw", "bin": "tools/other/sh"}}).encode()
        info = tarfile.TarInfo(rulesets.LOCK)
        info.size = len(raw)
        tf.addfile(info, io.BytesIO(raw))
    with pytest.raises(ValueError, match="not in the set"):
        rulesets.import_bundle(tmp_path / "other", forged)
    assert not (tmp_path / "other/tools/chainsaw").exists()  # refused before anything was installed


def test_fetched_programs_are_used_where_none_is_configured(tmp_path):
    from mordecai.config import load_config

    (tmp_path / "config").mkdir()
    path = write_config(tmp_path / "config")
    data = tmp_path / "data"
    (data / "tools/hayabusa").mkdir(parents=True)
    (data / "tools/hayabusa/hb").write_bytes(elf(62))
    (data / "tools/chainsaw/mappings").mkdir(parents=True)
    (data / "tools/chainsaw/mappings/sigma-event-logs-all.yml").write_text("x")
    (data / "tools/ez").mkdir(parents=True)
    (data / rulesets.LOCK).write_text(json.dumps({"hayabusa": {"dest": "tools/hayabusa", "bin": "tools/hayabusa/hb"}}))
    f = load_config(path).forensics
    assert f["binaries"]["hayabusa"] == str(data / "tools/hayabusa/hb") and f["ez_tools_dir"] == str(data / "tools/ez")
    assert f["binaries"]["chainsaw_mapping"] == str(data / "tools/chainsaw/mappings/sigma-event-logs-all.yml")
    raw = yaml.safe_load(path.read_text())
    raw["forensics"] = {"binaries": {"hayabusa": "/opt/approved/hayabusa"}, "ez_tools_dir": "/opt/ez"}
    path.write_text(yaml.safe_dump(raw))
    f = load_config(path).forensics  # what harness.yaml names wins
    assert f["binaries"]["hayabusa"] == "/opt/approved/hayabusa" and f["ez_tools_dir"] == "/opt/ez"


@pytest.mark.parametrize("pm,which", [("dnf", "dnf"), ("apt", "apt-get")])
def test_status_says_how_to_get_each_missing_program(tmp_path, monkeypatch, pm, which):
    from mordecai.config import load_config

    (tmp_path / "config").mkdir()
    shutil.copy(ROOT / "config" / "local-tools.yaml", tmp_path / "config")
    cfg = load_config(write_config(tmp_path / "config"))
    monkeypatch.setattr(shutil, "which", lambda name, *a, **k: {which: f"/usr/bin/{which}", "file": "/usr/bin/file"}.get(name))
    rows = {n: (found, how) for n, found, how in localtools.status(cfg)}
    assert rows["file"] == ("/usr/bin/file", "")
    assert rows["yara"][1].startswith(f"{pm} install yara") and rows["capa"][1].startswith("scripts/install.sh --forensics")
    assert rows["hayabusa"][1] == "optional download, if your organization allows it: mordecai local-tools fetch hayabusa"
    assert rows["ez-tools"][0] == "" and "fetch ez-tools" in rows["ez-tools"][1] and "ALEAPP_PATH" in rows["aleapp"][1]
    out: list[str] = []
    assert localtools.report(cfg, out.append) == len(rows) - 1
    install = next(line for line in out if f"sudo {pm} install " in line).split(f"sudo {pm} install ")[1].split()
    assert "yara" in install and "binutils" in install and len(install) == len(set(install))
    assert "never fetched for you" in out[-1]


def test_venv_programs_are_found_without_activating_it(monkeypatch):
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    monkeypatch.setattr(cli.sys, "executable", "/opt/m/.venv/bin/python")
    cli._venv_on_path()
    cli._venv_on_path()
    assert os.environ["PATH"] == "/usr/bin:/bin:/opt/m/.venv/bin"  # after the system's own, once


@pytest.mark.parametrize("help_text,cmd,quiet", [("Commands:\n  dfir-timeline  Create a DFIR timeline", "dfir-timeline", False),
                                                  ("Commands:\n  csv-timeline   Save the timeline in CSV", "csv-timeline", True)])
def test_hayabusa_4_and_older_each_get_their_own_command(tmp_path, monkeypatch, help_text, cmd, quiet):
    from test_hardening import _fake_bin

    from mordecai.case import Case
    from mordecai.tools.forensics import Forensics

    (tmp_path / "evidence").mkdir()
    (tmp_path / "evidence/Security.evtx").write_bytes(b"ElfFile")
    log = tmp_path / "argv.txt"
    _fake_bin(tmp_path, monkeypatch, "hayabusa",
              f'#!/bin/sh\n[ "$1" = help ] && {{ printf "{help_text}\\n"; exit 0; }}\necho "$@" >> {log}\n')
    f = Forensics({}, [tmp_path / "evidence"], Case(tmp_path / "cases", "HB-1"))
    asyncio.run(f.evtx_hunt(str(tmp_path / "evidence/Security.evtx")))
    args = log.read_text().split()
    assert args[0] == cmd and ("-q" in args) == quiet and {"-f", "-o", "-m", "-w", "-U"} <= set(args)
