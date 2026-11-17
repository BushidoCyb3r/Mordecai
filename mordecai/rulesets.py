"""Rules and reference data the tools read, kept on this host so nothing is downloaded while the harness runs.

config/rules.yaml lists the sets (YARA, Sigma and capa rules, MITRE ATT&CK, Volatility symbols, nuclei templates):
where each comes from and where it goes under data/. Each is fetched once - by scripts/install.sh, which asks about
each, or `mordecai rules` - from its source, an internal mirror or a local path. An air-gapped host gets them from a
bundle made on a connected host (`mordecai rules bundle`, then `mordecai rules import` here). data/rules.lock.json
records what is installed: where it came from, the SHA-256 of what was downloaded, and when.
"""

from __future__ import annotations

import fnmatch
import io
import json
import os
import shutil
import stat
import tarfile
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Callable

import httpx

from .config import load_yaml
from .toolspecs import sha256_file

LOCK = "rules.lock.json"


def sources(config_dir: Path) -> dict[str, dict[str, Any]]:
    """The sets in config/rules.yaml, with config/rules.local.yaml merged over them by name (enabled: false drops one)."""
    sets: dict[str, dict[str, Any]] = {}
    for f in (config_dir / "rules.yaml", config_dir / "rules.local.yaml"):
        if f.exists():
            for name, spec in ((load_yaml(f) or {}).get("sets") or {}).items():
                sets[str(name)] = {**sets.get(str(name), {}), **(spec or {})}
    return {k: v for k, v in sets.items() if v.get("enabled", True) is not False}


def data_dir(cfg: Any) -> Path:
    return (Path(cfg.root) / ".." / "data").resolve()


def _dest(data: Path, dest: str) -> Path:
    """A set's place under data/: relative, never out of it."""
    p = PurePosixPath(str(dest))
    if not str(dest) or p.is_absolute() or ".." in p.parts:
        raise ValueError(f"dest {dest!r}: a relative path under data/")
    return data.joinpath(*p.parts)


def lock(data: Path) -> dict[str, Any]:
    try:
        d = json.loads((data / LOCK).read_text(encoding="utf-8"))
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_lock(data: Path, entries: dict[str, Any]) -> None:
    data.mkdir(parents=True, exist_ok=True)
    tmp = data / (LOCK + ".tmp")
    tmp.write_text(json.dumps(entries, indent=1, sort_keys=True), encoding="utf-8")
    os.replace(tmp, data / LOCK)


def installed(data: Path, spec: dict[str, Any]) -> bool:
    d = _dest(data, spec["dest"])
    return d.is_file() or (d.is_dir() and any(d.iterdir()))


def _url(spec: dict[str, Any]) -> str:
    url = str(spec["url"])
    if "{capa}" in url:
        from importlib.metadata import PackageNotFoundError, version
        try:
            url = url.replace("{capa}", version("flare-capa"))
        except PackageNotFoundError:
            raise ValueError("needs the installed capa's version: install it first (scripts/install.sh --forensics), "
                             "or set url in config/rules.local.yaml") from None
    return url


def _download(url: str, to: Path, transport: Any = None) -> None:
    """From the network (http/https), or a copy of a local path or file:// URL (a mounted share, a mirror on disk)."""
    if url.startswith(("http://", "https://")):
        with httpx.Client(follow_redirects=True, timeout=httpx.Timeout(60, read=300), transport=transport) as c:
            with c.stream("GET", url) as r:
                r.raise_for_status()
                with open(to, "wb") as fh:
                    for chunk in r.iter_bytes(1 << 20):
                        fh.write(chunk)
    else:
        shutil.copyfile(Path(os.path.expanduser(url.removeprefix("file://"))), to)


def _member(name: str, strip: str) -> PurePosixPath | None:
    """An archive member's path inside the set (its top folder dropped when it matches `strip`), or None for one that
    would land outside it."""
    p = PurePosixPath(name)
    if p.is_absolute() or ".." in p.parts or not p.parts:
        return None
    if strip and len(p.parts) > 1 and fnmatch.fnmatchcase(p.parts[0], strip):
        p = PurePosixPath(*p.parts[1:])
    return p


def _write(into: Path, rel: PurePosixPath, src: Any) -> None:
    target = into.joinpath(*rel.parts)
    target.parent.mkdir(parents=True, exist_ok=True)
    with open(target, "wb") as fh:
        shutil.copyfileobj(src, fh)


def _extract(archive: Path, fmt: str, into: Path, strip: str = "", under: str = "") -> int:
    """Regular files only (no links, devices or paths that climb out); `under`: only members below this folder."""
    n = 0
    if fmt == "zip":
        with zipfile.ZipFile(archive) as z:
            for info in z.infolist():
                if info.is_dir() or stat.S_ISLNK(info.external_attr >> 16):
                    continue
                if (rel := _member(info.filename, strip)) is not None:
                    with z.open(info) as src:
                        _write(into, rel, src)
                    n += 1
        return n
    with tarfile.open(archive, "r:*") as tf:
        for m in tf:
            if not m.isfile():
                continue
            rel = _member(m.name, strip)
            if rel is None or (under and rel.parts[:len(PurePosixPath(under).parts)] != PurePosixPath(under).parts):
                continue
            if under:
                rel = PurePosixPath(*rel.parts[len(PurePosixPath(under).parts):])
            _write(into, rel, tf.extractfile(m))
            n += 1
    return n


def _check_attack(path: Path) -> None:
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("type") != "bundle" or not any(o.get("type") == "x-mitre-collection" for o in data.get("objects") or []):
        raise ValueError("not an ATT&CK STIX bundle (no x-mitre-collection object)")


def _remove(p: Path) -> None:
    if p.is_dir() and not p.is_symlink():
        shutil.rmtree(p)
    elif p.exists() or p.is_symlink():
        p.unlink()


def _place(dest: Path, built: Path) -> None:
    """Replace the set's folder or file with the one just built."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    old = dest.with_name(dest.name + ".old")
    _remove(old)  # left by a run that stopped half-way
    if dest.exists() or dest.is_symlink():
        os.replace(dest, old)
    os.replace(built, dest)
    _remove(old)


def fetch(data: Path, name: str, spec: dict[str, Any], transport: Any = None) -> dict[str, Any]:
    """Download (or copy) one set and install it under data/. Returns its lock entry."""
    url = _url(spec)
    dest = _dest(data, spec["dest"])
    fmt = spec.get("format") or ("zip" if url.endswith(".zip") else "tar.gz" if url.endswith((".tar.gz", ".tgz"))
                                  else "file")
    data.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=data, prefix=".fetch-") as tmp:
        got = Path(tmp) / "download"
        _download(url, got, transport)
        sha = sha256_file(got)
        if fmt == "file":
            if spec.get("check") == "attack":
                _check_attack(got)
            built = got
        else:
            built = Path(tmp) / "set"
            if not _extract(got, fmt, built, str(spec.get("strip") or "")):
                raise ValueError(f"{url}: no files in the archive")
        _place(dest, built)
    entry = {"dest": spec["dest"], "url": url, "sha256": sha, "fetched": datetime.now(timezone.utc).isoformat()[:19] + "Z"}
    _save_lock(data, {**lock(data), name: entry})
    return entry


def bundle(data: Path, sets: dict[str, dict[str, Any]], out: Path, names: list[str] | None = None) -> tuple[list[str], str]:
    """One file with the installed sets (all, or `names`) and their lock entries, for an air-gapped host.
    Returns (sets bundled, the bundle's SHA-256)."""
    have = [n for n, s in sets.items() if installed(data, s)]
    chosen = names or have
    if missing := [n for n in chosen if n not in have]:
        raise ValueError(f"not installed here, so not bundled: {', '.join(missing)}")
    if not chosen:
        raise ValueError("no sets are installed here: fetch them first (mordecai rules fetch)")
    lk = lock(data)
    entries = {n: {**lk.get(n, {}), "dest": sets[n]["dest"]} for n in chosen}
    with tarfile.open(out, "w:gz") as tf:
        for n in chosen:
            tf.add(_dest(data, sets[n]["dest"]), arcname=f"data/{sets[n]['dest']}")
        raw = json.dumps(entries, indent=1, sort_keys=True).encode()
        info = tarfile.TarInfo(LOCK)
        info.size = len(raw)
        tf.addfile(info, io.BytesIO(raw))
    return chosen, sha256_file(out)


def import_bundle(data: Path, path: Path, sha256: str = "") -> list[str]:
    """Install the sets in a bundle made by bundle() on another host. Nothing is downloaded."""
    got = sha256_file(Path(path))
    if sha256 and got != sha256.lower():
        raise ValueError(f"{path}: SHA-256 is {got}, not {sha256}: the file changed on the way")
    with tarfile.open(path, "r:*") as tf:
        member = tf.extractfile(LOCK) if LOCK in tf.getnames() else None
        entries = json.loads(member.read()) if member else None
    if not isinstance(entries, dict) or not entries:
        raise ValueError(f"{path}: not a rules bundle (no {LOCK} inside)")
    data.mkdir(parents=True, exist_ok=True)
    for name, entry in entries.items():
        dest = _dest(data, entry["dest"])
        with tempfile.TemporaryDirectory(dir=data, prefix=".import-") as tmp:
            built = Path(tmp) / "set"
            if not _extract(Path(path), "tar.gz", built, under=f"data/{entry['dest']}"):
                raise ValueError(f"{path}: {name} has no files in the bundle")
            _place(dest, built)  # a one-file set (attack/enterprise-attack.json) was extracted as that file
        entry["imported"] = datetime.now(timezone.utc).isoformat()[:19] + "Z"
    _save_lock(data, {**lock(data), **entries})
    return list(entries)


def setup(data: Path, sets: dict[str, dict[str, Any]], ask: Callable[[str], str] = input,
          say: Callable[[str], None] = print, transport: Any = None) -> int:
    """The installer's decision gates: for each set not installed yet, ask whether to fetch it now (Enter takes the
    set's default). A source that cannot be reached ends the questions with how to bring the sets in by hand.
    Returns how many sets failed."""
    failed = 0
    for name, spec in sets.items():
        if installed(data, spec):
            say(f"  ok    {name}: {_dest(data, spec['dest'])}")
            continue
        default = bool(spec.get("default"))
        q = (f"  Download {name}: {spec.get('what', '')} ({spec.get('size', 'size unknown')}; "
             f"{spec.get('license', 'license: see the source')})? [{'Y/n' if default else 'y/N'}] ")
        a = ask(q).strip().lower()
        if not (a.startswith("y") or (not a and default)):
            say(f"  skip  {name} (later: mordecai rules fetch {name})")
            continue
        try:
            fetch(data, name, spec, transport)
            say(f"  ok    {name}: {_dest(data, spec['dest'])}")
        except httpx.TransportError as e:  # no route to the source: the other sets will not come either
            say(f"  FAIL  {name}: cannot reach {spec.get('url')}: {type(e).__name__}: {e}")
            say("  No internet here? Make a bundle on a connected host (mordecai rules fetch, then mordecai rules "
                "bundle FILE) and run scripts/install.sh --rules-from FILE here, or point url at a local mirror in "
                "config/rules.local.yaml.")
            return failed + 1
        except (ValueError, OSError, httpx.HTTPStatusError) as e:  # this set only: a bad url, a missing file, a 404
            failed += 1
            say(f"  FAIL  {name}: {type(e).__name__}: {e}")
    return failed
