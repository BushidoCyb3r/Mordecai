"""Local programs the forensic tools use (config/local-tools.yaml): which ones the harness can use on this host, and how
to get each missing one. Mordecai installs none of them by itself: OS packages are yours to install, the Python ones
come with scripts/install.sh --forensics, and the third-party downloads are optional - fetched only when someone asks
for one (`mordecai local-tools fetch NAME`), pinned to a version and SHA-256, never by the installer.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any, Callable

from . import rulesets
from .config import load_yaml
from .tools.forensics import DEFAULT_BINARIES

KIND = "local-tools"
NOTICE = ("These are third-party programs. Fetch only the ones your organization allows on this host; every answer "
          "defaults to no.")


def catalog(config_dir: Path) -> dict[str, Any]:
    """config/local-tools.yaml with config/local-tools.local.yaml merged over it by name. Every download set must be
    pinned: one without a sha256 is refused, whatever the site file says."""
    cat: dict[str, Any] = {"packages": {}, "python": []}
    for f in (config_dir / f"{KIND}.yaml", config_dir / f"{KIND}.local.yaml"):
        if f.exists():
            d = load_yaml(f) or {}
            cat["packages"] = {**cat["packages"], **(d.get("packages") or {})}
            cat["python"] = list(d.get("python") or cat["python"])
    cat["sets"] = {n: {**s, "require_sha256": True} for n, s in rulesets.sources(config_dir, KIND).items()}
    return cat


def package_manager() -> str:
    return "dnf" if shutil.which("dnf") else "apt" if shutil.which("apt-get") else ""


def status(cfg: Any) -> list[tuple[str, str, str]]:
    """(name, where the harness finds it or "", how to get it) for every program the forensic tools use. Found the way
    the tools look: forensics.binaries (fetched sets included) on PATH, or the folder/path setting they read."""
    cat, f, pm = catalog(cfg.root), cfg.forensics, package_manager()
    bins = {**DEFAULT_BINARIES, **(f.get("binaries") or {})}
    rows = []
    for name in dict.fromkeys([*DEFAULT_BINARIES, *cat["packages"], *cat["sets"]]):
        pkg, st = cat["packages"].get(name) or {}, cat["sets"].get(name) or {}
        if setting := pkg.get("setting") or st.get("setting"):
            given = str(f.get(setting) or "")
            found = given if given and Path(given).exists() else ""
        else:
            found = shutil.which(str(bins.get(name, name))) or ""
        if found:
            how = ""
        elif name in cat["python"]:
            how = "scripts/install.sh --forensics (into .venv)"
        elif st:
            how = f"optional download, if your organization allows it: mordecai {KIND} fetch {name}"
        else:
            how = "; ".join([*([f"{pm} install {pkg[pm]}"] if pm and pkg.get(pm) else []), *([pkg["note"]] if pkg.get("note") else [])])
            how = how or f"install it on PATH, or set forensics.binaries.{name} in config/harness.yaml"
        rows.append((name, found, how))
    return rows


def report(cfg: Any, say: Callable[[str], None] = print) -> int:
    """Print status() and one install command for the missing packages. Returns how many programs are missing."""
    cat, pm = catalog(cfg.root), package_manager()
    lk = rulesets.lock(rulesets.data_dir(cfg))
    rows = status(cfg)
    for name, found, how in rows:
        fetched = f" (fetched {lk[name].get('version') or lk[name].get('fetched', '')})" if found and name in lk else ""
        say(f"  {'ok' if found else 'MISSING':8s} {name:15s} {found + fetched if found else how}")
    pkgs = [cat["packages"][n][pm] for n, found, _ in rows if not found and pm and (cat["packages"].get(n) or {}).get(pm)]
    if pkgs:
        say(f"  The missing packages, if you want them:  sudo {pm} install {' '.join(dict.fromkeys(pkgs))}")
    say(f"  Optional downloads ({', '.join(cat['sets'])}) are never fetched for you: fetch only the ones your "
        f"organization allows on this host (mordecai {KIND} fetch NAME, or setup to be asked about each; default no).")
    return sum(1 for _, found, _ in rows if not found)
