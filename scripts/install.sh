#!/usr/bin/env bash
# Mordecai installer: from `git clone` to "ready to configure the model and connectors".
#
#   git clone <repo> mordecai && cd mordecai
#   ./scripts/install.sh            # then follow the printed next steps / SETUP.md
#
# What it does (safe to re-run; it never overwrites your settings and never prints secrets):
#   1. finds Python >= 3.11 and creates .venv
#   2. installs the harness (pip; or offline from a wheelhouse with --wheelhouse DIR)
#   3. creates config/.env (mode 600) from config/env.example, config/secrets/ (700), the site scope file
#      config/policy.local.yaml (600), and the evidence, vault, cases and memory folders
#   4. checks the evidence vault mount (noexec), the system tools it uses (openssl, bwrap) and which local
#      forensic tools are installed (it installs none)
#   5. asks about each set of rules and reference data (config/rules.yaml: ATT&CK, YARA, Sigma, capa rules, Volatility
#      symbols, nuclei templates) and fetches the ones you choose into data/ once - or imports a bundle on an
#      air-gapped host (--rules-from) - so nothing is downloaded while the harness runs
#   6. runs `mordecai doctor` (and the test suite with --test)
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/install.sh [options]

  --python PATH       Python interpreter to use (default: newest python3.x >= 3.11 found)
  --forensics         also install the Python forensic tools (YARA, Volatility 3, capa, FLOSS, MemProcFS, sigma-cli)
  --core              install the harness only (no Claude / Velociraptor client libraries)
  --wheelhouse DIR    offline install: pip --no-index --find-links DIR (air-gapped networks)
  --test              install pytest and run the test suite
  --harden-vault      bind-mount evidence/vault and forensics/ noexec,nosuid,nodev and add them to /etc/fstab
                      (uses sudo)
  --rules LIST        rules and reference data to fetch now, without asking: all | none | a comma list of the
                      sets in config/rules.yaml (attack,yara,sigma,capa,volatility-windows,...). Default: ask
                      about each set that is missing (no terminal: fetch nothing and say how)
  --rules-from FILE   air-gapped: import the sets from a bundle made on a connected host with
                      `mordecai rules bundle FILE` (nothing is downloaded)
  --rules-sha256 HEX  with --rules-from: refuse the bundle unless it has this SHA-256 (printed by `rules bundle`)
  --attack            same as adding attack to --rules
  --skip-install      do not run pip (configure folders and files only)
  -y, --yes           do not ask before using sudo
  -h, --help          this help
EOF
}

PY="" EXTRAS="connectors" WHEELHOUSE="" RUN_TESTS=0 HARDEN=0 SKIP_INSTALL=0 YES=0 FORENSICS=0 RULES="" RULES_FROM="" RULES_SHA="" ATTACK=0
while [ $# -gt 0 ]; do
  case "$1" in
    --python) PY="$2"; shift 2 ;;
    --forensics) FORENSICS=1; shift ;;
    --core) EXTRAS=""; shift ;;
    --wheelhouse) WHEELHOUSE="$2"; shift 2 ;;
    --test) RUN_TESTS=1; shift ;;
    --harden-vault) HARDEN=1; shift ;;
    --rules) RULES="$2"; shift 2 ;;
    --rules-from) RULES_FROM="$2"; shift 2 ;;
    --rules-sha256) RULES_SHA="$2"; shift 2 ;;
    --attack) ATTACK=1; shift ;;
    --skip-install) SKIP_INSTALL=1; shift ;;
    -y|--yes) YES=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage; exit 2 ;;
  esac
done

# --attack adds the ATT&CK set to --rules (all already has it; none becomes just it)
if [ "$ATTACK" = 1 ]; then case "$RULES" in all) ;; ""|none) RULES=attack ;; *) RULES="$RULES,attack" ;; esac; fi

if [ -t 1 ]; then B=$'\033[1m' G=$'\033[32m' Y=$'\033[33m' R=$'\033[31m' D=$'\033[2m' X=$'\033[0m'; else B="" G="" Y="" R="" D="" X=""; fi
step() { printf '\n%s== %s%s\n' "$B" "$*" "$X"; }
ok()   { printf '  %sok%s   %s\n' "$G" "$X" "$*"; }
warn() { printf '  %swarn%s %s\n' "$Y" "$X" "$*"; }
info() { printf '  %s%s%s\n' "$D" "$*" "$X"; }
die()  { printf '%serror:%s %s\n' "$R" "$X" "$*" >&2; exit 1; }
confirm() { [ "$YES" = 1 ] && return 0; read -r -p "  $1 [y/N] " a; [[ "$a" =~ ^[Yy] ]]; }

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"
[ -f pyproject.toml ] && [ -d mordecai ] || die "run this from a Mordecai checkout (pyproject.toml not found in $REPO)"
umask 077   # everything this script creates is private unless set otherwise below

# WSL: a Windows drive (/mnt/c, ...) ignores Linux permissions - every file is executable, evidence samples included,
# and the secrets are readable by every user - and its file locking is unreliable for SQLite. Refuse before building.
if grep -qi microsoft /proc/sys/kernel/osrelease 2>/dev/null; then
  fs=$(awk -v t="$REPO" '{mp=$5; gsub(/\\040/," ",mp); if ((t==mp || mp=="/" || index(t, mp"/")==1) && length(mp)>=bl) {bl=length(mp); for (i=7; i<NF && $i!="-"; i++); fs=$(i+1)}} END {print fs}' /proc/self/mountinfo)
  case "$fs" in 9p|drvfs|virtiofs)
    die "$REPO is on a Windows drive ($fs). WSL does not apply Linux file permissions there, so the vault and the
       secrets would be unprotected. Clone it into your Linux home instead (SETUP.md section 0b):
       cd ~ && git clone https://github.com/BushidoCyb3r/Mordecai.git mordecai" ;;
  esac
fi

# ---------------------------------------------------------------------------------------------------------------
step "1. Python"
py_ok() { "$1" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' 2>/dev/null; }
if [ -z "$PY" ]; then
  for c in python3.14 python3.13 python3.12 python3.11 python3; do
    if command -v "$c" >/dev/null 2>&1 && py_ok "$c"; then PY="$(command -v "$c")"; break; fi
  done
fi
[ -n "$PY" ] && py_ok "$PY" || die "Python 3.11 or newer is required (install it, or pass --python /path/to/python3.x)"
"$PY" -c 'import venv, ensurepip' 2>/dev/null || die "$PY lacks venv/ensurepip (Debian/Ubuntu: apt install python3-venv)"
ok "$("$PY" -V) at $PY"

# ---------------------------------------------------------------------------------------------------------------
step "2. Virtual environment and install"
if [ ! -x .venv/bin/python ]; then
  "$PY" -m venv .venv && ok "created .venv"
else
  ok ".venv already exists ($(.venv/bin/python -V))"
fi
PIP=(.venv/bin/python -m pip --disable-pip-version-check)
if [ -n "$WHEELHOUSE" ]; then
  [ -d "$WHEELHOUSE" ] || die "wheelhouse $WHEELHOUSE not found"
  # as environment, not options: they are `pip install` options, and they must also reach the isolated build of -e .
  export PIP_NO_INDEX=1 PIP_FIND_LINKS="$(cd "$WHEELHOUSE" && pwd)"
  info "offline install from $WHEELHOUSE"
fi
extras=()
[ -n "$EXTRAS" ] && extras+=("$EXTRAS")
[ "$FORENSICS" = 1 ] && extras+=("forensics")
[ "$RUN_TESTS" = 1 ] && extras+=("dev")
spec="."
[ ${#extras[@]} -gt 0 ] && spec=".[$(IFS=,; echo "${extras[*]}")]"
if [ "$SKIP_INSTALL" = 1 ]; then
  warn "skipping pip install (--skip-install)"
else
  info "pip install -e '$spec'   (this downloads packages from your configured index unless --wheelhouse)"
  "${PIP[@]}" install --quiet --upgrade pip setuptools wheel || warn "could not upgrade pip/setuptools (continuing)"
  "${PIP[@]}" install --quiet -e "$spec"
  ok "installed mordecai $spec"
fi
if [ -x .venv/bin/mordecai ]; then ok "mordecai command: .venv/bin/mordecai"; else warn "mordecai command not installed yet"; fi

# ---------------------------------------------------------------------------------------------------------------
step "3. Configuration files and folders"
if [ ! -f config/.env ]; then
  cp config/env.example config/.env
  sed -i "s/^MORDECAI_OPERATOR=.*/MORDECAI_OPERATOR=${USER:-analyst}/" config/.env
  sed -i "s/^MORDECAI_POLICY=.*/MORDECAI_POLICY=policy.local.yaml               # your site's scope (config\/policy.local.yaml, git-ignored)/" config/.env
  ok "created config/.env from config/env.example (operator: ${USER:-analyst})"
else
  ok "config/.env exists - left unchanged"
fi
chmod 600 config/.env

mkdir -p config/secrets && chmod 700 config/secrets && ok "config/secrets/ (700) for API configs, CA bundles, client certs"

if .venv/bin/mordecai account status >/dev/null 2>&1; then
  ok "dashboard account exists - left unchanged (change the password: mordecai account passwd)"
elif [ -t 0 ]; then
  step "Dashboard sign-in account"
  echo "  You sign in to the dashboard with this username and password plus the access token each start prints."
  .venv/bin/mordecai account create || warn "no account yet - scripts/start.sh will ask for it"
else
  warn "no dashboard account yet (no terminal to ask in) - scripts/start.sh will ask for it"
fi

if [ ! -f config/models.local.yaml ]; then
  cat > config/models.local.yaml <<'MODELS'
# Site model profiles (git-ignored). Merged over config/models.yaml, which documents every field:
# add your own profiles here, override fields of a shipped one, set default_model, or hide one with
# `enabled: false`. Secrets stay in config/.env as ${VARIABLES}.
#
# default_model: claude-sonnet
models: {}
#   my-ollama:
#     label: Ollama - Qwen3 32B
#     group: Local
#     provider: openai_compat
#     base_url: http://127.0.0.1:11434/v1
#     model: qwen3:32b
#     context_tokens: 32000
MODELS
  ok "created config/models.local.yaml for your site's model profiles (config/models.yaml has the templates)"
else
  ok "config/models.local.yaml exists - left unchanged"
fi

if [ ! -f config/policy.local.yaml ]; then
  { echo "# Site policy: copy of policy.yaml. Fill in scope.allowed_targets and scope.protected_assets (SETUP.md section 9)."
    echo "# Git-ignored. Selected with MORDECAI_POLICY=policy.local.yaml in config/.env."
    cat config/policy.yaml; } > config/policy.local.yaml
  ok "created config/policy.local.yaml - set your scope before enabling Velociraptor"
else
  ok "config/policy.local.yaml exists - left unchanged"
fi
chmod 600 config/policy.local.yaml

mkdir -p evidence forensics cases memory
chmod 750 evidence forensics
mkdir -p evidence/vault && chmod 700 evidence/vault
ok "forensics/ (per-case folders: drop artifacts in forensics/<case-id>/), evidence/vault/ (700), cases/, memory/"

if command -v git >/dev/null 2>&1 && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  for f in config/.env config/secrets/x.api.yaml config/policy.local.yaml evidence/x forensics/x cases/x memory/x; do
    git check-ignore -q "$f" || warn "$f is NOT git-ignored - check .gitignore before committing anything"
  done
  ok "secrets, scope, evidence, forensics, cases and memory are git-ignored"
fi

# ---------------------------------------------------------------------------------------------------------------
step "4. Evidence vault and forensics folder"
# Both hold evidence that may be hostile (collected files, malware samples, dropped artifacts): on a
# noexec,nosuid,nodev mount nothing in them can be run as a program, set-ID bits are ignored, and device files
# do not work, whatever a file's own permissions say.
mount_noexec() { awk -v t="$1" '{mp=$5; gsub(/\\040/," ",mp); if ((t==mp || index(t, mp"/")==1) && length(mp)>=bl) {bl=length(mp); o=$6}} END {exit (o ~ /(^|,)noexec(,|$)/) ? 0 : 1}' /proc/self/mountinfo; }
fstab_escape() { printf '%s' "$1" | sed -e 's/\\/\\134/g' -e 's/ /\\040/g' -e 's/\t/\\011/g'; }
for DIR in "$REPO/evidence/vault" "$REPO/forensics"; do
  if mount_noexec "$DIR"; then
    ok "$DIR is on a noexec mount"
  elif [ "$HARDEN" = 1 ]; then
    if confirm "Bind-mount $DIR noexec,nosuid,nodev and add it to /etc/fstab (sudo)?"; then
      sudo mount --bind "$DIR" "$DIR"
      sudo mount -o remount,bind,noexec,nosuid,nodev "$DIR"
      # fstab separates fields with whitespace: a path holding a space or tab is written escaped (\040, \011).
      # nofail: if this folder is moved, renamed or deleted later, the boot carries on instead of stopping in
      # emergency mode; the vault is then simply not noexec until you fix the line (doctor says so).
      FS=$(fstab_escape "$DIR")
      if ! grep -qsF "$FS $FS none bind" /etc/fstab; then
        echo "$FS $FS none bind,noexec,nosuid,nodev,nofail 0 0" | sudo tee -a /etc/fstab >/dev/null
      elif ! grep -sF "$FS $FS none bind" /etc/fstab | grep -q nofail; then
        warn "/etc/fstab already has a line for $DIR without nofail: add ,nofail to its options, or a moved or"
        info "     deleted folder stops the next boot in emergency mode"
      fi
      mount_noexec "$DIR" && ok "$DIR mounted noexec (persisted in /etc/fstab)" || warn "mount of $DIR did not take effect"
    fi
  else
    warn "$DIR is not on a noexec mount. For full protection re-run with --harden-vault, or (root):"
    info "     sudo mount --bind $DIR $DIR && sudo mount -o remount,bind,noexec,nosuid,nodev $DIR"
  fi
done

# ---------------------------------------------------------------------------------------------------------------
step "5. System tools"
if command -v openssl >/dev/null 2>&1; then
  ok "openssl: the dashboard's TLS certificate when it serves beyond localhost"
else
  warn "openssl not found: install it to serve the dashboard beyond this host (scripts/start.sh --localhost works without it)"
fi
if command -v bwrap >/dev/null 2>&1; then
  if bwrap --unshare-all --ro-bind / / true 2>/dev/null; then
    ok "bwrap (bubblewrap): the sandbox for onboarded tools"
  else
    warn "bwrap is installed but cannot create a sandbox here (user namespaces disabled?) - tool onboarding will not work"
    info "     check: sysctl user.max_user_namespaces (must be > 0); on Ubuntu 24.04+ also the AppArmor userns restriction;"
    info "     in WSL, the distribution must be WSL 2 (wsl -l -v in PowerShell)"
  fi
else
  warn "bwrap (bubblewrap) not found: needed only to onboard new tools (dnf install bubblewrap | apt install bubblewrap)"
fi
if [ -e /proc/sys/fs/binfmt_misc/WSLInterop ] || [ -e /proc/sys/fs/binfmt_misc/WSLInterop-late ]; then
  warn "WSL interop is on: programs here can start Windows programs, which the vault's Linux protections do not cover"
  info "     on a host that handles hostile files, turn it off: [interop] enabled=false in /etc/wsl.conf (SETUP.md 0b)"
fi

# ---------------------------------------------------------------------------------------------------------------
step "6. Local forensic tools (optional - none are installed by this script)"
have=() missing=()
for t in file strings yara vol log2timeline.py tshark zeek capa floss exiftool hayabusa chainsaw sigma fls bulk_extractor dotnet; do
  if command -v "$t" >/dev/null 2>&1 || [ -x ".venv/bin/$t" ]; then have+=("$t"); else missing+=("$t"); fi
done
[ ${#have[@]} -gt 0 ] && ok "found: ${have[*]}"
[ ${#missing[@]} -gt 0 ] && info "not found: ${missing[*]}"
info "Install only what your team needs, after clearing it with your security team (SETUP.md section 8)."
info "--forensics installs the Python ones (YARA, Volatility 3, capa, FLOSS, MemProcFS, sigma-cli) into .venv."

# ---------------------------------------------------------------------------------------------------------------
step "7. Rules and reference data (fetched once; nothing is downloaded while the harness runs)"
# Each set in config/rules.yaml is a decision: fetch it now, or not. They land in data/ and the tools read them there.
if [ ! -x .venv/bin/mordecai ]; then
  warn "skipping: mordecai is not installed"
elif [ -n "$RULES_FROM" ]; then
  [ -f "$RULES_FROM" ] || die "rules bundle $RULES_FROM not found"
  .venv/bin/mordecai rules import "$RULES_FROM" ${RULES_SHA:+--sha256 "$RULES_SHA"} && ok "imported the rules bundle (no download)" \
    || warn "import failed - retry: .venv/bin/mordecai rules import $RULES_FROM"
elif [ "$RULES" = "none" ]; then
  info "not fetching any (--rules none). Later: .venv/bin/mordecai rules setup"
elif [ "$RULES" = "all" ]; then
  .venv/bin/mordecai rules fetch --all || warn "some sets did not come (see above) - no internet here? use --rules-from"
elif [ -n "$RULES" ]; then
  .venv/bin/mordecai rules fetch ${RULES//,/ } || warn "some sets did not come (see above) - no internet here? use --rules-from"
elif [ -t 0 ]; then
  info "Enter takes the default shown. Air-gapped? Answer n, then use --rules-from with a bundle (config/rules.yaml)."
  .venv/bin/mordecai rules setup || warn "some sets did not come - re-run later: .venv/bin/mordecai rules setup"
else
  info "no terminal to ask in: nothing fetched. Use --rules all|none|LIST or --rules-from FILE, or later:"
  info "     .venv/bin/mordecai rules setup"
fi
[ -x .venv/bin/mordecai ] && .venv/bin/mordecai rules status 2>/dev/null || true

# ---------------------------------------------------------------------------------------------------------------
step "8. Checks"
if [ -x .venv/bin/mordecai ]; then
  if [ "$RUN_TESTS" = 1 ]; then
    .venv/bin/python -m pytest -q && ok "test suite passed" || warn "some tests failed (see above)"
  fi
  log="$(mktemp)"
  if ( set -a; . config/.env; set +a; .venv/bin/mordecai doctor --case SETUP-CHECK ) > "$log" 2>&1; then
    head -12 "$log" | sed 's/^/  /'
    ok "doctor ran (full output: .venv/bin/mordecai doctor --case SETUP-CHECK)"
  else
    tail -20 "$log" | sed 's/^/  /'
    warn "doctor failed - fix the error above (usually config/.env)"
  fi
  rm -f "$log"
else
  warn "skipping checks: mordecai is not installed"
fi

# ---------------------------------------------------------------------------------------------------------------
step "Ready for configuration"
cat <<EOF
  Next, follow SETUP.md:
    1. Model (required): pick or fill in a profile in config/models.yaml (e.g. the my-local-model template)
       and put its key in config/.env; the dashboard's model picker lists them all (SETUP.md section 1).
    2. Connectors you have: Security Onion, Elastic, Splunk, Velociraptor, MISP, OpenCTI, Archer (sections 2-7b).
       Velociraptor: run scripts/velociraptor_setup.sh on the Velociraptor server; put the key files
       in config/secrets/ (section 5).
    3. Scope: config/policy.local.yaml - allowed_targets and protected_assets (section 9).
    4. Check:     .venv/bin/mordecai doctor --case SETUP-CHECK   (it reads config/.env itself)
    5. Use it:    scripts/start.sh     (prints the sign-in link and this start's access token)
                  scripts/stop.sh      (stops it; your data stays)
                  or on the command line: .venv/bin/mordecai chat / run
EOF
