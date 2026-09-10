#!/bin/bash
# =============================================================================
# Mobile App Static Scan — wires apkleaks + MobSF + objection for APK/IPA triage
#
# Static-first (fast, no device): apkleaks (secrets + hidden endpoints/base URLs)
# -> MobSF CLI (full static report) -> objection patchapk (SSL-pinning bypass so
# you can proxy runtime traffic, which is where most paid mobile bugs live).
#
# Complements skills/mobile-pentest (runtime-first methodology): this script is
# the automated static sweep + pinning-bypass prep step.
#
# Usage:
#   ./tools/mobile_scan.sh <app.apk|app.ipa>
#   ./tools/mobile_scan.sh <app.apk> --output-dir ./findings/target/mobile
#   ./tools/mobile_scan.sh <app.apk> --patch     # also run objection patchapk
# =============================================================================
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; MAG='\033[0;35m'; BOLD='\033[1m'; NC='\033[0m'
log()  { echo -e "${CYAN}[*]${NC} $1"; }
ok()   { echo -e "${GREEN}[+]${NC} $1"; }
hit()  { echo -e "${MAG}${BOLD}[HIT]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[-]${NC} $1" >&2; }
skip() { echo -e "${YELLOW}[~]${NC} $1 (tool not installed)"; }
tool_ok() { command -v "$1" &>/dev/null; }

APP=""; OUT_DIR=""; DO_PATCH=false
while [ "$#" -gt 0 ]; do
  case "$1" in
    --output-dir) shift; OUT_DIR="${1:-}" ;;
    --patch)      DO_PATCH=true ;;
    -h|--help)    sed -n '2,18p' "$0"; exit 0 ;;
    *)            [ -z "$APP" ] && APP="$1" ;;
  esac
  shift
done

[ -z "$APP" ] && { err "No app file given. Usage: $0 <app.apk|app.ipa> [--output-dir DIR] [--patch]"; exit 1; }
[ -f "$APP" ] || { err "File not found: $APP"; exit 1; }

BASE="$(basename "$APP")"
OUT_DIR="${OUT_DIR:-$SCRIPT_DIR/../findings/mobile/${BASE%.*}}"
mkdir -p "$OUT_DIR"
log "Mobile static scan: $APP"
log "Output: $OUT_DIR"

# --- 1. apkleaks: secrets + hidden endpoints / base URLs ---------------------
if tool_ok apkleaks; then
  log "apkleaks: extracting secrets + endpoints..."
  if apkleaks -f "$APP" -o "$OUT_DIR/apkleaks.txt" >/dev/null 2>&1; then
    N=$(grep -cE 'https?://|api|secret|key|token' "$OUT_DIR/apkleaks.txt" 2>/dev/null || echo 0)
    [ "$N" -gt 0 ] && hit "apkleaks: $N secret/endpoint lines -> $OUT_DIR/apkleaks.txt" || ok "apkleaks: report at $OUT_DIR/apkleaks.txt"
    grep -oE 'https?://[a-zA-Z0-9./_-]+' "$OUT_DIR/apkleaks.txt" 2>/dev/null | sort -u > "$OUT_DIR/endpoints.txt" || true
    [ -s "$OUT_DIR/endpoints.txt" ] && hit "Hidden endpoints -> $OUT_DIR/endpoints.txt (feed these to /hunt as fresh attack surface)"
  else
    warn "apkleaks failed (only .apk supported; IPA needs manual unzip)"
  fi
else
  skip "apkleaks (pipx install apkleaks)"
fi

# --- 2. MobSF: full static analysis report -----------------------------------
# MobSF is a server; the pipx 'mobsf' entrypoint + mobsfscan give static SAST.
if tool_ok mobsfscan; then
  log "mobsfscan: static SAST over the app..."
  mobsfscan --json -o "$OUT_DIR/mobsfscan.json" "$APP" >/dev/null 2>&1 || true
  [ -s "$OUT_DIR/mobsfscan.json" ] && hit "mobsfscan findings -> $OUT_DIR/mobsfscan.json"
elif tool_ok mobsf; then
  warn "MobSF installed as a server. Start it (mobsf) then upload $APP via the API/UI for the full report."
  echo "See: https://mobsf.github.io/docs/ for REST API upload" > "$OUT_DIR/mobsf_manual.txt"
else
  skip "mobsf/mobsfscan (pipx install mobsf mobsfscan)"
fi

# --- 3. objection: SSL-pinning bypass patch (enables runtime proxying) --------
if [[ "$APP" == *.apk ]] && [ "$DO_PATCH" = true ]; then
  if tool_ok objection; then
    log "objection: patching APK to bypass SSL pinning..."
    if objection patchapk -s "$APP" >/dev/null 2>&1; then
      hit "Patched APK created (objection.patched.apk) — install it, then proxy through Burp/mitmproxy to capture pinned traffic"
    else
      warn "objection patchapk failed (needs apktool + a Frida gadget; see objection docs)"
    fi
  else
    skip "objection (pipx install objection)"
  fi
elif [ "$DO_PATCH" = true ]; then
  warn "--patch only supports .apk (iOS pinning bypass needs a jailbroken device + Frida)"
else
  tool_ok objection && log "objection available — rerun with --patch to bypass SSL pinning for runtime testing" || skip "objection (pipx install objection)"
fi

ok "Mobile static scan complete. Next: proxy runtime traffic (skills/mobile-pentest) and /hunt the recovered endpoints."
