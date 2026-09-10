#!/bin/bash
# =============================================================================
# Parallel multi-host hunt — run the hunt loop across many hosts concurrently.
#
# Reads a hosts/URLs file (one per line) and runs a per-host hunt command with a
# bounded concurrency (default 4). Every host is scope-checked first; anything
# out of scope is skipped and logged, never touched.
#
# Default per-host command is the vuln scanner against that host's recon dir; you
# can override it (e.g. to run recon+scan, or a single scanner) with --cmd, where
# {host} and {outdir} are substituted.
#
# Usage:
#   ./tools/parallel_hunt.sh hosts.txt
#   ./tools/parallel_hunt.sh hosts.txt --jobs 8
#   ./tools/parallel_hunt.sh hosts.txt --scope scope.txt
#   ./tools/parallel_hunt.sh hosts.txt --cmd 'tools/cors_scanner.py {host} --json'
# =============================================================================
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$SCRIPT_DIR")"
PY=""; for _c in python3 python py; do if command -v "$_c" >/dev/null 2>&1 && "$_c" -c "" >/dev/null 2>&1; then PY="$_c"; break; fi; done

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${CYAN}[*]${NC} $1"; }
ok()   { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[-]${NC} $1" >&2; }

HOSTS_FILE=""; JOBS=4; SCOPE_FILE=""; OUT_BASE="$ROOT/findings"
CMD_TMPL='tools/vuln_scanner.sh {outdir}/recon'
while [ "$#" -gt 0 ]; do
  case "$1" in
    --jobs)  shift; JOBS="${1:-4}" ;;
    --scope) shift; SCOPE_FILE="${1:-}" ;;
    --out)   shift; OUT_BASE="${1:-}" ;;
    --cmd)   shift; CMD_TMPL="${1:-}" ;;
    -h|--help) sed -n '2,22p' "$0"; exit 0 ;;
    *)       [ -z "$HOSTS_FILE" ] && HOSTS_FILE="$1" ;;
  esac
  shift
done

[ -z "$HOSTS_FILE" ] && { err "No hosts file. Usage: $0 <hosts.txt> [--jobs N] [--scope scope.txt] [--cmd '...']"; exit 1; }
[ -f "$HOSTS_FILE" ] || { err "Not found: $HOSTS_FILE"; exit 1; }

# Scope gate: filter hosts through scope_checker.py when a scope file is given.
scope_ok() {
  local host="$1"
  [ -z "$SCOPE_FILE" ] && return 0
  # scope_checker.py takes -d/--domain patterns; feed it each line of the scope file.
  local dargs=()
  while IFS= read -r pat; do
    case "$pat" in ""|\#*) continue ;; esac
    dargs+=( -d "$pat" )
  done < "$SCOPE_FILE"
  "$PY" "$SCRIPT_DIR/scope_checker.py" "${dargs[@]}" "$host" >/dev/null 2>&1
}

log "Parallel hunt: $(grep -cvE '^\s*(#|$)' "$HOSTS_FILE") host(s), concurrency=$JOBS"
[ -n "$SCOPE_FILE" ] && log "Scope gate: $SCOPE_FILE"

run_one() {
  local host="$1"
  [ -z "$host" ] && return 0
  case "$host" in \#*) return 0 ;; esac
  local slug; slug="$(echo "$host" | sed -E 's#https?://##; s#[/:].*$##; s#[^A-Za-z0-9._-]#_#g')"
  local outdir="$OUT_BASE/$slug"
  mkdir -p "$outdir"
  local cmd="${CMD_TMPL//\{host\}/$host}"
  cmd="${cmd//\{outdir\}/$outdir}"
  log "[$slug] $cmd"
  ( cd "$ROOT" && FINDINGS_OUT_DIR="$outdir" eval "$cmd" ) > "$outdir/parallel_hunt.log" 2>&1
  ok "[$slug] done -> $outdir/parallel_hunt.log"
}

# Filter to in-scope hosts in THIS shell (reliable: no exported functions), then
# run the per-host command with a bounded background-job pool.
IN_SCOPE=()
while IFS= read -r host; do
  case "$host" in ""|\#*) continue ;; esac
  if scope_ok "$host"; then
    IN_SCOPE+=( "$host" )
  else
    warn "OUT OF SCOPE, skipping: $host"
  fi
done < "$HOSTS_FILE"

log "${#IN_SCOPE[@]} host(s) in scope; launching (concurrency=$JOBS)"
running=0
for host in ${IN_SCOPE[@]+"${IN_SCOPE[@]}"}; do
  run_one "$host" &
  running=$((running+1))
  if [ "$running" -ge "$JOBS" ]; then
    wait -n 2>/dev/null || wait
    running=$((running-1))
  fi
done
wait

ok "Parallel hunt complete. Results under $OUT_BASE/<host>/"
