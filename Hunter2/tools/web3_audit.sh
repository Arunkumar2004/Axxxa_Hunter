#!/bin/bash
# =============================================================================
# Web3 automated analyzer runner — wires the industry smart-contract tools into
# the /web3-audit flow so the audit is backed by real static + fuzzing + symbolic
# analysis, not reasoning alone.
#
# Pipeline (each step skipped gracefully if the tool is absent):
#   slither   static analysis (detectors: reentrancy, access control, etc.)
#   aderyn    Rust static analyzer (fast, complementary detector set)
#   mythril   symbolic execution over the bytecode/EVM
#   echidna   property-based fuzzing (needs an *.echidna.yaml / test contract)
#   medusa    parallel coverage-guided fuzzer (Foundry-style invariants)
#   halmos    symbolic testing over Foundry `test_`/`check_` functions
#
# Findings are normalized into findings/web3/<project>/ with a summary.
#
# Usage:
#   ./tools/web3_audit.sh Contract.sol
#   ./tools/web3_audit.sh ./contracts-repo            # a Foundry/Hardhat project
#   ./tools/web3_audit.sh ./repo --output-dir findings/web3/acme
#   ./tools/web3_audit.sh ./repo --skip echidna,medusa
# =============================================================================
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$SCRIPT_DIR")"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; MAG='\033[0;35m'; BOLD='\033[1m'; NC='\033[0m'
log()  { echo -e "${CYAN}[*]${NC} $1"; }
ok()   { echo -e "${GREEN}[+]${NC} $1"; }
hit()  { echo -e "${MAG}${BOLD}[FINDING]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[-]${NC} $1" >&2; }
skip() { echo -e "${YELLOW}[~]${NC} $1 (not installed)"; }
tool_ok() { command -v "$1" &>/dev/null; }

TARGET=""; OUT_DIR=""; SKIP=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --output-dir) shift; OUT_DIR="${1:-}" ;;
    --skip)       shift; SKIP="${1:-}" ;;
    -h|--help)    sed -n '2,26p' "$0"; exit 0 ;;
    *)            [ -z "$TARGET" ] && TARGET="$1" ;;
  esac
  shift
done
[ -z "$TARGET" ] && { err "No target. Usage: $0 <Contract.sol|project-dir> [--output-dir DIR] [--skip a,b]"; exit 1; }
[ -e "$TARGET" ] || { err "Not found: $TARGET"; exit 1; }
skip_has() { case ",$SKIP," in *",$1,"*) return 0 ;; *) return 1 ;; esac; }

NAME="$(basename "$TARGET" | sed 's/\.[^.]*$//')"
OUT_DIR="${OUT_DIR:-$ROOT/findings/web3/$NAME}"
mkdir -p "$OUT_DIR"
SUMMARY="$OUT_DIR/summary.md"
: > "$SUMMARY"
echo "# Web3 automated audit: $TARGET" >> "$SUMMARY"
echo "_$(date)_" >> "$SUMMARY"; echo >> "$SUMMARY"
log "Target: $TARGET"; log "Output: $OUT_DIR"
ANY=0

record() { echo "## $1" >> "$SUMMARY"; echo '```' >> "$SUMMARY"; tail -40 "$2" 2>/dev/null >> "$SUMMARY"; echo '```' >> "$SUMMARY"; echo >> "$SUMMARY"; }

# --- slither ---------------------------------------------------------------
if ! skip_has slither; then
  if tool_ok slither; then
    log "slither: static analysis..."
    slither "$TARGET" --json "$OUT_DIR/slither.json" > "$OUT_DIR/slither.txt" 2>&1 || true
    N=$(grep -ciE 'high|medium|reentrancy|arbitrary|unprotected' "$OUT_DIR/slither.txt" 2>/dev/null || echo 0)
    [ "$N" -gt 0 ] && { hit "slither: $N notable detector hits -> $OUT_DIR/slither.txt"; ANY=1; record "slither" "$OUT_DIR/slither.txt"; } || ok "slither: report at $OUT_DIR/slither.txt"
  else skip "slither (pipx install slither-analyzer)"; fi
fi

# --- aderyn -----------------------------------------------------------------
if ! skip_has aderyn; then
  if tool_ok aderyn; then
    log "aderyn: static analysis..."
    aderyn "$TARGET" -o "$OUT_DIR/aderyn.md" > "$OUT_DIR/aderyn.log" 2>&1 || true
    [ -s "$OUT_DIR/aderyn.md" ] && { hit "aderyn report -> $OUT_DIR/aderyn.md"; ANY=1; record "aderyn" "$OUT_DIR/aderyn.md"; } || ok "aderyn: see $OUT_DIR/aderyn.log"
  else skip "aderyn (cargo install aderyn)"; fi
fi

# --- mythril ----------------------------------------------------------------
if ! skip_has mythril; then
  if tool_ok myth; then
    if [ -f "$TARGET" ]; then
      log "mythril: symbolic execution..."
      timeout 600 myth analyze "$TARGET" -o markdown > "$OUT_DIR/mythril.md" 2>&1 || true
      grep -qiE 'SWC|vulnerability|integer|reentran' "$OUT_DIR/mythril.md" 2>/dev/null && { hit "mythril findings -> $OUT_DIR/mythril.md"; ANY=1; record "mythril" "$OUT_DIR/mythril.md"; } || ok "mythril: see $OUT_DIR/mythril.md"
    else warn "mythril needs a single .sol/.bytecode file, not a directory — skipping"; fi
  else skip "mythril (pipx install mythril)"; fi
fi

# --- echidna (property fuzzing) --------------------------------------------
if ! skip_has echidna; then
  if tool_ok echidna || tool_ok echidna-test; then
    E="$(command -v echidna || command -v echidna-test)"
    log "echidna: property fuzzing (needs echidna_* property functions in the contract)..."
    ( cd "$(dirname "$TARGET")" && timeout 600 "$E" "$(basename "$TARGET")" ) > "$OUT_DIR/echidna.txt" 2>&1 || true
    grep -qiE 'failed|falsified|counterexample' "$OUT_DIR/echidna.txt" 2>/dev/null && { hit "echidna falsified a property -> $OUT_DIR/echidna.txt"; ANY=1; record "echidna" "$OUT_DIR/echidna.txt"; } || ok "echidna: see $OUT_DIR/echidna.txt"
  else skip "echidna (brew install echidna / see crytic/echidna)"; fi
fi

# --- medusa (parallel fuzzing) ---------------------------------------------
if ! skip_has medusa; then
  if tool_ok medusa; then
    log "medusa: coverage-guided fuzzing (needs medusa.json config in project)..."
    ( cd "$([ -d "$TARGET" ] && echo "$TARGET" || dirname "$TARGET")" && timeout 600 medusa fuzz ) > "$OUT_DIR/medusa.txt" 2>&1 || true
    grep -qiE 'failed|assertion|violated' "$OUT_DIR/medusa.txt" 2>/dev/null && { hit "medusa found a violation -> $OUT_DIR/medusa.txt"; ANY=1; record "medusa" "$OUT_DIR/medusa.txt"; } || ok "medusa: see $OUT_DIR/medusa.txt"
  else skip "medusa (go install github.com/crytic/medusa)"; fi
fi

# --- halmos (symbolic Foundry tests) ---------------------------------------
if ! skip_has halmos; then
  if tool_ok halmos; then
    log "halmos: symbolic testing of Foundry check_/test_ functions..."
    ( cd "$([ -d "$TARGET" ] && echo "$TARGET" || dirname "$TARGET")" && timeout 600 halmos ) > "$OUT_DIR/halmos.txt" 2>&1 || true
    grep -qiE 'counterexample|FAIL|violated' "$OUT_DIR/halmos.txt" 2>/dev/null && { hit "halmos counterexample -> $OUT_DIR/halmos.txt"; ANY=1; record "halmos" "$OUT_DIR/halmos.txt"; } || ok "halmos: see $OUT_DIR/halmos.txt"
  else skip "halmos (pipx install halmos)"; fi
fi

echo "---"
if [ "$ANY" -eq 1 ]; then
  hit "Automated analyzers flagged issues — see $SUMMARY, then hand to web3-auditor for triage + Foundry PoC."
else
  ok "No automated findings surfaced. Continue with the /web3-audit reasoning checklist (business logic, oracle, accounting — tools miss these)."
fi
echo "Summary: $SUMMARY"
