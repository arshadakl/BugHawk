#!/usr/bin/env bash
# bughawk.sh — main entry point and pipeline orchestrator
set -euo pipefail

BUGHAWK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOTAL_STEPS=7

# ── Source libraries ──────────────────────────────────────────────────────────
source "$BUGHAWK_DIR/lib/utils.sh"
source "$BUGHAWK_DIR/lib/cache.sh"
source "$BUGHAWK_DIR/lib/setup.sh"
source "$BUGHAWK_DIR/lib/recon.sh"
source "$BUGHAWK_DIR/lib/scan.sh"
source "$BUGHAWK_DIR/lib/secrets.sh"
source "$BUGHAWK_DIR/lib/aggregator.sh"
source "$BUGHAWK_DIR/lib/ai.sh"
source "$BUGHAWK_DIR/lib/report.sh"

# ── Load config ───────────────────────────────────────────────────────────────
if [ -f "$BUGHAWK_DIR/config.sh" ]; then
  source "$BUGHAWK_DIR/config.sh"
else
  source "$BUGHAWK_DIR/config.example.sh"
  log_warn "config.sh not found — using defaults. Copy config.example.sh to config.sh and set your API key."
fi

# ── Defaults ──────────────────────────────────────────────────────────────────
SCOPE="${SCOPE:-single}"
DEPTH="${DEPTH:-full}"
SKIP_TOOLS=()
OUTPUT_DIR="${OUTPUT_DIR:-./output}"
QUIET_MODE="${QUIET_MODE:-false}"

# ── Help ──────────────────────────────────────────────────────────────────────
show_help() {
  cat << 'HELP'
BugHawk — Autonomous Bug Bounty Scanner

Usage:
  ./bughawk.sh <target> [options]

Arguments:
  <target>                  URL, domain, or IP to scan (required)

Scan scope:
  --scope single            Scan only the given domain (default)
  --scope subdomains        Also scan all discovered subdomains
  --scope wildcard          Treat *.target.com as in-scope

Scan depth:
  --depth quick             Recon + nuclei only, skip sqlmap/dalfox/ffuf
  --depth full              Full pipeline (default)

Tool control:
  --skip-scan <tool>        Skip a specific tool, comma-separated
  --skip-install-check      Skip tool installation check (faster on repeat runs)
  --allow-internal          Allow scanning private IP ranges (default: blocked)

Timeouts (seconds, override config defaults):
  --timeout-nuclei <s>      Nuclei scan timeout (default: 600)
  --timeout-sqlmap <s>      SQLMap timeout (default: 600)
  --timeout-ffuf <s>        ffuf fuzzing timeout (default: 180)
  --timeout-nmap <s>        Nmap timeout (default: 300)

AI control:
  --ai-tier <1|2|3|4>       Force a specific AI tier (overrides auto-routing)
  --no-ai                   Skip AI triage entirely

Output:
  --output <dir>            Custom output directory (default: ./output)
  --quiet                   Suppress tool stdout
  --no-report               Skip report generation

Cache:
  --no-cache                Disable cache — always run all tools fresh
  --clear-cache             Delete cached data for this target and exit
  --cache-status            Show cache age/freshness for this target and exit

Help:
  --help                    Show this help text

Examples:
  ./bughawk.sh https://example.com
  ./bughawk.sh https://example.com --depth quick
  ./bughawk.sh https://example.com --scope subdomains
  ./bughawk.sh https://example.com --skip-scan sqlmap --ai-tier 3
  ./bughawk.sh https://example.com --quiet --skip-install-check
  ./bughawk.sh http://192.168.1.1 --allow-internal
  ./bughawk.sh https://example.com --no-ai
HELP
}

# ── Argument parsing ──────────────────────────────────────────────────────────
parse_args() {
  if [ $# -eq 0 ] || [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
    show_help
    exit 0
  fi

  TARGET="$1"
  shift

  while [ $# -gt 0 ]; do
    case "$1" in
      --scope)         SCOPE="$2";                              shift 2 ;;
      --depth)         DEPTH="$2";                              shift 2 ;;
      --skip-scan)     IFS=',' read -ra SKIP_TOOLS <<< "$2"; IFS=$' \t\n'; shift 2 ;;
      --skip-install-check) SKIP_INSTALL_CHECK=true;           shift   ;;
      --allow-internal)     ALLOW_INTERNAL=true;               shift   ;;
      --timeout-nuclei)     TIMEOUT_NUCLEI="$2";               shift 2 ;;
      --timeout-sqlmap)     TIMEOUT_SQLMAP="$2";               shift 2 ;;
      --timeout-ffuf)       TIMEOUT_FFUF="$2";                 shift 2 ;;
      --timeout-nmap)       TIMEOUT_NMAP="$2";                 shift 2 ;;
      --ai-tier)       FORCE_TIER="$2";                        shift 2 ;;
      --no-ai)         ENABLE_AI_TRIAGE=false;                 shift   ;;
      --output)        OUTPUT_DIR="$2";                        shift 2 ;;
      --quiet)         QUIET_MODE=true;                        shift   ;;
      --no-report)     NO_REPORT=true;                         shift   ;;
      --no-cache)      NO_CACHE=true;                          shift   ;;
      --clear-cache)   CLEAR_CACHE=true;                       shift   ;;
      --cache-status)  CACHE_STATUS=true;                      shift   ;;
      *) log_error "Unknown flag: $1"; show_help; exit 1 ;;
    esac
  done
}

# ── Legal disclaimer ──────────────────────────────────────────────────────────
check_legal() {
  if [ -f "$HOME/.bughawk_accepted" ]; then
    return 0
  fi

  echo -e "${YELLOW}${BOLD}"
  cat << 'LEGAL'
╔══════════════════════════════════════════════════════════════════════╗
║                    LEGAL DISCLAIMER                                  ║
║                                                                      ║
║  BugHawk is a security scanning tool intended for authorized         ║
║  penetration testing and bug bounty programs ONLY.                   ║
║                                                                      ║
║  By using this tool you confirm:                                     ║
║    1. You have explicit written permission to scan the target         ║
║    2. You are complying with all applicable laws and regulations      ║
║    3. You accept full responsibility for your actions                 ║
║                                                                      ║
║  Unauthorized scanning is illegal. The authors accept no liability.  ║
╚══════════════════════════════════════════════════════════════════════╝
LEGAL
  echo -e "${RESET}"
  echo -n "Type 'I AGREE' to continue: "
  read -r consent
  if [ "$consent" != "I AGREE" ]; then
    echo "Aborted."
    exit 1
  fi
  touch "$HOME/.bughawk_accepted"
}

# ── Private IP guard ──────────────────────────────────────────────────────────
check_private_ip() {
  local target="$1"
  # Strip protocol for IP check
  local host
  host=$(echo "$target" | sed -E 's|https?://||' | cut -d'/' -f1 | cut -d':' -f1)

  if [[ "$host" =~ ^10\. ]] || \
     [[ "$host" =~ ^192\.168\. ]] || \
     [[ "$host" =~ ^172\.(1[6-9]|2[0-9]|3[01])\. ]]; then
    if [ "${ALLOW_INTERNAL:-false}" != "true" ]; then
      log_error "Private IP range blocked: $host"
      log_error "Use --allow-internal to scan internal targets."
      exit 1
    fi
    log_warn "Scanning internal IP: $host (--allow-internal passed)"
  fi
}

# ── Target parsing ────────────────────────────────────────────────────────────
parse_target() {
  # Normalize — strip trailing slash
  TARGET="${TARGET%/}"

  # Extract domain from URL
  TARGET_DOMAIN=$(echo "$TARGET" | sed -E 's|https?://||' | cut -d'/' -f1 | cut -d':' -f1)

  # Output directory
  local ts
  ts=$(date '+%Y%m%d_%H%M')
  local safe_target
  safe_target=$(echo "$TARGET_DOMAIN" | tr '.' '_')
  OUTDIR="${OUTPUT_DIR}/${safe_target}_${ts}"
  mkdir -p "$OUTDIR"
}

# ── Valid tool names for --skip-scan ─────────────────────────────────────────
VALID_SKIP_TOOLS=(subfinder httpx nmap whois waybackurls gf paramspider
                  nuclei dalfox sqlmap ffuf trufflehog gitleaks)

# ── Validate and apply --skip-scan flags ──────────────────────────────────────
apply_skip_tools() {
  [ "${#SKIP_TOOLS[@]}" -eq 0 ] && return 0
  for tool in "${SKIP_TOOLS[@]}"; do
    local valid=false
    for v in "${VALID_SKIP_TOOLS[@]}"; do
      [ "$tool" = "$v" ] && valid=true && break
    done
    if [ "$valid" = "false" ]; then
      log_error "Unknown tool name for --skip-scan: '$tool'"
      log_error "Valid names: ${VALID_SKIP_TOOLS[*]}"
      exit 1
    fi
    # Map tool name to ENABLE_* flag
    case "$tool" in
      sqlmap)      ENABLE_SQLMAP=false ;;
      dalfox)      ENABLE_DALFOX=false ;;
      ffuf)        ENABLE_FFUF=false ;;
      trufflehog)  ENABLE_SECRETS=false ;;
      waybackurls) ENABLE_WAYBACK=false ;;
      paramspider) ENABLE_PARAMSPIDER=false ;;
    esac
    log_info "Skipping tool: $tool"
  done
}

# ── Skip tool check ───────────────────────────────────────────────────────────
is_skipped() {
  local tool="$1"
  for t in "${SKIP_TOOLS[@]:-}"; do
    [ "$t" = "$tool" ] && return 0
  done
  return 1
}

# ── Quiet mode — suppress all tool stdout ─────────────────────────────────────
apply_quiet_mode() {
  if [ "${QUIET_MODE:-false}" = "true" ]; then
    exec 3>&1          # save original stdout
    # Tools are called in subshells — setting QUIET_MODE=true is read by
    # individual tool wrappers. We keep BugHawk's own log_ functions on fd 3.
    log_info "Quiet mode active — tool stdout suppressed"
  fi
}

# ── Main pipeline ─────────────────────────────────────────────────────────────
main() {
  parse_args "$@"
  apply_skip_tools
  apply_quiet_mode
  print_banner
  check_legal
  check_private_ip "$TARGET"
  parse_target   # must come before any use of TARGET_DOMAIN / OUTDIR

  # Cache utility commands — run and exit
  if [ "${CLEAR_CACHE:-false}" = "true" ]; then
    clear_cache "$TARGET_DOMAIN"
    exit 0
  fi
  if [ "${CACHE_STATUS:-false}" = "true" ]; then
    show_cache_status "$TARGET_DOMAIN"
    exit 0
  fi

  local scan_start=$SECONDS

  log_info "Target: $TARGET"
  log_info "Domain: $TARGET_DOMAIN"
  log_info "Output: $OUTDIR"
  log_info "Scope:  $SCOPE | Depth: $DEPTH"
  [ "${NO_CACHE:-false}" = "true" ] && log_warn "Cache disabled — running all tools fresh"
  [ "${NO_CACHE:-false}" != "true" ] && show_cache_status "$TARGET_DOMAIN"

  # Phase 2 — Setup
  log_step 1 "Setup — checking tools"
  if [ "${SKIP_INSTALL_CHECK:-false}" != "true" ]; then
    run_setup
  else
    log_info "Skipping install check (--skip-install-check)"
  fi

  # Phase 3 — Recon
  log_step 2 "Recon"
  local step_start=$SECONDS
  run_recon "$TARGET" "$TARGET_DOMAIN" "$OUTDIR"
  log_success "Recon done in $(( SECONDS - step_start ))s"

  # Phase 4 — Scanning
  log_step 3 "Scanning"
  step_start=$SECONDS
  run_scans "$TARGET" "$TARGET_DOMAIN" "$OUTDIR" "$DEPTH"
  log_success "Scanning done in $(( SECONDS - step_start ))s"

  # Phase 5 — Secrets
  log_step 4 "Secrets detection"
  step_start=$SECONDS
  run_secrets "$TARGET" "$TARGET_DOMAIN" "$OUTDIR"
  log_success "Secrets done in $(( SECONDS - step_start ))s"

  # Phase 6 — Aggregation
  log_step 5 "Aggregating findings"
  step_start=$SECONDS
  aggregate_findings "$OUTDIR"
  log_success "Aggregation done in $(( SECONDS - step_start ))s"

  # Phase 7 — AI Triage
  log_step 6 "AI triage"
  step_start=$SECONDS
  if [ "${ENABLE_AI_TRIAGE:-true}" = "true" ]; then
    run_ai_triage "$TARGET" "$OUTDIR"
    log_success "AI triage done in $(( SECONDS - step_start ))s"
  else
    log_info "AI triage skipped (--no-ai)"
  fi

  # Phase 8 — Report
  log_step 7 "Generating report"
  step_start=$SECONDS
  if [ "${NO_REPORT:-false}" != "true" ]; then
    generate_report "$TARGET" "$OUTDIR"
    log_success "Report done in $(( SECONDS - step_start ))s"
  else
    log_info "Report skipped (--no-report)"
  fi

  # ── End summary ──────────────────────────────────────────────────────────────
  local total_time=$(( SECONDS - scan_start ))
  echo ""
  echo -e "${CYAN}${BOLD}══════════════════════════════════════${RESET}"
  echo -e "${GREEN}${BOLD}  Scan complete — ${total_time}s${RESET}"
  echo -e "${CYAN}${BOLD}══════════════════════════════════════${RESET}"

  if [ -f "$OUTDIR/findings.json" ]; then
    local counts
    counts=$(python3 -c "
import json, sys
try:
  data = json.load(open('$OUTDIR/findings.json'))
  from collections import Counter
  c = Counter(f.get('severity','unknown') for f in data)
  for sev in ['critical','high','medium','low','info']:
    if c[sev]: print(f'  {sev.upper():10} {c[sev]}')
except: pass
" 2>/dev/null)
    [ -n "$counts" ] && echo -e "$counts"
  fi

  echo -e "  Report:    ${OUTDIR}/report.md"
  echo -e "  Raw:       ${OUTDIR}/findings.json"
  [ -f "$OUTDIR/errors.log" ] && echo -e "  Errors:    ${OUTDIR}/errors.log"

  # Auto-open report
  if [ "${OPEN_REPORT_AFTER:-true}" = "true" ] && [ -f "$OUTDIR/report.md" ]; then
    if command -v xdg-open &>/dev/null; then
      xdg-open "$OUTDIR/report.md" 2>/dev/null &
    elif command -v open &>/dev/null; then
      open "$OUTDIR/report.md" 2>/dev/null &
    elif command -v start &>/dev/null; then
      start "$OUTDIR/report.md" 2>/dev/null &
    fi
  fi
}

main "$@"
