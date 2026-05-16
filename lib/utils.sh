#!/usr/bin/env bash
# lib/utils.sh — shared colors, logging, spinner, table helpers, safe_timeout

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

# ── Logging ───────────────────────────────────────────────────────────────────
log_info()    { echo -e "${BLUE}[*]${RESET} $1"; }
log_success() { echo -e "${GREEN}[+]${RESET} $1"; }
log_warn()    { echo -e "${YELLOW}[!]${RESET} $1"; }
log_error()   { echo -e "${RED}[✗]${RESET} $1"; }
log_critical(){ echo -e "${RED}${BOLD}[CRITICAL]${RESET} $1"; }
log_step()    { echo -e "\n${CYAN}${BOLD}[$1/$TOTAL_STEPS] $2${RESET}"; }

# ── Banner ────────────────────────────────────────────────────────────────────
print_banner() {
  echo -e "${RED}${BOLD}"
  cat << 'BANNER'
  ██████╗ ██╗   ██╗ ██████╗ ██╗  ██╗ █████╗ ██╗    ██╗██╗  ██╗
  ██╔══██╗██║   ██║██╔════╝ ██║  ██║██╔══██╗██║    ██║██║ ██╔╝
  ██████╔╝██║   ██║██║  ███╗███████║███████║██║ █╗ ██║█████╔╝
  ██╔══██╗██║   ██║██║   ██║██╔══██║██╔══██║██║███╗██║██╔═██╗
  ██████╔╝╚██████╔╝╚██████╔╝██║  ██║██║  ██║╚███╔███╔╝██║  ██╗
  ╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝
  Autonomous Bug Bounty Scanner — github.com/arshadakl/BugHawk
BANNER
  echo -e "${RESET}"
}

# ── Spinner — show_spinner <pid> <message> ────────────────────────────────────
show_spinner() {
  local pid=$1
  local msg="${2:-Working...}"
  local spin='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
  local i=0
  while kill -0 "$pid" 2>/dev/null; do
    printf "\r  ${CYAN}${spin:$i:1}${RESET}  %-60s" "$msg"
    i=$(( (i+1) % 10 ))
    sleep 0.15
  done
  printf "\r%-70s\r" ""  # clear line
}

# ── Multi-progress — show_multi_progress <label> <pid1> <desc1> [pid2 desc2...]
# Shows which jobs are still running, cycles through their descriptions
show_multi_progress() {
  local label="$1"; shift
  local spin='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
  local i=0
  local tick=0

  # Build parallel arrays from alternating pid/desc args
  local pids=() descs=()
  while [ $# -ge 2 ]; do
    pids+=("$1"); descs+=("$2"); shift 2
  done

  while true; do
    # Collect still-running descriptions
    local running=()
    for idx in "${!pids[@]}"; do
      kill -0 "${pids[$idx]}" 2>/dev/null && running+=("${descs[$idx]}")
    done

    [ "${#running[@]}" -eq 0 ] && break

    # Cycle through running descriptions every 2 ticks
    local show_idx=$(( (tick / 2) % ${#running[@]} ))
    local msg="${running[$show_idx]}"

    printf "\r  ${CYAN}${spin:$i:1}${RESET}  ${BOLD}[%s]${RESET} %-50s" "$label" "$msg"
    i=$(( (i+1) % 10 ))
    tick=$(( tick + 1 ))
    sleep 0.2
  done
  printf "\r%-80s\r" ""
}

# ── Tool Status Table ─────────────────────────────────────────────────────────
print_tool_table_header() {
  printf "\n  %-16s %-8s %-20s\n" "Tool" "Status" "Version"
  printf "  %-16s %-8s %-20s\n" "────────────────" "────────" "────────────────────"
}

print_tool_row() {
  # $1=name $2="✓" or "✗" $3=version
  printf "  %-16s %-8s %-20s\n" "$1" "$2" "$3"
}

# ── Error Logger ──────────────────────────────────────────────────────────────
log_tool_error() {
  # $1=tool $2=message
  local ts
  ts=$(date '+%Y-%m-%d %H:%M:%S')
  echo "[$ts] ERROR [$1] $2" >> "${OUTDIR:-/tmp}/errors.log"
  log_warn "$1 failed — check errors.log"
}

# ── safe_timeout ──────────────────────────────────────────────────────────────
# Cross-platform timeout: gtimeout (macOS brew) > timeout (GNU) > bash fallback
safe_timeout() {
  local secs=$1; shift
  if command -v gtimeout &>/dev/null; then
    gtimeout "$secs" "$@"
  elif command -v timeout &>/dev/null; then
    timeout "$secs" "$@"
  else
    # Pure bash fallback for environments with neither
    "$@" &
    local pid=$!
    ( sleep "$secs" && kill "$pid" 2>/dev/null ) &
    local watchdog=$!
    wait "$pid"
    local exit_code=$?
    kill "$watchdog" 2>/dev/null
    wait "$watchdog" 2>/dev/null
    return $exit_code
  fi
}
