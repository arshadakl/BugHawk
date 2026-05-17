#!/usr/bin/env bash
# lib/scan.sh — vulnerability scanners (nuclei, dalfox, sqlmap, ffuf) in parallel

# ── Interactive skip menu (fires on Ctrl+C during scans) ─────────────────────
# Reads global PIDS and pid_descs arrays populated by run_scans().
_skip_menu() {
  printf "\r%-70s\r" " "   # clear progress line
  echo ""
  echo -e "${YELLOW}${BOLD}[!] Interrupted during scan.${RESET}"
  echo -e "  ${BOLD}s${RESET}) skip a running tool and continue"
  echo -e "  ${BOLD}a${RESET}) abort all running scans"
  echo -e "  ${BOLD}c${RESET}) continue (default, auto in 10s)"
  printf "Choice [s/a/c]: "

  local choice
  read -r -t 10 choice 2>/dev/null || choice="c"
  choice="${choice:-c}"

  case "${choice,,}" in
    s)
      local running=() running_descs=() i=0
      while [ $i -lt ${#PIDS[@]} ]; do
        local pid="${PIDS[$i]}"
        if kill -0 "$pid" 2>/dev/null; then
          running+=("$pid")
          local j=0 desc="unknown tool"
          while [ $j -lt ${#pid_descs[@]} ]; do
            if [ "${pid_descs[$j]}" = "$pid" ]; then
              desc="${pid_descs[$((j+1))]}"; break
            fi
            j=$((j+2))
          done
          running_descs+=("$desc")
        fi
        i=$((i+1))
      done

      if [ ${#running[@]} -eq 0 ]; then
        log_info "No tools still running — continuing."; return
      fi

      echo ""
      echo -e "  Running tools:"
      local k=0
      while [ $k -lt ${#running[@]} ]; do
        echo -e "    $((k+1))) ${running_descs[$k]}"
        k=$((k+1))
      done
      printf "Skip which? [1-%d] (default 1): " "${#running[@]}"

      local pick
      read -r -t 10 pick 2>/dev/null || pick="1"
      pick="${pick:-1}"

      if [[ "$pick" =~ ^[0-9]+$ ]] && [ "$pick" -ge 1 ] && [ "$pick" -le "${#running[@]}" ]; then
        local kill_pid="${running[$((pick-1))]}"
        kill "$kill_pid" 2>/dev/null || true
        log_warn "Skipped tool PID $kill_pid — continuing with remaining..."
      else
        log_warn "Invalid choice — continuing."
      fi
      ;;
    a)
      log_warn "Aborting all scans..."
      local p
      for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
      ;;
    *)
      log_info "Continuing..."
      ;;
  esac
}

# ── Quiet redirect helper ─────────────────────────────────────────────────────
_quiet() {
  if [ "${QUIET_MODE:-false}" = "true" ]; then
    "$@" >/dev/null 2>&1
  else
    "$@"
  fi
}

# ── Nuclei ────────────────────────────────────────────────────────────────────
run_nuclei() {
  local target="$1" outdir="$2"
  _quiet safe_timeout "${TIMEOUT_NUCLEI:-600}" \
    nuclei \
      -target "$target" \
      -severity "${NUCLEI_SEVERITY:-medium,high,critical}" \
      -json-export "$outdir/nuclei.json" \
      -silent 2>/dev/null \
    || log_tool_error "nuclei" "exited non-zero or timed out"
}

# ── Dalfox ────────────────────────────────────────────────────────────────────
run_dalfox() {
  local outdir="$1"
  if [ ! -s "$outdir/params_xss.txt" ]; then
    log_warn "params_xss.txt empty — skipping dalfox"
    return
  fi
  dalfox file "$outdir/params_xss.txt" \
    --output "$outdir/dalfox.json" \
    --format json \
    --silence 2>/dev/null \
    || log_tool_error "dalfox" "exited non-zero"
}

# ── SQLMap ────────────────────────────────────────────────────────────────────
run_sqlmap() {
  local outdir="$1"
  if [ ! -s "$outdir/params_sqli.txt" ]; then
    log_warn "params_sqli.txt empty — skipping sqlmap"
    return
  fi
  safe_timeout "${TIMEOUT_SQLMAP:-600}" \
    sqlmap \
      -m "$outdir/params_sqli.txt" \
      --batch \
      --level="${SQLMAP_LEVEL:-2}" \
      --risk="${SQLMAP_RISK:-2}" \
      --output-dir="$outdir/sqlmap" 2>/dev/null \
    || log_tool_error "sqlmap" "exited non-zero or timed out"
}

# ── ffuf ──────────────────────────────────────────────────────────────────────
run_ffuf() {
  local domain="$1" outdir="$2"
  local wordlist="${BUGHAWK_DIR}/wordlists/dirs.txt"
  if [ ! -s "$wordlist" ]; then
    log_warn "wordlists/dirs.txt missing — skipping ffuf"
    return
  fi
  local port="${TARGET_PORT:-443}"
  local base_url="https://${domain}"
  [ "$port" != "443" ] && base_url="https://${domain}:${port}"
  safe_timeout "${TIMEOUT_FFUF:-180}" \
    ffuf \
      -u "${base_url}/FUZZ" \
      -w "$wordlist" \
      -mc "${FFUF_MATCH_CODES:-200,301,302,403,405}" \
      -t "${FFUF_THREADS:-50}" \
      -maxtime "${TIMEOUT_FFUF:-180}" \
      -json -o "$outdir/ffuf.json" \
      -s 2>/dev/null \
    || log_tool_error "ffuf" "exited non-zero or timed out"
}

# ── Main Scan Runner ──────────────────────────────────────────────────────────
run_scans() {
  local target="$1"
  local domain="$2"
  local outdir="$3"
  local depth="${4:-full}"

  PIDS=()
  pid_descs=()   # global — readable by _skip_menu handler

  # Trap Ctrl+C: show interactive skip menu instead of killing everything
  trap '_skip_menu' INT

  log_info "nuclei — scanning with CVE + misconfiguration templates..."
  ( trap '' INT; run_nuclei "$target" "$outdir" ) &
  local _p=$!; PIDS+=($_p); pid_descs+=($_p "nuclei: template-based CVE + misconfiguration scan")

  if [ "$depth" = "full" ]; then
    if [ "${ENABLE_DALFOX:-true}" = "true" ]; then
      log_info "dalfox — XSS detection on extracted parameters..."
      ( trap '' INT; run_dalfox "$outdir" ) &
      local _p=$!; PIDS+=($_p); pid_descs+=($_p "dalfox: fuzzing XSS payloads on reflected parameters")
    fi

    if [ "${ENABLE_SQLMAP:-true}" = "true" ]; then
      log_info "sqlmap — SQL injection testing (this may take a while)..."
      ( trap '' INT; run_sqlmap "$outdir" ) &
      local _p=$!; PIDS+=($_p); pid_descs+=($_p "sqlmap: SQL injection exploitation — testing all params")
    fi

    if [ "${ENABLE_FFUF:-true}" = "true" ]; then
      log_info "ffuf — directory + endpoint fuzzing..."
      ( trap '' INT; run_ffuf "$domain" "$outdir" ) &
      local _p=$!; PIDS+=($_p); pid_descs+=($_p "ffuf: brute-forcing directories and hidden endpoints")
    fi
  else
    log_info "Depth: quick — skipping dalfox, sqlmap, ffuf"
  fi

  show_multi_progress "SCANNING" "${pid_descs[@]}"

  # Wait for all, log failures
  local failed=0
  for pid in "${PIDS[@]}"; do
    if ! wait "$pid" 2>/dev/null; then
      log_warn "A scan task failed (PID $pid) — check errors.log"
      failed=$((failed + 1))
    fi
  done

  trap - INT   # restore default Ctrl+C behaviour after scans finish

  [ "$failed" -gt 0 ] && log_warn "$failed scanner(s) had errors. Results may be incomplete."

  # Log finding counts
  local nuclei_count=0
  [ -s "$outdir/nuclei.json" ] && nuclei_count=$(wc -l < "$outdir/nuclei.json")
  log_success "Scans done: $nuclei_count nuclei findings"
}
