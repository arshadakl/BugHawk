#!/usr/bin/env bash
# lib/scan.sh — vulnerability scanners (nuclei, dalfox, sqlmap, ffuf) in parallel

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
  safe_timeout "${TIMEOUT_FFUF:-180}" \
    ffuf \
      -u "https://${domain}/FUZZ" \
      -w "$wordlist" \
      -mc "${FFUF_MATCH_CODES:-200,301,302,403,405}" \
      -t "${FFUF_THREADS:-50}" \
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
  local pid_descs=()

  log_info "nuclei — scanning with CVE + misconfiguration templates..."
  run_nuclei "$target" "$outdir" &
  local _p=$!; PIDS+=($_p); pid_descs+=($_p "nuclei: template-based CVE + misconfiguration scan")

  if [ "$depth" = "full" ]; then
    if [ "${ENABLE_DALFOX:-true}" = "true" ]; then
      log_info "dalfox — XSS detection on extracted parameters..."
      run_dalfox "$outdir" &
      local _p=$!; PIDS+=($_p); pid_descs+=($_p "dalfox: fuzzing XSS payloads on reflected parameters")
    fi

    if [ "${ENABLE_SQLMAP:-true}" = "true" ]; then
      log_info "sqlmap — SQL injection testing (this may take a while)..."
      run_sqlmap "$outdir" &
      local _p=$!; PIDS+=($_p); pid_descs+=($_p "sqlmap: SQL injection exploitation — testing all params")
    fi

    if [ "${ENABLE_FFUF:-true}" = "true" ]; then
      log_info "ffuf — directory + endpoint fuzzing..."
      run_ffuf "$domain" "$outdir" &
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

  [ "$failed" -gt 0 ] && log_warn "$failed scanner(s) had errors. Results may be incomplete."

  # Log finding counts
  local nuclei_count=0
  [ -s "$outdir/nuclei.json" ] && nuclei_count=$(wc -l < "$outdir/nuclei.json")
  log_success "Scans done: $nuclei_count nuclei findings"
}
