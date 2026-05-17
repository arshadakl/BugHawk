#!/usr/bin/env bash
# lib/recon.sh — passive and active recon pipeline

# ── Subfinder ─────────────────────────────────────────────────────────────────
run_subfinder() {
  local domain="$1" outdir="$2"
  subfinder -d "$domain" -silent -o "$outdir/subdomains.txt" 2>/dev/null \
    || log_tool_error "subfinder" "exited non-zero"
}

# ── httpx ─────────────────────────────────────────────────────────────────────
run_httpx() {
  local outdir="$1"
  # Use explicit go/bin path to avoid Python httpx conflict
  local httpx_bin="$HOME/go/bin/httpx"
  command -v "$httpx_bin" &>/dev/null || httpx_bin="httpx"

  if [ ! -s "$outdir/subdomains.txt" ]; then
    log_warn "subdomains.txt empty — skipping httpx"
    return
  fi

  "$httpx_bin" -l "$outdir/subdomains.txt" \
    -status-code -title -tech-detect \
    -json -o "$outdir/httpx.json" -silent 2>/dev/null \
    || log_tool_error "httpx" "exited non-zero"
}

# ── Whois ─────────────────────────────────────────────────────────────────────
run_whois() {
  local domain="$1" outdir="$2"
  whois "$domain" > "$outdir/whois.txt" 2>/dev/null \
    || log_tool_error "whois" "exited non-zero"
}

# ── Nmap ──────────────────────────────────────────────────────────────────────
run_nmap() {
  local domain="$1" outdir="$2"
  local port_arg=""
  local port="${TARGET_PORT:-443}"
  # Scan specific port when non-standard
  if [ "$port" != "443" ] && [ "$port" != "80" ]; then
    port_arg="-p $port"
  fi
  safe_timeout "${TIMEOUT_NMAP:-300}" \
    nmap -sV --script=http-headers,http-title \
    $port_arg "$domain" \
    -oX "$outdir/nmap.xml" \
    -oN "$outdir/nmap.txt" 2>/dev/null \
    || log_tool_error "nmap" "exited non-zero or timed out"
}

# ── Waybackurls ───────────────────────────────────────────────────────────────
run_waybackurls() {
  local domain="$1" outdir="$2"
  waybackurls "$domain" \
    | head -"${WAYBACK_URL_LIMIT:-5000}" \
    | anew "$outdir/wayback.txt" 2>/dev/null \
    || log_tool_error "waybackurls" "exited non-zero"
}

# ── gf pattern extraction ─────────────────────────────────────────────────────
run_gf_patterns() {
  local outdir="$1"
  if [ ! -s "$outdir/wayback.txt" ]; then
    log_warn "wayback.txt empty — skipping gf pattern extraction"
    return
  fi

  for pattern in xss sqli lfi ssrf redirect; do
    cat "$outdir/wayback.txt" | gf "$pattern" > "$outdir/params_${pattern}.txt" 2>/dev/null || true
  done
}

# ── Paramspider ───────────────────────────────────────────────────────────────
run_paramspider() {
  local domain="$1" outdir="$2"
  local port="${TARGET_PORT:-443}"
  local port_arg=""
  [ "$port" != "443" ] && port_arg="--port $port"

  # v2 writes to results/<domain>.txt — move it after run
  paramspider -d "$domain" $port_arg 2>/dev/null || true

  local ps_out="results/${domain}.txt"
  if [ -f "$ps_out" ]; then
    cat "$ps_out" >> "$outdir/paramspider.txt"
    rm -f "$ps_out"
  else
    log_tool_error "paramspider" "output file not found (results/${domain}.txt)"
  fi
}

# ── Main Recon Function ───────────────────────────────────────────────────────
run_recon() {
  local target="$1"
  local domain="$2"
  local outdir="$3"

  PIDS=()
  local pid_descs=()

  # Init cache for this domain
  init_cache "$domain"

  # Subfinder — check cache first (sequential: httpx depends on its output)
  if ! cache_load "$domain" "subdomains.txt" "$outdir"; then
    log_info "subfinder — passive subdomain enumeration..."
    run_subfinder "$domain" "$outdir"
    cache_save "$domain" "subdomains.txt" "$outdir"
  fi

  # httpx — check cache, else run after subfinder
  if ! cache_load "$domain" "httpx.json" "$outdir"; then
    log_info "httpx — probing live hosts, detecting tech stack..."
    run_httpx "$outdir" &
    local _p=$!; PIDS+=($_p); pid_descs+=($_p "httpx: probing live hosts + tech detection")
  fi

  # whois
  if ! cache_load "$domain" "whois.txt" "$outdir"; then
    run_whois "$domain" "$outdir" &
    local _p=$!; PIDS+=($_p); pid_descs+=($_p "whois: fetching registrar + ASN info")
  fi

  # nmap — cache both outputs together
  if ! cache_load "$domain" "nmap.txt" "$outdir"; then
    run_nmap "$domain" "$outdir" &
    local _p=$!; PIDS+=($_p); pid_descs+=($_p "nmap: port scan + service version detection")
  fi

  # waybackurls — special merge logic
  if [ "${ENABLE_WAYBACK:-true}" = "true" ]; then
    if ! cache_load_wayback "$domain" "$outdir"; then
      run_waybackurls "$domain" "$outdir" &
      local _p=$!; PIDS+=($_p); pid_descs+=($_p "waybackurls: pulling historical URLs from archive.org")
    fi
  fi

  # paramspider
  if [ "${ENABLE_PARAMSPIDER:-true}" = "true" ]; then
    if ! cache_load "$domain" "paramspider.txt" "$outdir"; then
      run_paramspider "$domain" "$outdir" &
      local _p=$!; PIDS+=($_p); pid_descs+=($_p "paramspider: crawling for injectable parameters")
    fi
  fi

  if [ "${#pid_descs[@]}" -gt 0 ]; then
    show_multi_progress "RECON" "${pid_descs[@]}"
  else
    log_success "All recon data served from cache"
  fi

  # Wait for all, log failures
  local failed=0
  for pid in "${PIDS[@]}"; do
    if ! wait "$pid" 2>/dev/null; then
      log_warn "A recon task failed (PID $pid) — check errors.log"
      failed=$((failed + 1))
    fi
  done

  [ "$failed" -gt 0 ] && log_warn "$failed recon tool(s) had errors. Results may be incomplete."

  # Save newly collected data to cache
  cache_save "$domain" "httpx.json"      "$outdir"
  cache_save "$domain" "whois.txt"       "$outdir"
  cache_save "$domain" "nmap.txt"        "$outdir"
  cache_save "$domain" "nmap.xml"        "$outdir"
  cache_save "$domain" "paramspider.txt" "$outdir"
  cache_merge_wayback  "$domain"         "$outdir"

  # gf runs after waybackurls (sequential dependency)
  run_gf_patterns "$outdir"

  # Cache gf pattern outputs too
  for pat in xss sqli lfi ssrf redirect; do
    cache_save "$domain" "params_${pat}.txt" "$outdir"
  done

  # Log what was found
  local sub_count=0
  local url_count=0
  [ -s "$outdir/subdomains.txt" ] && sub_count=$(wc -l < "$outdir/subdomains.txt")
  [ -s "$outdir/wayback.txt" ]    && url_count=$(wc -l < "$outdir/wayback.txt")
  log_success "Recon: $sub_count subdomains, $url_count wayback URLs"
}
