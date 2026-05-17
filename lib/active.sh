#!/usr/bin/env bash
# lib/active.sh — active checks: CORS, headers, open redirect, LFI, takeover, SSL, SSRF

# ── CORS Misconfiguration ──────────────────────────────────────────────────────
run_cors_check() {
  local domain="$1" tmpfile="$2"
  local port="${TARGET_PORT:-443}"
  local base_url="https://${domain}"
  [ "$port" != "443" ] && base_url="https://${domain}:${port}"

  for origin in "https://evil.com" "null" "https://${domain}.evil.com"; do
    local resp acao acac
    resp=$(curl -s -I "$base_url" -H "Origin: ${origin}" --max-time 10 2>/dev/null)
    acao=$(echo "$resp" | grep -i "^access-control-allow-origin:" | cut -d: -f2- | tr -d ' \r\n')
    acac=$(echo "$resp" | grep -i "^access-control-allow-credentials:" | grep -i "true" || true)

    if [ "$acao" = "$origin" ] || [ "$acao" = "*" ]; then
      local sev="HIGH"
      [ -n "$acac" ] && sev="CRITICAL"
      echo "${sev}|cors_misconfiguration|${base_url}|Origin: ${origin} reflected in ACAO: ${acao}" \
        >> "$tmpfile"
      log_warn "CORS misconfiguration: ${base_url} reflects ${origin}"
    fi
  done
}

# ── Security Headers Check ─────────────────────────────────────────────────────
run_headers_check() {
  local domain="$1" tmpfile="$2"
  local port="${TARGET_PORT:-443}"
  local base_url="https://${domain}"
  [ "$port" != "443" ] && base_url="https://${domain}:${port}"

  local resp
  resp=$(curl -s -I "$base_url" --max-time 10 2>/dev/null)

  local -A checks=(
    ["Strict-Transport-Security"]="missing_hsts"
    ["Content-Security-Policy"]="missing_csp"
    ["X-Frame-Options"]="missing_x_frame_options"
    ["X-Content-Type-Options"]="missing_x_content_type"
    ["Referrer-Policy"]="missing_referrer_policy"
    ["Permissions-Policy"]="missing_permissions_policy"
  )

  for header in "${!checks[@]}"; do
    if ! echo "$resp" | grep -qi "^${header}:"; then
      echo "LOW|${checks[$header]}|${base_url}|Missing HTTP security header: ${header}" \
        >> "$tmpfile"
    fi
  done
}

# ── Open Redirect Active Testing ──────────────────────────────────────────────
run_open_redirect() {
  local outdir="$1" tmpfile="$2"
  if [ ! -s "$outdir/params_redirect.txt" ]; then
    log_warn "params_redirect.txt empty — skipping open redirect check"
    return
  fi

  local payloads_file="${BUGHAWK_DIR}/payloads/redirect.txt"
  [ ! -f "$payloads_file" ] && return

  while IFS= read -r url; do
    [ -z "$url" ] && continue
    while IFS= read -r payload; do
      [ -z "$payload" ] && continue
      # Replace the value of any redirect-like parameter
      local test_url
      test_url=$(echo "$url" | sed -E 's/(url|redirect|next|return|goto|rurl|target|dest|destination|location|r|u|link)=([^&]*)/\1='"${payload//\//\\/}"'/gi' 2>/dev/null || echo "$url")
      [ "$test_url" = "$url" ] && continue

      local effective_url
      effective_url=$(curl -s -o /dev/null -L -w "%{url_effective}" \
        "$test_url" --max-time 10 2>/dev/null)

      if echo "$effective_url" | grep -qi "evil\.com"; then
        echo "HIGH|open_redirect|${url}|Redirected to: ${effective_url} via payload: ${payload}" \
          >> "$tmpfile"
        log_warn "Open redirect: ${url} → ${effective_url}"
        break  # one confirmed redirect per URL is enough
      fi
    done < "$payloads_file"
  done < "$outdir/params_redirect.txt"
}

# ── LFI Active Testing ────────────────────────────────────────────────────────
run_lfi_active() {
  local outdir="$1" tmpfile="$2"
  if [ ! -s "$outdir/params_lfi.txt" ]; then
    log_warn "params_lfi.txt empty — skipping active LFI check"
    return
  fi

  local payloads_file="${BUGHAWK_DIR}/payloads/lfi.txt"
  [ ! -f "$payloads_file" ] && return

  while IFS= read -r url; do
    [ -z "$url" ] && continue
    while IFS= read -r payload; do
      [ -z "$payload" ] && continue
      local test_url
      test_url=$(echo "$url" | sed -E 's/(file|path|page|include|doc|document|folder|root|pg|style)=([^&]*)/\1='"${payload//\//\\/}"'/gi' 2>/dev/null || echo "$url")
      [ "$test_url" = "$url" ] && continue

      local resp
      resp=$(curl -s "$test_url" --max-time 10 2>/dev/null)

      if echo "$resp" | grep -qE "root:x:0:0|/bin/bash|/bin/sh|\[boot loader\]|\[fonts\]"; then
        echo "CRITICAL|lfi|${url}|LFI confirmed with payload: ${payload}" >> "$tmpfile"
        log_warn "LFI confirmed: ${url} with ${payload}"
        break
      fi
    done < "$payloads_file"
  done < "$outdir/params_lfi.txt"
}

# ── Subdomain Takeover ────────────────────────────────────────────────────────
run_takeover_check() {
  local outdir="$1"
  if [ ! -s "$outdir/subdomains.txt" ]; then
    log_warn "subdomains.txt empty — skipping takeover check"
    return
  fi

  local subzy_bin="$HOME/go/bin/subzy"
  if ! command -v "$subzy_bin" &>/dev/null && ! command -v subzy &>/dev/null; then
    log_warn "subzy not found — skipping takeover check"
    return
  fi
  command -v "$subzy_bin" &>/dev/null || subzy_bin="subzy"

  "$subzy_bin" run \
    --targets "$outdir/subdomains.txt" \
    --output "$outdir/takeover.json" \
    --hide-fails 2>/dev/null \
    || log_tool_error "subzy" "exited non-zero"
}

# ── SSL/TLS Analysis ──────────────────────────────────────────────────────────
run_ssl_check() {
  local domain="$1" outdir="$2"
  local port="${TARGET_PORT:-443}"
  local testssl_bin="/opt/testssl/testssl.sh"

  if [ ! -x "$testssl_bin" ]; then
    log_warn "testssl.sh not found at /opt/testssl — skipping SSL check"
    return
  fi

  safe_timeout "${TIMEOUT_SSL:-180}" \
    "$testssl_bin" \
      --jsonfile "$outdir/ssl.json" \
      --quiet \
      --color 0 \
      "${domain}:${port}" 2>/dev/null \
    || log_tool_error "testssl" "exited non-zero or timed out"
}

# ── SSRF OOB Detection ────────────────────────────────────────────────────────
run_ssrf_check() {
  local outdir="$1"
  if [ ! -s "$outdir/params_ssrf.txt" ]; then
    log_warn "params_ssrf.txt empty — skipping SSRF check"
    return
  fi

  local interactsh_bin="$HOME/go/bin/interactsh-client"
  if ! command -v "$interactsh_bin" &>/dev/null && ! command -v interactsh-client &>/dev/null; then
    log_warn "interactsh-client not found — skipping SSRF OOB check"
    return
  fi
  command -v "$interactsh_bin" &>/dev/null || interactsh_bin="interactsh-client"

  # Generate OOB host and inject into params, poll for 30s
  local oob_log="$outdir/ssrf_oob.txt"
  "$interactsh_bin" -server interactsh.com -n 1 -o "$oob_log" &
  local iact_pid=$!
  sleep 2

  local oob_host
  oob_host=$(cat "$oob_log" 2>/dev/null | head -1 | tr -d '\n')

  if [ -n "$oob_host" ]; then
    while IFS= read -r url; do
      [ -z "$url" ] && continue
      local test_url
      test_url=$(echo "$url" | sed -E "s|(url|ssrf|host|server|dest|target)=([^&]*)|\1=https://${oob_host}|gi" 2>/dev/null || echo "$url")
      [ "$test_url" != "$url" ] && curl -s "$test_url" --max-time 5 2>/dev/null &
    done < "$outdir/params_ssrf.txt"

    sleep 30
    kill "$iact_pid" 2>/dev/null || true

    if [ -s "$oob_log" ] && grep -q "http\|dns" "$oob_log" 2>/dev/null; then
      echo "HIGH|ssrf_oob|${oob_host}|OOB callback received — SSRF confirmed" \
        >> "$outdir/manual_findings.txt"
      log_warn "SSRF OOB callback detected!"
    fi
  else
    kill "$iact_pid" 2>/dev/null || true
    log_warn "Could not get interactsh OOB host — skipping SSRF OOB"
  fi
}

# ── Main Active Checks Runner ──────────────────────────────────────────────────
run_active() {
  local target="$1"
  local domain="$2"
  local outdir="$3"

  if [ "${ENABLE_ACTIVE:-true}" != "true" ]; then
    log_info "Active checks disabled (ENABLE_ACTIVE=false)"
    return
  fi

  touch "$outdir/manual_findings.txt"

  local tmp_cors tmp_headers tmp_redirect tmp_lfi
  tmp_cors=$(mktemp)
  tmp_headers=$(mktemp)
  tmp_redirect=$(mktemp)
  tmp_lfi=$(mktemp)
  trap "rm -f '$tmp_cors' '$tmp_headers' '$tmp_redirect' '$tmp_lfi'" RETURN

  PIDS=()
  local pid_descs=()

  if [ "${ENABLE_CORS_CHECK:-true}" = "true" ]; then
    run_cors_check "$domain" "$tmp_cors" &
    local _p=$!; PIDS+=($_p); pid_descs+=($_p "cors: testing reflected origin + credentials")
  fi

  if [ "${ENABLE_HEADERS_CHECK:-true}" = "true" ]; then
    run_headers_check "$domain" "$tmp_headers" &
    local _p=$!; PIDS+=($_p); pid_descs+=($_p "headers: checking CSP/HSTS/X-Frame-Options")
  fi

  if [ "${ENABLE_REDIRECT_CHECK:-true}" = "true" ]; then
    run_open_redirect "$outdir" "$tmp_redirect" &
    local _p=$!; PIDS+=($_p); pid_descs+=($_p "redirect: injecting evil.com into redirect params")
  fi

  if [ "${ENABLE_LFI_ACTIVE:-true}" = "true" ]; then
    run_lfi_active "$outdir" "$tmp_lfi" &
    local _p=$!; PIDS+=($_p); pid_descs+=($_p "lfi: injecting traversal payloads")
  fi

  if [ "${ENABLE_TAKEOVER:-true}" = "true" ]; then
    run_takeover_check "$outdir" &
    local _p=$!; PIDS+=($_p); pid_descs+=($_p "subzy: checking subdomains for takeover")
  fi

  if [ "${ENABLE_SSL_CHECK:-true}" = "true" ]; then
    run_ssl_check "$domain" "$outdir" &
    local _p=$!; PIDS+=($_p); pid_descs+=($_p "testssl: cipher + protocol + cert analysis")
  fi

  if [ "${#pid_descs[@]}" -gt 0 ]; then
    show_multi_progress "ACTIVE" "${pid_descs[@]}"
  fi

  local failed=0
  for pid in "${PIDS[@]}"; do
    if ! wait "$pid" 2>/dev/null; then
      log_warn "An active check failed (PID $pid) — check errors.log"
      failed=$((failed + 1))
    fi
  done

  # Atomic merge of temp files
  cat "$tmp_cors" "$tmp_headers" "$tmp_redirect" "$tmp_lfi" \
    >> "$outdir/manual_findings.txt" 2>/dev/null || true

  # SSRF runs sequentially (needs OOB polling wait)
  if [ "${ENABLE_SSRF_OOB:-false}" = "true" ]; then
    log_info "interactsh — SSRF OOB detection (30s poll)..."
    run_ssrf_check "$outdir"
  fi

  [ "$failed" -gt 0 ] && log_warn "$failed active check(s) had errors."

  local active_count=0
  [ -s "$outdir/manual_findings.txt" ] \
    && active_count=$(wc -l < "$outdir/manual_findings.txt")
  log_success "Active checks done: $active_count findings"
}
