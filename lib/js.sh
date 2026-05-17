#!/usr/bin/env bash
# lib/js.sh — JavaScript analysis: endpoint extraction + secret detection

# ── Collect JS file URLs ───────────────────────────────────────────────────────
collect_js_urls() {
  local domain="$1" outdir="$2"
  local port="${TARGET_PORT:-443}"
  local base_url="https://${domain}"
  [ "$port" != "443" ] && base_url="https://${domain}:${port}"
  local js_urls_file="$outdir/js_urls.txt"

  # From wayback history
  if [ -s "$outdir/wayback.txt" ]; then
    grep -iE '\.js(\?|$)' "$outdir/wayback.txt" >> "$js_urls_file" 2>/dev/null || true
  fi

  # From httpx output — extract URLs ending in .js
  if [ -s "$outdir/httpx.json" ]; then
    python3 -c "
import json, sys
for line in open('$outdir/httpx.json', errors='ignore'):
    try:
        r = json.loads(line)
        url = r.get('url','')
        if url.lower().endswith('.js'):
            print(url)
    except: pass
" >> "$js_urls_file" 2>/dev/null || true
  fi

  # Direct crawl of target homepage for <script src> tags
  local page
  page=$(curl -s "$base_url" --max-time 15 2>/dev/null)
  echo "$page" | grep -oE 'src="[^"]*\.js[^"]*"' | sed 's/src="//;s/"//' | while read -r src; do
    # Make absolute if relative
    if echo "$src" | grep -q '^http'; then
      echo "$src"
    elif echo "$src" | grep -q '^//'; then
      echo "https:${src}"
    elif echo "$src" | grep -q '^/'; then
      echo "${base_url}${src}"
    else
      echo "${base_url}/${src}"
    fi
  done >> "$js_urls_file" 2>/dev/null || true

  # Use getJS if available
  if command -v getJS &>/dev/null || [ -x "$HOME/go/bin/getJS" ]; then
    local getjs_bin="$HOME/go/bin/getJS"
    command -v getjs_bin &>/dev/null || getjs_bin="getJS"
    "$getjs_bin" --url "$base_url" --output /dev/stdout 2>/dev/null \
      >> "$js_urls_file" || true
  fi

  # Deduplicate
  if [ -s "$js_urls_file" ]; then
    sort -u "$js_urls_file" -o "$js_urls_file"
    log_info "JS analysis: found $(wc -l < "$js_urls_file") unique JS files"
  fi
}

# ── Download JS files ──────────────────────────────────────────────────────────
download_js_files() {
  local outdir="$1"
  local js_dir="$outdir/js"
  mkdir -p "$js_dir"

  if [ ! -s "$outdir/js_urls.txt" ]; then
    return
  fi

  local count=0
  while IFS= read -r url; do
    [ -z "$url" ] && continue
    # Safe filename: hash the URL
    local fname
    fname=$(echo "$url" | md5sum | cut -c1-12).js
    curl -s "$url" --max-time 15 -o "$js_dir/$fname" 2>/dev/null && count=$((count + 1))
    # Cap at 100 files to avoid runaway download
    [ $count -ge 100 ] && break
  done < "$outdir/js_urls.txt"

  log_info "JS analysis: downloaded $count JS files"
}

# ── jsluice — endpoint + secret extraction ─────────────────────────────────────
run_jsluice() {
  local outdir="$1" tmpfile="$2"
  local js_dir="$outdir/js"

  local jsluice_bin="$HOME/go/bin/jsluice"
  command -v jsluice &>/dev/null && jsluice_bin="jsluice"

  if [ ! -x "$jsluice_bin" ] && ! command -v jsluice &>/dev/null; then
    log_warn "jsluice not found — skipping JS endpoint/secret extraction"
    return
  fi

  if [ ! -d "$js_dir" ] || [ -z "$(ls -A "$js_dir" 2>/dev/null)" ]; then
    return
  fi

  local endpoints_file="$outdir/js_endpoints.txt"
  local secrets_file="$outdir/js_secrets.json"

  # Extract URLs/endpoints from all downloaded JS files
  find "$js_dir" -name "*.js" -type f | while read -r jsfile; do
    "$jsluice_bin" urls "$jsfile" 2>/dev/null
  done | sort -u > "$endpoints_file" 2>/dev/null || true

  # Extract secrets
  local secrets_tmp
  secrets_tmp=$(mktemp)
  find "$js_dir" -name "*.js" -type f | while read -r jsfile; do
    "$jsluice_bin" secrets "$jsfile" 2>/dev/null
  done > "$secrets_tmp" 2>/dev/null || true

  if [ -s "$secrets_tmp" ]; then
    cp "$secrets_tmp" "$secrets_file"
    # Write each secret to manual_findings.txt via tmpfile
    while IFS= read -r line; do
      [ -z "$line" ] && continue
      python3 -c "
import json, sys
try:
    r = json.loads('$line'.replace(\"'\", \"'\\\\''\"))
    kind = r.get('kind', 'secret')
    value = str(r.get('value', ''))[:80]
    url_context = r.get('filename', '')
    print(f'HIGH|js_secret_{kind}|{url_context}|Leaked {kind} in JS: {value}')
except: pass
" >> "$tmpfile" 2>/dev/null || true
    done < "$secrets_tmp"
  fi
  rm -f "$secrets_tmp"

  local ep_count=0 sec_count=0
  [ -s "$endpoints_file" ] && ep_count=$(wc -l < "$endpoints_file")
  [ -s "$secrets_file" ]   && sec_count=$(wc -l < "$secrets_file")
  log_success "JS: $ep_count endpoints, $sec_count potential secrets"
}

# ── Regex-based secret scanner (fallback if jsluice absent) ──────────────────
run_js_regex_scan() {
  local outdir="$1" tmpfile="$2"
  local js_dir="$outdir/js"

  [ ! -d "$js_dir" ] && return
  [ -z "$(ls -A "$js_dir" 2>/dev/null)" ] && return

  # Patterns: key=value pairs likely to be secrets
  local patterns=(
    'api[_-]?key\s*[=:]\s*["\047][A-Za-z0-9_\-]{16,}["\047]'
    'secret[_-]?key\s*[=:]\s*["\047][A-Za-z0-9_\-]{16,}["\047]'
    'access[_-]?token\s*[=:]\s*["\047][A-Za-z0-9_\-]{20,}["\047]'
    'authorization\s*[=:]\s*["\047]Bearer\s+[A-Za-z0-9_\.\-]{20,}["\047]'
    'AKIA[0-9A-Z]{16}'
    'ghp_[A-Za-z0-9]{36}'
    'sk-[A-Za-z0-9]{32,}'
    'eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+'
  )

  find "$js_dir" -name "*.js" -type f | while read -r jsfile; do
    for pat in "${patterns[@]}"; do
      grep -oiE "$pat" "$jsfile" 2>/dev/null | while read -r match; do
        echo "HIGH|js_secret_regex|${jsfile}|Pattern match: ${match:0:80}" >> "$tmpfile"
      done
    done
  done
}

# ── Main JS Analysis Runner ────────────────────────────────────────────────────
run_js_analysis() {
  local domain="$1" outdir="$2"

  if [ "${ENABLE_JS_ANALYSIS:-true}" != "true" ]; then
    log_info "JS analysis disabled (ENABLE_JS_ANALYSIS=false)"
    return
  fi

  log_info "JS analysis — collecting JavaScript files..."
  collect_js_urls "$domain" "$outdir"

  if [ ! -s "$outdir/js_urls.txt" ]; then
    log_warn "No JS files found — skipping JS analysis"
    return
  fi

  download_js_files "$outdir"

  local tmp_js
  tmp_js=$(mktemp)
  trap "rm -f '$tmp_js'" RETURN

  if command -v jsluice &>/dev/null || [ -x "$HOME/go/bin/jsluice" ]; then
    run_jsluice "$outdir" "$tmp_js"
  else
    log_warn "jsluice not installed — using regex fallback for JS secrets"
    run_js_regex_scan "$outdir" "$tmp_js"
  fi

  # Merge findings into manual_findings.txt
  cat "$tmp_js" >> "$outdir/manual_findings.txt" 2>/dev/null || true

  # If new endpoints found, add them to a re-scan list for nuclei
  if [ -s "$outdir/js_endpoints.txt" ]; then
    log_info "JS endpoints discovered — consider re-running nuclei with --scope subdomains"
  fi
}
