#!/usr/bin/env bash
# lib/cache.sh — persistent per-target cache with per-tool TTLs

# Cache lives at ~/.bughawk/cache/<domain>/
# Each cached file has a companion .<file>.ts with Unix timestamp of last update

BUGHAWK_CACHE_DIR="${HOME}/.bughawk/cache"

# ── Bash 4+ required for associative arrays ───────────────────────────────────
if [ "${BASH_VERSINFO[0]}" -lt 4 ]; then
  echo "[!] BugHawk cache requires bash 4+. Current: $BASH_VERSION" >&2
  echo "[!] macOS users: brew install bash && use /usr/local/bin/bash" >&2
fi

# ── TTLs in hours ─────────────────────────────────────────────────────────────
declare -A CACHE_TTL=(
  [subdomains.txt]=24
  [httpx.json]=12
  [whois.txt]=168          # 7 days — registrar info rarely changes
  [nmap.txt]=24
  [nmap.xml]=24
  [wayback.txt]=72
  [paramspider.txt]=24
  [params_xss.txt]=24
  [params_sqli.txt]=24
  [params_lfi.txt]=24
  [params_ssrf.txt]=24
  [params_redirect.txt]=24
)

# ── Init cache dir for this domain ────────────────────────────────────────────
init_cache() {
  local domain="$1"
  CACHE_DOMAIN_DIR="${BUGHAWK_CACHE_DIR}/${domain}"
  mkdir -p "$CACHE_DOMAIN_DIR"
}

# ── Get age of cached file in hours ───────────────────────────────────────────
_cache_age_hours() {
  local ts_file="$1"
  [ ! -f "$ts_file" ] && echo 99999 && return

  local saved_ts now_ts
  saved_ts=$(cat "$ts_file" 2>/dev/null || echo 0)
  now_ts=$(date +%s)
  echo $(( (now_ts - saved_ts) / 3600 ))
}

# ── Check if cached file is fresh (within TTL) ────────────────────────────────
is_cache_fresh() {
  local domain="$1"
  local filename="$2"
  local ttl="${CACHE_TTL[$filename]:-24}"

  local cached="${BUGHAWK_CACHE_DIR}/${domain}/${filename}"
  local ts_file="${BUGHAWK_CACHE_DIR}/${domain}/.${filename}.ts"

  # Must exist and be non-empty
  [ ! -s "$cached" ] && return 1

  local age
  age=$(_cache_age_hours "$ts_file")
  [ "$age" -lt "$ttl" ] && return 0 || return 1
}

# ── Load cached file into outdir (returns 0 on hit, 1 on miss) ───────────────
cache_load() {
  local domain="$1"
  local filename="$2"
  local outdir="$3"

  [ "${NO_CACHE:-false}" = "true" ] && return 1

  local cached="${BUGHAWK_CACHE_DIR}/${domain}/${filename}"
  local ts_file="${BUGHAWK_CACHE_DIR}/${domain}/.${filename}.ts"

  if is_cache_fresh "$domain" "$filename"; then
    cp "$cached" "$outdir/$filename"
    local age
    age=$(_cache_age_hours "$ts_file")
    local count=""
    # Add line count for text files
    if [[ "$filename" == *.txt ]]; then
      count=" ($(wc -l < "$outdir/$filename") lines)"
    fi
    log_success "[CACHE HIT] $filename — ${age}h old${count} — skipping tool run"
    return 0
  fi
  return 1
}

# ── Save file to cache after tool run ─────────────────────────────────────────
cache_save() {
  local domain="$1"
  local filename="$2"
  local outdir="$3"

  local src="$outdir/$filename"
  [ ! -s "$src" ] && return  # don't cache empty files

  local cached="${BUGHAWK_CACHE_DIR}/${domain}/${filename}"
  local ts_file="${BUGHAWK_CACHE_DIR}/${domain}/.${filename}.ts"

  cp "$src" "$cached"
  date +%s > "$ts_file"
}

# ── Special: merge wayback URLs into cache (accumulate, don't replace) ────────
cache_merge_wayback() {
  local domain="$1"
  local outdir="$2"

  local src="$outdir/wayback.txt"
  local cached="${BUGHAWK_CACHE_DIR}/${domain}/wayback.txt"
  local ts_file="${BUGHAWK_CACHE_DIR}/${domain}/.wayback.txt.ts"

  [ ! -s "$src" ] && return

  if [ -f "$cached" ]; then
    # Merge new URLs into cache — anew deduplicates
    cat "$src" | anew "$cached" > /dev/null 2>&1 || true
  else
    cp "$src" "$cached"
  fi
  date +%s > "$ts_file"
}

# ── Load wayback from cache + merge any new results ───────────────────────────
cache_load_wayback() {
  local domain="$1"
  local outdir="$2"

  [ "${NO_CACHE:-false}" = "true" ] && return 1

  local cached="${BUGHAWK_CACHE_DIR}/${domain}/wayback.txt"
  local ts_file="${BUGHAWK_CACHE_DIR}/${domain}/.wayback.txt.ts"

  [ ! -s "$cached" ] && return 1

  # Wayback cache: if fresh — use only cache. If stale — use cache as seed,
  # still run tool to get new URLs, then merge.
  local age
  age=$(_cache_age_hours "$ts_file")
  local ttl="${CACHE_TTL[wayback.txt]:-72}"

  if [ "$age" -lt "$ttl" ]; then
    cp "$cached" "$outdir/wayback.txt"
    log_success "[CACHE HIT] wayback.txt — ${age}h old ($(wc -l < "$outdir/wayback.txt") URLs) — skipping fetch"
    return 0
  else
    # Stale: seed outdir with cached data so new results get merged in
    cp "$cached" "$outdir/wayback.txt"
    log_info "[CACHE STALE] wayback.txt — ${age}h old — refreshing with new URLs"
    return 1  # still run the tool
  fi
}

# ── Show cache status for a domain ────────────────────────────────────────────
show_cache_status() {
  local domain="$1"
  local cache_dir="${BUGHAWK_CACHE_DIR}/${domain}"

  if [ ! -d "$cache_dir" ]; then
    log_info "No cache for $domain — first scan will populate it"
    return
  fi

  echo -e "\n${CYAN}${BOLD}  Cache: $domain${RESET}"
  printf "  %-25s %-12s %-10s\n" "File" "Age" "Status"
  printf "  %-25s %-12s %-10s\n" "─────────────────────────" "────────────" "──────────"

  for filename in "${!CACHE_TTL[@]}"; do
    local cached="${cache_dir}/${filename}"
    local ts_file="${cache_dir}/.${filename}.ts"
    [ ! -f "$cached" ] && continue

    local age
    age=$(_cache_age_hours "$ts_file")
    local ttl="${CACHE_TTL[$filename]}"
    local status

    if [ "$age" -lt "$ttl" ]; then
      status="${GREEN}fresh${RESET}"
    else
      status="${YELLOW}stale${RESET}"
    fi

    printf "  %-25s %-12s " "$filename" "${age}h / TTL ${ttl}h"
    echo -e "$status"
  done
  echo ""
}

# ── Clear cache for a domain ──────────────────────────────────────────────────
clear_cache() {
  local domain="$1"
  local cache_dir="${BUGHAWK_CACHE_DIR}/${domain}"
  if [ -d "$cache_dir" ]; then
    rm -rf "$cache_dir"
    log_success "Cache cleared for $domain"
  else
    log_warn "No cache found for $domain"
  fi
}
