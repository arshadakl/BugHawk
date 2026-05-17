#!/usr/bin/env bash
# lib/secrets.sh — trufflehog, gitleaks, sensitive path exposure checks

# ── Sensitive Paths List ───────────────────────────────────────────────────────
SENSITIVE_PATHS=(
  ".env" ".env.local" ".env.backup" ".env.production" ".env.dev" ".env.staging"
  "config.php" "wp-config.php" "configuration.php" "settings.py" "local_settings.py"
  "database.yml" "database.sql" "backup.sql" "dump.sql" "db.sql" "data.sql"
  ".git/config" ".git/HEAD" ".svn/entries" ".svn/wc.db"
  ".htpasswd" ".htaccess"
  "api_keys.txt" "credentials.txt" "passwords.txt" "secrets.txt" "tokens.txt"
  "web.config" "appsettings.json" "appsettings.Development.json"
  "application.properties" "application.yml" "bootstrap.yml"
  "id_rsa" "id_ed25519" "id_dsa" "private.key" "server.key" "server.pem"
  "composer.json" "composer.lock" "package.json" "yarn.lock" "Gemfile" "Gemfile.lock"
  "phpinfo.php" "info.php" "test.php" "debug.php" "phptest.php"
  "admin/" "admin/login" "admin/login.php" "administrator/" "wp-admin/"
  "phpmyadmin/" "pma/" "adminer.php" "adminer/" "dbadmin/"
  "swagger.json" "openapi.json" "openapi.yaml" "api/docs" "api/swagger" "api-docs"
  ".DS_Store" "Thumbs.db" "desktop.ini"
  "robots.txt" "sitemap.xml" "crossdomain.xml" "clientaccesspolicy.xml"
  "server-status" "server-info"
  "actuator" "actuator/env" "actuator/health" "actuator/mappings"
  "graphql" "graphiql" "playground"
  "console" "h2-console" "druid/index.html"
  "trace" "env" "health" "metrics" "dump"
)

# ── Trufflehog ────────────────────────────────────────────────────────────────
run_trufflehog() {
  local domain="$1" outdir="$2"
  local port="${TARGET_PORT:-443}"
  local base_url="https://${domain}"
  [ "$port" != "443" ] && base_url="https://${domain}:${port}"
  trufflehog http --url "$base_url" \
    --json 2>/dev/null > "$outdir/trufflehog.json" \
    || log_tool_error "trufflehog" "exited non-zero"
}

# ── Soft-404 Fingerprint ──────────────────────────────────────────────────────
# Returns md5 of homepage body — used to detect SPA catch-all 200s
_get_home_hash() {
  local base_url="$1"
  curl -s "$base_url" --max-time 10 -L 2>/dev/null | md5sum | cut -c1-16
}

# ── Content Validator ─────────────────────────────────────────────────────────
# Returns 0 (confirmed) or 1 (false positive) based on body content + path type
_validate_sensitive_content() {
  local path="$1" body="$2" content_type="$3"

  # If response is HTML and path is not an HTML-expected endpoint → false positive
  local is_html=false
  echo "$content_type" | grep -qi 'text/html' && is_html=true
  echo "$body" | head -5 | grep -qi '<!DOCTYPE\|<html' && is_html=true

  case "$path" in
    # Env files — must have KEY=VALUE lines, no HTML
    .env|.env.*|*.env)
      $is_html && return 1
      echo "$body" | grep -qE '^[A-Z_][A-Z0-9_]*=' && return 0
      return 1 ;;

    # Private keys — must have PEM header
    id_rsa|id_ed25519|id_dsa|*.key|*.pem|private.key|server.key|server.pem)
      echo "$body" | grep -q 'BEGIN.*PRIVATE KEY\|BEGIN RSA PRIVATE KEY\|BEGIN EC PRIVATE KEY\|BEGIN OPENSSH PRIVATE KEY' \
        && return 0
      return 1 ;;

    # SQL dumps — must have SQL keywords
    *.sql|database.sql|backup.sql|dump.sql|db.sql|data.sql)
      $is_html && return 1
      echo "$body" | grep -qiE 'CREATE TABLE|INSERT INTO|DROP TABLE|ALTER TABLE' && return 0
      return 1 ;;

    # Git files — must have git signatures
    .git/config)
      echo "$body" | grep -qE '\[core\]|\[remote|repositoryformatversion' && return 0
      return 1 ;;
    .git/HEAD)
      echo "$body" | grep -qE '^ref: refs/|^[0-9a-f]{40}' && return 0
      return 1 ;;

    # SVN files — must have svn signatures
    .svn/entries)
      echo "$body" | grep -qE '^[0-9]+$|svn' && return 0
      return 1 ;;
    .svn/wc.db)
      echo "$body" | grep -q 'SQLite' && return 0
      return 1 ;;

    # PHP config files — must contain PHP source or DB credentials
    wp-config.php|config.php|configuration.php|local_settings.py|settings.py)
      $is_html && return 1
      echo "$body" | grep -qiE 'DB_NAME|DB_PASSWORD|define\(|SECRET_KEY|DATABASE' && return 0
      return 1 ;;

    # Credential files — must have credential-like content, not HTML
    api_keys.txt|credentials.txt|passwords.txt|secrets.txt|tokens.txt|.htpasswd)
      $is_html && return 1
      echo "$body" | grep -qE '.{8,}' && return 0  # non-empty text file
      return 1 ;;

    # PHP info pages — must show PHP output
    phpinfo.php|info.php|test.php|debug.php|phptest.php)
      echo "$body" | grep -qi 'PHP Version\|phpinfo\|php_flag' && return 0
      return 1 ;;

    # App config files — must not be HTML
    web.config|appsettings*.json|application.properties|application.yml|bootstrap.yml|database.yml)
      $is_html && return 1
      echo "$body" | grep -qE '.{5,}' && return 0
      return 1 ;;

    # JSON/YAML API docs — must be valid structured content
    swagger.json|openapi.json|api-docs)
      echo "$body" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('openapi',d.get('swagger','')))" 2>/dev/null | grep -q '.' && return 0
      return 1 ;;
    openapi.yaml|openapi.yaml)
      $is_html && return 1
      echo "$body" | grep -qE '^openapi:|^swagger:' && return 0
      return 1 ;;

    # Admin panels — login page existence is valid (HTML expected)
    admin/*|administrator/*|wp-admin/*|phpmyadmin/*|pma/*|adminer*|dbadmin/*)
      return 0 ;;  # any 200 on admin path is a real finding

    # API/GraphQL endpoints — JSON or known UI is valid
    graphql|graphiql|playground|api/docs|api/swagger|api/*)
      echo "$body" | grep -qiE 'query|mutation|graphql|swagger|openapi|<!DOCTYPE' && return 0
      return 1 ;;

    # Spring actuator endpoints — must return JSON, not HTML
    actuator|actuator/*|trace|env|health|metrics|dump)
      $is_html && return 1
      echo "$body" | python3 -c "import json,sys; json.load(sys.stdin)" 2>/dev/null && return 0
      echo "$body" | grep -qE 'status|uptime|heap|thread|beans' && return 0
      return 1 ;;

    # Server status pages
    server-status|server-info)
      echo "$body" | grep -qiE 'Apache Server Status|Server Version|nginx' && return 0
      return 1 ;;

    # Source control config files
    .htaccess|.htpasswd)
      $is_html && return 1
      echo "$body" | grep -qE '^(Require|Allow|Deny|Options|RewriteRule|AuthType|\$apr1\$|\$2y\$)' && return 0
      return 1 ;;

    # Dependency manifests — must be JSON/YAML, not HTML
    composer.json|package.json|Gemfile|Gemfile.lock|composer.lock|yarn.lock)
      $is_html && return 1
      echo "$body" | grep -qE '"name"|"version"|gem |source ' && return 0
      return 1 ;;

    # Debug/metadata files
    .DS_Store)
      echo "$body" | grep -q 'Bud1\|Mac OS X' && return 0
      # .DS_Store is binary — check first bytes
      echo "$body" | head -c 8 | grep -q $'\x00' && return 0
      return 1 ;;

    *)
      # Default: reject HTML, accept text/plain or structured content
      $is_html && return 1
      echo "$body" | grep -qE '.{5,}' && return 0
      return 1 ;;
  esac
}

# ── Git Exposure Check + Gitleaks ─────────────────────────────────────────────
run_git_exposure() {
  local domain="$1" outdir="$2" tmpfile="$3"
  local port="${TARGET_PORT:-443}"
  local base_url="https://${domain}"
  [ "$port" != "443" ] && base_url="https://${domain}:${port}"

  local body http_status
  body=$(curl -s "${base_url}/.git/config" --max-time 10 2>/dev/null)
  http_status=$(curl -s -o /dev/null -w "%{http_code}" \
    "${base_url}/.git/config" --max-time 10)

  # Validate body — must contain git config structure, not a redirect/HTML page
  if [ "$http_status" = "200" ] && \
     echo "$body" | grep -qE '\[core\]|\[remote|repositoryformatversion'; then
    log_critical ".git directory publicly exposed on $domain"
    echo "CRITICAL|git_exposure|${base_url}/.git/config|.git config accessible — source code leak" \
      >> "$tmpfile"

    gitleaks detect --source "${base_url}" \
      --report-format json \
      --report-path "$outdir/gitleaks.json" 2>/dev/null \
      || log_tool_error "gitleaks" "exited non-zero"
  fi
}

# ── Sensitive Path Loop ───────────────────────────────────────────────────────
run_sensitive_paths() {
  local domain="$1" outdir="$2" tmpfile="$3"
  local port="${TARGET_PORT:-443}"
  local base_url="https://${domain}"
  [ "$port" != "443" ] && base_url="https://${domain}:${port}"
  local found=0

  # Fingerprint homepage to detect soft-404 (SPA catch-all returning 200)
  local home_hash
  home_hash=$(_get_home_hash "$base_url")

  for path in "${SENSITIVE_PATHS[@]}"; do
    [ "$path" = ".git/config" ] && continue

    # Fetch status + content-type + body + final URL (follow redirects)
    local tmp_body
    tmp_body=$(mktemp)
    local meta
    meta=$(curl -s -L \
      -w "%{http_code}\t%{content_type}\t%{url_effective}" \
      -o "$tmp_body" \
      "${base_url}/${path}" --max-time 10 2>/dev/null)

    local status content_type final_url body
    status=$(echo "$meta"       | cut -f1)
    content_type=$(echo "$meta" | cut -f2)
    final_url=$(echo "$meta"    | cut -f3)
    body=$(cat "$tmp_body" 2>/dev/null)
    rm -f "$tmp_body"

    # Skip non-200
    [[ "$status" =~ ^(200|206)$ ]] || continue

    # Skip if redirected away from the requested path (SPA routing catch-all)
    local expected_path_enc
    expected_path_enc=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$path" 2>/dev/null || echo "$path")
    if ! echo "$final_url" | grep -qF "$path" && ! echo "$final_url" | grep -qF "$expected_path_enc"; then
      continue
    fi

    # Skip if response is identical to homepage (soft-404)
    local resp_hash
    resp_hash=$(echo "$body" | md5sum | cut -c1-16)
    [ "$resp_hash" = "$home_hash" ] && continue

    # Validate content matches expected file type
    local severity="HIGH"
    case "$path" in
      id_rsa|id_ed25519|id_dsa|*.key|*.pem|private.key|server.key|server.pem) severity="CRITICAL" ;;
      .git/*|.svn/*) severity="CRITICAL" ;;
      *.sql|database.*) severity="CRITICAL" ;;
      .env|.env.*) severity="CRITICAL" ;;
    esac

    if _validate_sensitive_content "$path" "$body" "$content_type"; then
      echo "${severity}|sensitive_path|${base_url}/${path}|HTTP $status | Content-Type: ${content_type}" \
        >> "$tmpfile"
      log_warn "Confirmed: /${path} (HTTP $status, ${content_type})"
      found=$((found + 1))
    fi
  done

  [ "$found" -gt 0 ] && log_warn "$found confirmed sensitive path(s) found"
}

# ── Main Secrets Runner ───────────────────────────────────────────────────────
run_secrets() {
  local target="$1"
  local domain="$2"
  local outdir="$3"

  if [ "${ENABLE_SECRETS:-true}" != "true" ]; then
    log_info "Secrets detection disabled (ENABLE_SECRETS=false)"
    return
  fi

  # Ensure output file exists before parallel jobs try to append
  touch "$outdir/manual_findings.txt"

  # Each parallel job writes to its own temp file — merged atomically after wait
  local tmp_git tmp_paths
  tmp_git=$(mktemp)
  tmp_paths=$(mktemp)
  # Ensure cleanup on exit
  trap "rm -f '$tmp_git' '$tmp_paths'" RETURN

  PIDS=()
  local pid_descs=()

  log_info "trufflehog — scanning HTTP responses + JS files for leaked secrets..."
  run_trufflehog "$domain" "$outdir" &
  local _p=$!; PIDS+=($_p); pid_descs+=($_p "trufflehog: scanning JS/HTTP responses for API keys + secrets")

  log_info "Checking for exposed .git directory..."
  run_git_exposure "$domain" "$outdir" "$tmp_git" &
  local _p=$!; PIDS+=($_p); pid_descs+=($_p "git exposure check: probing /.git/config for source code leak")

  log_info "Probing ${#SENSITIVE_PATHS[@]} sensitive paths (env files, backups, admin panels)..."
  run_sensitive_paths "$domain" "$outdir" "$tmp_paths" &
  local _p=$!; PIDS+=($_p); pid_descs+=($_p "sensitive paths: checking .env, wp-config, database.sql, swagger...")

  show_multi_progress "SECRETS" "${pid_descs[@]}"

  local failed=0
  for pid in "${PIDS[@]}"; do
    if ! wait "$pid" 2>/dev/null; then
      log_warn "A secrets task failed (PID $pid) — check errors.log"
      failed=$((failed + 1))
    fi
  done

  # Atomic merge of temp files into manual_findings.txt
  cat "$tmp_git" "$tmp_paths" >> "$outdir/manual_findings.txt" 2>/dev/null || true

  [ "$failed" -gt 0 ] && log_warn "$failed secrets tool(s) had errors."

  local manual_count=0
  [ -s "$outdir/manual_findings.txt" ] \
    && manual_count=$(wc -l < "$outdir/manual_findings.txt")
  log_success "Secrets done: $manual_count manual findings"
}
