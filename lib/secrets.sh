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
  trufflehog http --url "https://${domain}" \
    --json 2>/dev/null > "$outdir/trufflehog.json" \
    || log_tool_error "trufflehog" "exited non-zero"
}

# ── Git Exposure Check + Gitleaks ─────────────────────────────────────────────
# Writes to its own temp file to avoid race with run_sensitive_paths
run_git_exposure() {
  local domain="$1" outdir="$2" tmpfile="$3"
  local http_status
  http_status=$(curl -s -o /dev/null -w "%{http_code}" \
    "https://${domain}/.git/config" --max-time 10)

  if [ "$http_status" = "200" ]; then
    log_critical ".git directory publicly exposed on $domain"
    echo "CRITICAL|git_exposure|https://${domain}/.git/config|.git directory publicly exposed" \
      >> "$tmpfile"

    gitleaks detect --source "https://${domain}" \
      --report-format json \
      --report-path "$outdir/gitleaks.json" 2>/dev/null \
      || log_tool_error "gitleaks" "exited non-zero"
  fi
}

# ── Sensitive Path Loop ───────────────────────────────────────────────────────
# Writes to its own temp file to avoid race with run_git_exposure
run_sensitive_paths() {
  local domain="$1" outdir="$2" tmpfile="$3"
  local found=0

  for path in "${SENSITIVE_PATHS[@]}"; do
    [ "$path" = ".git/config" ] && continue

    local status
    status=$(curl -s -o /dev/null -w "%{http_code}" \
      "https://${domain}/${path}" --max-time 10)

    if [[ "$status" =~ ^(200|206)$ ]]; then
      echo "HIGH|sensitive_path|https://${domain}/${path}|HTTP $status" \
        >> "$tmpfile"
      log_warn "Sensitive path exposed: /${path} (HTTP $status)"
      found=$((found + 1))
    fi
  done

  [ "$found" -gt 0 ] && log_warn "$found sensitive path(s) found"
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
