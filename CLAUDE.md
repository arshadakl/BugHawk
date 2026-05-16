# BugHawk — CLAUDE.md

> This file is the **single source of truth** for every Claude Code session on BugHawk.
> Read the ENTIRE file before touching any code. Do not skip sections.
> After completing any task, tick (x) the checkbox in the Task Checklist below.
> Before starting any phase marked "ask first", pause and confirm with the developer.

---

## What is BugHawk?

BugHawk is an **autonomous security scanning tool written entirely in Bash**.

The user gives it a target URL, domain, or IP. BugHawk:
1. Checks that all required tools are installed — installs any that are missing
2. Runs a full recon pipeline (subdomains, live hosts, ports, historical URLs, parameters)
3. Runs active vulnerability scanners in parallel (nuclei, sqlmap, dalfox, ffuf)
4. Runs secrets detection (trufflehog, gitleaks, manual path checks)
5. Aggregates every tool's raw output into a single normalized `findings.json`
6. Routes findings to an AI model via OpenRouter based on complexity
7. AI triages findings: filters false positives, scores severity, detects exploit chains
8. Generates a structured Markdown report + HackerOne-ready writeup per critical finding

The key idea: **tools do the work, AI does the thinking.**
AI never runs tools. It reads tool output and reasons like a senior pentester.

BugHawk works on Linux, macOS, and Windows (Git Bash / WSL2).
It uses free OpenRouter models for ~80% of tasks. Paid models are opt-in.

---

## Project Philosophy — Never Violate These

1. **Bash-first.** Orchestration is pure bash. Python is used only for JSON aggregation
   (embedded heredoc inside bash). Node.js is NOT used anywhere.
2. **Zero manual setup.** `./bughawk.sh <target>` must work on a fresh machine.
   The script installs everything it needs.
3. **AI as analyst, not operator.** Tools scan. AI reads output and thinks.
   Never pass raw tool stdout directly to AI — always normalize to JSON first.
4. **Free tier by default.** OpenRouter free models handle ~80% of tasks.
   Tier 3 / Tier 4 (paid) only activate for complex chains or H1 reports.
5. **Parallel everything.** Scans run concurrently via background jobs + `PIDS[]`.
   Never run scanners sequentially when they can be parallelized.
6. **Structured output everywhere.** Every tool output → normalized finding object.
   The finding schema is fixed — do not deviate from it.
7. **Never abort on single tool failure.** Log the error, continue with other tools.
8. **No API keys in logs or output files. Ever.**

---

## Repository Structure

```
bughawk/
├── bughawk.sh                  ← main entry point (orchestrator only)
├── CLAUDE.md                   ← this file — read before everything
├── PLAN.md                     ← architecture decisions, rationale
├── TASKS.md                    ← atomic task list for Claude Code sessions
├── config.sh                   ← real config (git-ignored, never commit)
├── config.example.sh           ← template with placeholder values (committed)
├── .gitignore
├── lib/
│   ├── utils.sh                ← colors, log helpers, spinner, print_table, timeout
│   ├── setup.sh                ← OS detect, pkg manager, tool check + auto-install
│   ├── recon.sh                ← subfinder, httpx, whois, nmap, waybackurls, gf, paramspider
│   ├── scan.sh                 ← nuclei, sqlmap, dalfox, ffuf (parallel)
│   ├── secrets.sh              ← trufflehog, gitleaks, sensitive path check loop
│   ├── aggregator.sh           ← merge all tool outputs → findings.json (Python heredoc)
│   ├── ai.sh                   ← OpenRouter API calls, tier routing, exploit chain detection
│   └── report.sh               ← report.md + h1_*.md generator (Python heredoc)
├── wordlists/
│   ├── dirs.txt                ← directory fuzzing (min 500 entries)
│   ├── params.txt              ← parameter fuzzing (min 200 entries)
│   └── subdomains.txt          ← subdomain brute-force (min 1000 entries)
├── payloads/
│   ├── xss.txt                 ← XSS payloads (min 50, context-aware)
│   ├── sqli.txt                ← SQLi test strings (min 30)
│   └── lfi.txt                 ← LFI traversal strings (min 20)
├── nuclei-templates/           ← custom nuclei templates (optional, git-ignored)
├── output/                     ← auto-created, git-ignored
│   └── <target>_YYYYMMDD_HHMM/
│       ├── subdomains.txt          ← subfinder raw output
│       ├── httpx.json              ← live hosts, status codes, tech stack
│       ├── whois.txt               ← registrar, ASN, org info
│       ├── nmap.txt                ← human-readable nmap output
│       ├── nmap.xml                ← machine-parseable nmap output
│       ├── wayback.txt             ← deduplicated historical URLs
│       ├── params_xss.txt          ← gf xss pattern matches
│       ├── params_sqli.txt         ← gf sqli pattern matches
│       ├── params_lfi.txt          ← gf lfi pattern matches
│       ├── params_ssrf.txt         ← gf ssrf pattern matches
│       ├── params_redirect.txt     ← gf redirect pattern matches
│       ├── paramspider.txt         ← paramspider discovered params
│       ├── nuclei.json             ← nuclei findings (one JSON per line / NDJSON)
│       ├── dalfox.json             ← dalfox XSS findings
│       ├── sqlmap/                 ← sqlmap output directory
│       ├── ffuf.json               ← directory/endpoint fuzzing results
│       ├── trufflehog.json         ← trufflehog secrets findings
│       ├── gitleaks.json           ← gitleaks findings (if .git exposed)
│       ├── manual_findings.txt     ← sensitive path exposure findings
│       ├── findings.json           ← aggregated, normalized, all tools merged
│       ├── ai_triage.json          ← AI triage output (is_real, confidence, chains)
│       ├── ai_triage_raw.txt       ← fallback if AI response is not valid JSON
│       ├── report.md               ← final human-readable report
│       ├── h1_<type>.md            ← HackerOne-ready writeup per critical/high
│       └── errors.log              ← tool failures and skipped steps
└── tests/
    ├── test_setup.sh               ← mock tool check (no real installs)
    ├── test_aggregator.sh          ← parse mock outputs, validate findings.json
    ├── test_ai.sh                  ← mock OpenRouter with static response
    ├── test_report.sh              ← generate report from mock findings.json
    └── mock_outputs/               ← static sample outputs for all tools
        ├── nuclei.json
        ├── httpx.json
        ├── dalfox.json
        ├── ffuf.json
        └── trufflehog.json
```

---

## CLI Interface — All Flags

```bash
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
                            e.g. --skip-scan sqlmap,dalfox
  --skip-install-check      Skip tool installation check (faster on repeat runs)
  --allow-internal          Allow scanning private IP ranges (default: blocked)

AI control:
  --ai-tier <1|2|3|4>       Force a specific AI tier (overrides auto-routing)
  --no-ai                   Skip AI triage entirely, just produce raw findings

Output:
  --output <dir>            Custom output directory (default: ./output)
  --quiet                   Suppress tool stdout, show only BugHawk status lines
  --no-report               Skip report generation (just save findings.json)

Help:
  --help                    Show this help text with examples
```

---

## OS / Platform Support

| Platform        | Support Level | Package Manager Used                     |
|-----------------|---------------|------------------------------------------|
| Ubuntu / Debian | Full          | apt-get, go install, pip3                |
| Kali Linux      | Full          | apt-get (many tools pre-installed)       |
| Arch Linux      | Full          | pacman, go install                       |
| macOS           | Full          | brew, go install                         |
| Windows WSL2    | Full          | apt-get inside WSL (treated as Linux)    |
| Windows Git Bash| Partial       | winget / choco; go install works         |
| Windows Cygwin  | Minimal       | not recommended — flag unsupported tools |

Detection in `lib/setup.sh`:

```bash
detect_os() {
  if grep -qi microsoft /proc/version 2>/dev/null; then
    OS="wsl"
    return
  fi
  case "$(uname -s)" in
    Linux*)               OS="linux" ;;
    Darwin*)              OS="mac" ;;
    CYGWIN*|MINGW*|MSYS*) OS="windows_bash" ;;
    *)                    OS="unknown" ;;
  esac
}

detect_pkg_manager() {
  if   command -v apt-get &>/dev/null; then PKG="apt"
  elif command -v brew    &>/dev/null; then PKG="brew"
  elif command -v pacman  &>/dev/null; then PKG="pacman"
  elif command -v winget  &>/dev/null; then PKG="winget"
  elif command -v choco   &>/dev/null; then PKG="choco"
  else                                      PKG="none"
  fi
}
```

On Windows Git Bash without WSL2:
- Install Go tools via `go install` (works in Git Bash)
- Install nmap via `winget install nmap` or `choco install nmap`
- Print a warning listing tools that could NOT be auto-installed
- Continue with available tools — never abort

---

## All Tools — Complete Reference

| Tool        | Binary      | Category      | Install Method                                                                    | Version Flag         |
|-------------|-------------|---------------|-----------------------------------------------------------------------------------|----------------------|
| Go          | go          | runtime       | golang.org binary / brew install go / apt install golang                          | `go version`         |
| Python 3    | python3     | runtime       | apt / brew / winget                                                               | `python3 --version`  |
| jq          | jq          | utility       | apt / brew / winget                                                               | `jq --version`       |
| curl        | curl        | utility       | pre-installed on most; apt / brew fallback                                        | `curl --version`     |
| subfinder   | subfinder   | recon         | `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest`     | `subfinder -version` |
| httpx       | httpx       | recon         | `go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest`                | `httpx -version`     |
| nuclei      | nuclei      | vuln scan     | `go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`           | `nuclei -version`    |
| nmap        | nmap        | recon/port    | apt / brew / winget                                                               | `nmap --version`     |
| sqlmap      | sqlmap      | vuln scan     | `pip3 install sqlmap --break-system-packages`                                     | `sqlmap --version`   |
| dalfox      | dalfox      | XSS           | `go install github.com/hahwul/dalfox/v2@latest`                                  | `dalfox version`     |
| ffuf        | ffuf        | fuzzing       | `go install github.com/ffuf/ffuf/v2@latest`                                       | `ffuf -V`            |
| gf          | gf          | param extract | `go install github.com/tomnomnom/gf@latest`                                       | `gf --help`          |
| waybackurls | waybackurls | recon         | `go install github.com/tomnomnom/waybackurls@latest`                              | (check binary exists)|
| anew        | anew        | utility       | `go install github.com/tomnomnom/anew@latest`                                     | (check binary exists)|
| paramspider | paramspider | param extract | `pip3 install paramspider --break-system-packages`                                | `paramspider --help` |
| trufflehog  | trufflehog  | secrets       | curl install script / brew / GitHub releases binary                               | `trufflehog --version`|
| gitleaks    | gitleaks    | secrets       | GitHub releases binary download / brew                                            | `gitleaks version`   |
| whois       | whois       | recon         | apt / brew / winget                                                               | `whois --version`    |

**Critical PATH note:** Go tools install to `$HOME/go/bin`.
During setup, check if it's on PATH. If not, add it:
```bash
export PATH="$PATH:$HOME/go/bin"
echo 'export PATH="$PATH:$HOME/go/bin"' >> ~/.bashrc   # or ~/.zshrc on macOS
```

**gf pattern files** — required separately AFTER `go install tomnomnom/gf`:
```bash
git clone https://github.com/1ndianl33t/Gf-Patterns ~/.gf
```
Without this, all `gf` pattern calls will silently produce no output.

**nuclei templates** — update during setup to avoid template download mid-scan:
```bash
nuclei -update-templates -silent
```

---

## Exact Tool Commands Used in the Pipeline

These are the exact flags. Do not change them without updating this file.

### Recon commands

```bash
# Subfinder — passive subdomain enumeration
subfinder -d "$TARGET_DOMAIN" -silent -o "$OUTDIR/subdomains.txt"

# httpx — live host probing with tech detection
httpx -l "$OUTDIR/subdomains.txt" \
      -status-code -title -tech-detect \
      -json -o "$OUTDIR/httpx.json" -silent

# Whois — registrar and ASN info
whois "$TARGET_DOMAIN" > "$OUTDIR/whois.txt" 2>/dev/null

# Nmap — service version + http scripts, both output formats
nmap -sV --script=http-headers,http-title \
     "$TARGET" \
     -oX "$OUTDIR/nmap.xml" \
     -oN "$OUTDIR/nmap.txt"

# Waybackurls — historical URL fetch, capped and deduplicated
waybackurls "$TARGET_DOMAIN" | head -"$WAYBACK_URL_LIMIT" | anew "$OUTDIR/wayback.txt"

# gf — 5 pattern extractions from wayback URLs
cat "$OUTDIR/wayback.txt" | gf xss      > "$OUTDIR/params_xss.txt"
cat "$OUTDIR/wayback.txt" | gf sqli     > "$OUTDIR/params_sqli.txt"
cat "$OUTDIR/wayback.txt" | gf lfi      > "$OUTDIR/params_lfi.txt"
cat "$OUTDIR/wayback.txt" | gf ssrf     > "$OUTDIR/params_ssrf.txt"
cat "$OUTDIR/wayback.txt" | gf redirect > "$OUTDIR/params_redirect.txt"

# Paramspider — crawl-based parameter discovery
paramspider -d "$TARGET_DOMAIN" --output "$OUTDIR/paramspider.txt" --quiet
```

### Scan commands

```bash
# Nuclei — template-based vulnerability scan
safe_timeout "$TIMEOUT_NUCLEI" nuclei \
       -target "$TARGET" \
       -severity "$NUCLEI_SEVERITY" \
       -json-export "$OUTDIR/nuclei.json" \
       -silent

# Dalfox — XSS detection (only if params_xss.txt is non-empty)
[ -s "$OUTDIR/params_xss.txt" ] && \
dalfox file "$OUTDIR/params_xss.txt" \
       --output "$OUTDIR/dalfox.json" \
       --format json \
       --silence

# SQLMap — SQL injection (only if params_sqli.txt is non-empty)
[ -s "$OUTDIR/params_sqli.txt" ] && \
safe_timeout "$TIMEOUT_SQLMAP" sqlmap \
       -m "$OUTDIR/params_sqli.txt" \
       --batch \
       --level="$SQLMAP_LEVEL" \
       --risk="$SQLMAP_RISK" \
       --output-dir="$OUTDIR/sqlmap"

# ffuf — directory and endpoint fuzzing
safe_timeout "$TIMEOUT_FFUF" ffuf \
       -u "https://$TARGET_DOMAIN/FUZZ" \
       -w "$BUGHAWK_DIR/wordlists/dirs.txt" \
       -mc "$FFUF_MATCH_CODES" \
       -t "$FFUF_THREADS" \
       -json -o "$OUTDIR/ffuf.json" \
       -s
```

### Secrets commands

```bash
# Trufflehog — scan live target HTTP responses and JS files for secrets
trufflehog http --url "https://$TARGET_DOMAIN" \
           --json 2>/dev/null > "$OUTDIR/trufflehog.json"

# .git exposure check
http_status=$(curl -s -o /dev/null -w "%{http_code}" \
              "https://$TARGET_DOMAIN/.git/config" --max-time 10)
if [ "$http_status" = "200" ]; then
    echo "CRITICAL|git_exposure|https://$TARGET_DOMAIN/.git/config|.git directory publicly exposed" \
      >> "$OUTDIR/manual_findings.txt"
    gitleaks detect --source "https://$TARGET_DOMAIN" \
             --report-format json \
             --report-path "$OUTDIR/gitleaks.json" 2>/dev/null
fi

# Sensitive path check loop
for path in "${SENSITIVE_PATHS[@]}"; do
    status=$(curl -s -o /dev/null -w "%{http_code}" \
             "https://$TARGET_DOMAIN/$path" --max-time 10)
    if [[ "$status" =~ ^(200|206)$ ]]; then
        echo "HIGH|sensitive_path|https://$TARGET_DOMAIN/$path|HTTP $status" \
          >> "$OUTDIR/manual_findings.txt"
    fi
done
```

---

## AI Tier Routing Logic

The router in `lib/ai.sh` decides which model to use based on the findings.

```bash
route_to_tier() {
  local findings_file=$1
  local finding_count
  finding_count=$(jq length "$findings_file")

  local has_chain
  has_chain=$(detect_exploit_chain "$findings_file")

  local has_critical
  has_critical=$(jq '[.[] | select(.severity == "critical")] | length' "$findings_file")

  if [ "$has_chain" = "true" ] || [ "$has_critical" -gt 0 ]; then
    echo "3"
  elif [ "$finding_count" -gt "$TIER3_FINDING_THRESHOLD" ]; then
    echo "3"
  elif [ "$finding_count" -gt "$TIER2_FINDING_THRESHOLD" ]; then
    echo "2"
  else
    echo "1"
  fi
}

detect_exploit_chain() {
  local findings_file=$1
  local types
  types=$(jq -r '[.[] | .type] | join(",")' "$findings_file")

  # Common chainable combinations
  if echo "$types" | grep -q "ssrf" && echo "$types" | grep -q "internal"; then
    echo "true"; return
  fi
  if echo "$types" | grep -q "xss" && echo "$types" | grep -q "csrf"; then
    echo "true"; return
  fi
  if echo "$types" | grep -q "sqli" && echo "$types" | grep -q "auth"; then
    echo "true"; return
  fi
  if echo "$types" | grep -q "lfi" && echo "$types" | grep -q "rce"; then
    echo "true"; return
  fi
  echo "false"
}
```

### AI Model Tier Reference

| Tier | Model                                    | Cost   | When Used                                      |
|------|------------------------------------------|--------|------------------------------------------------|
| 1    | `google/gemma-3-27b-it:free`             | Free   | <10 findings, no critical, no chain            |
| 2    | `meta-llama/llama-3.3-70b-instruct:free` | Free   | 10–30 findings, moderate complexity            |
| 3    | `deepseek/deepseek-r1-0528:free`         | Free*  | >30 findings, critical severity, exploit chain |
| 4    | `anthropic/claude-sonnet-4-5`            | Paid   | H1 report writing only (opt-in)                |

*DeepSeek R1 is currently free on OpenRouter. If it returns HTTP 402, fall back to Tier 2.
`FORCE_TIER` in config overrides all routing logic.

---

## Finding Object Schema — Exact, Do Not Deviate

Every tool output MUST be normalized to this schema before aggregation or AI call.
Tools fill the first group of fields. AI fills the second group.

```json
{
  "id": 0,
  "tool": "nuclei",
  "severity": "high",
  "type": "CVE-2024-XXXXX",
  "url": "https://target.com/vulnerable/path",
  "parameter": "id",
  "evidence": "response contained: root:x:0:0",
  "description": "SQL injection via id parameter allows data extraction",
  "raw": "...full tool output line...",
  "is_real": null,
  "ai_confidence": null,
  "ai_reason": null,
  "chain_id": null,
  "cvss_score": null,
  "cvss_vector": null
}
```

`manual_findings.txt` pipe-delimited format (parsed by aggregator):
```
SEVERITY|type|url|evidence
CRITICAL|git_exposure|https://target.com/.git/config|.git directory publicly exposed
HIGH|sensitive_path|https://target.com/.env|HTTP 200
```

---

## AI Prompts — Exact Text, Use Verbatim

### Triage prompt (Tier 1 / 2 / 3)

```
You are a senior bug bounty analyst and penetration tester.

Analyze the following automated tool findings from a security scan of {{TARGET}}.

Your job:
1. Determine which findings are real vulnerabilities vs false positives
2. Assign a confidence score (0.0 to 1.0) for each real finding
3. Identify if any findings can be chained into a higher-severity exploit —
   assign those the same chain_id (integer starting at 1, null if not chained)
4. Write a one-sentence reason for each decision
5. For each real finding, assign a CVSS 3.1 score and vector string

Output ONLY a valid JSON array. No preamble. No explanation. No markdown fences.

Schema per item:
{
  "id": <int>,
  "is_real": <bool>,
  "ai_confidence": <0.0-1.0>,
  "ai_reason": "<one sentence>",
  "chain_id": <int|null>,
  "cvss_score": "<X.X>",
  "cvss_vector": "<CVSS:3.1/AV:...>"
}

FINDINGS:
{{FINDINGS_JSON}}
```

### Chain analysis prompt (Tier 3 / 4)

```
You are a senior penetration tester writing up an exploit chain for a bug bounty report.

The following findings have been identified as chainable (same chain_id).
Describe a realistic multi-step attack scenario that combines these vulnerabilities.
Be specific — include exact URLs, parameters, and payloads where possible.

Output ONLY valid JSON. No preamble. No markdown fences.

{
  "chain_title": "<short descriptive title>",
  "chain_severity": "<critical|high>",
  "attack_steps": [
    "<step 1 — specific action>",
    "<step 2 — specific action>"
  ],
  "combined_impact": "<paragraph — what an attacker achieves and business impact>",
  "cvss_score": "<X.X>",
  "cvss_vector": "<CVSS:3.1/AV:N/...>"
}

CHAINABLE FINDINGS:
{{CHAIN_FINDINGS_JSON}}
```

### HackerOne report prompt (Tier 4 — Claude Sonnet only)

```
You are a professional bug bounty researcher writing a HackerOne vulnerability report.

Write a complete, professional report for the finding below.
Follow HackerOne's standard report format exactly.
Use clear, technical but readable English.
Be specific — include exact URLs, parameters, payloads, and response snippets from evidence.

Output plain Markdown only. No JSON. No preamble.

Required sections (use these exact headings):
## Summary
## Steps to Reproduce
## Expected Behavior
## Actual Behavior
## Impact
## Proof of Concept
## Recommended Fix
## Severity
## CVSS Score

FINDING:
{{FINDING_JSON}}

CHAIN CONTEXT (if applicable):
{{CHAIN_JSON}}
```

---

## OpenRouter API Call Pattern

```bash
call_openrouter() {
  local model="$1"
  local prompt="$2"
  local attempt=0

  while [ $attempt -lt "$OPENROUTER_RETRY_LIMIT" ]; do
    response=$(curl -s -w "\n%{http_code}" \
      "https://openrouter.ai/api/v1/chat/completions" \
      -H "Authorization: Bearer $OPENROUTER_API_KEY" \
      -H "Content-Type: application/json" \
      -H "HTTP-Referer: https://github.com/arshadakl/BugHawk" \
      -H "X-Title: BugHawk" \
      -d "$(jq -n \
        --arg model "$model" \
        --arg content "$prompt" \
        '{model: $model, messages: [{role: "user", content: $content}]}'
      )")

    http_code=$(echo "$response" | tail -1)
    body=$(echo "$response" | head -n -1)

    if [ "$http_code" = "200" ]; then
      echo "$body" | jq -r '.choices[0].message.content'
      return 0
    elif [ "$http_code" = "429" ]; then
      log_warn "OpenRouter rate limit hit. Waiting ${OPENROUTER_RETRY_DELAY}s..."
      sleep "$OPENROUTER_RETRY_DELAY"
      attempt=$((attempt + 1))
    elif [ "$http_code" = "402" ]; then
      log_warn "Model requires payment. Falling back to Tier 2..."
      model="$TIER2_MODEL"
      attempt=$((attempt + 1))
    else
      log_error "OpenRouter error: HTTP $http_code"
      echo "$body" >> "$OUTDIR/errors.log"
      return 1
    fi
  done

  log_error "OpenRouter failed after $OPENROUTER_RETRY_LIMIT retries"
  return 1
}
```

---

## Parallel Execution Pattern — Use This Everywhere

All tools in `lib/scan.sh` and `lib/recon.sh` must follow this exact pattern.
No untracked background jobs. Every `&` PID goes in `PIDS[]`.

```bash
PIDS=()

run_tool_a "$TARGET" "$OUTDIR" &
PIDS+=($!)

run_tool_b "$TARGET" "$OUTDIR" &
PIDS+=($!)

run_tool_c "$TARGET" "$OUTDIR" &
PIDS+=($!)

# Show spinner while waiting
show_spinner "${PIDS[-1]}"

# Wait for all, log failures
FAILED=0
for pid in "${PIDS[@]}"; do
  if ! wait "$pid"; then
    log_warn "A background task failed (PID $pid) — check errors.log"
    FAILED=$((FAILED + 1))
  fi
done

[ $FAILED -gt 0 ] && log_warn "$FAILED tool(s) had errors. Results may be incomplete."
```

---

## Timeout Wrapper — `safe_timeout()`

Linux/WSL: `timeout` (GNU coreutils).
macOS: `gtimeout` from `brew install coreutils`.
`lib/utils.sh` must implement:

```bash
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
```

Always wrap: `safe_timeout "$TIMEOUT_SQLMAP" sqlmap ...`
Always wrap: `safe_timeout "$TIMEOUT_NUCLEI" nuclei ...`
Always wrap: `safe_timeout "$TIMEOUT_NMAP" nmap ...`

---

## Sensitive Path Check List

Full list used in `lib/secrets.sh`. `.git/config` → CRITICAL. All others → HIGH.

```bash
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
```

---

## `config.sh` — All Variables

```bash
#!/usr/bin/env bash
# BugHawk configuration — copy to config.sh and fill in values
# NEVER commit config.sh (it is git-ignored)

# ── API Keys ──────────────────────────────────────────────────────────────────
OPENROUTER_API_KEY=""         # Required. Get at openrouter.ai

# ── AI Model Tiers ────────────────────────────────────────────────────────────
TIER1_MODEL="google/gemma-3-27b-it:free"
TIER2_MODEL="meta-llama/llama-3.3-70b-instruct:free"
TIER3_MODEL="deepseek/deepseek-r1-0528:free"
TIER4_MODEL="anthropic/claude-sonnet-4-5"

# ── Tier Routing Thresholds ───────────────────────────────────────────────────
TIER2_FINDING_THRESHOLD=10    # use Tier 2 if finding count > this
TIER3_FINDING_THRESHOLD=30    # use Tier 3 if finding count > this
FORCE_TIER=""                 # "1","2","3","4" — overrides auto-routing

# ── Scan Settings ─────────────────────────────────────────────────────────────
NUCLEI_SEVERITY="medium,high,critical"
SQLMAP_LEVEL=2
SQLMAP_RISK=2
FFUF_MATCH_CODES="200,301,302,403,405"
FFUF_THREADS=50
NMAP_FLAGS="-sV --script=http-headers,http-title"
SUBFINDER_TIMEOUT=60
WAYBACK_URL_LIMIT=5000        # cap waybackurls output

# ── Timeouts (seconds) ────────────────────────────────────────────────────────
TIMEOUT_NUCLEI=600
TIMEOUT_SQLMAP=600
TIMEOUT_NMAP=300
TIMEOUT_FFUF=180
TIMEOUT_RECON=120

# ── Feature Flags ─────────────────────────────────────────────────────────────
ENABLE_SQLMAP=true
ENABLE_DALFOX=true
ENABLE_FFUF=true
ENABLE_SECRETS=true
ENABLE_WAYBACK=true
ENABLE_PARAMSPIDER=true
ENABLE_AI_TRIAGE=true
ENABLE_H1_REPORT=true
SKIP_INSTALL_CHECK=false

# ── Output ────────────────────────────────────────────────────────────────────
OUTPUT_DIR="./output"
OPEN_REPORT_AFTER=true        # auto-open report.md when done
QUIET_MODE=false              # suppress tool stdout

# ── Rate Limiting ─────────────────────────────────────────────────────────────
OPENROUTER_RETRY_LIMIT=3
OPENROUTER_RETRY_DELAY=5      # seconds between retries on 429
```

---

## `lib/utils.sh` — Required Helpers

Every other lib file sources utils.sh first. All of these must be implemented.

```bash
# Colors
RED='\033[0;31m';  GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m';  BOLD='\033[1m'; RESET='\033[0m'

# Logging functions
log_info()    { echo -e "${BLUE}[*]${RESET} $1"; }
log_success() { echo -e "${GREEN}[+]${RESET} $1"; }
log_warn()    { echo -e "${YELLOW}[!]${RESET} $1"; }
log_error()   { echo -e "${RED}[✗]${RESET} $1"; }
log_critical(){ echo -e "${RED}${BOLD}[CRITICAL]${RESET} $1"; }
log_step()    { echo -e "\n${CYAN}${BOLD}[$1/$TOTAL_STEPS] $2${RESET}"; }
# Usage: TOTAL_STEPS=7 in bughawk.sh; then log_step 1 "Recon"

# Spinner — shows while background jobs run
show_spinner() {
  local pid=$1
  local spin='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
  local i=0
  while kill -0 "$pid" 2>/dev/null; do
    printf "\r  ${CYAN}${spin:$i:1}${RESET}  Working..."
    i=$(( (i+1) % 10 ))
    sleep 0.1
  done
  printf "\r                    \r"
}

# Tool status table (printf for alignment)
print_tool_table_header() {
  printf "\n  %-16s %-8s %-20s\n" "Tool" "Status" "Version"
  printf "  %-16s %-8s %-20s\n" "────────────────" "────────" "────────────────────"
}
print_tool_row() {
  # $1=name $2="✓" or "✗" $3=version
  printf "  %-16s %-8s %-20s\n" "$1" "$2" "$3"
}

# Banner — exact text, print on every run
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

# safe_timeout — cross-platform timeout wrapper (see Timeout section above)
```

---

## Error Handling Rules

1. `set -euo pipefail` in `bughawk.sh` ONLY. Not in lib files (subshell issues).
2. Any tool failure: log to `$OUTDIR/errors.log` with timestamp, continue.
3. Missing `OPENROUTER_API_KEY`: skip AI, warn user, still produce raw findings report.
4. Tool install failed: log it, mark tool as skipped, continue with remaining tools.
5. `safe_timeout` expiry: log as timeout, treat as tool failure, continue.
6. API key must never appear in `errors.log` or any output file.
7. Empty `findings.json`: write a report saying "no findings" — do not error out.
8. Invalid JSON from AI: save raw to `ai_triage_raw.txt`, skip merge step, continue to report.

---

## Security & Ethics — Non-Negotiable, Enforced in Code

1. **Legal disclaimer on first run.** Print it, require user to type `I AGREE`.
   Store acknowledgment in `~/.bughawk_accepted`. Skip prompt on subsequent runs.
2. **No scanning without explicit target.** Target must be passed as CLI argument.
3. **Private IP range block.** Refuse to scan `10.x.x.x`, `172.16–31.x.x`, `192.168.x.x`
   unless `--allow-internal` is passed.
4. **sqlmap always `--batch`.** Never interactive.
5. **Rate limit HTTP requests.** All curl calls use `--max-time 10`.
   ffuf uses `-t $FFUF_THREADS` (default 50, not unlimited).
6. **No API key in any output.** Strip or never write `OPENROUTER_API_KEY` to files.

---

## Known Gotchas — Read Before Coding

- **`httpx` name conflict.** Python installs an `httpx` package that can shadow the Go binary.
  Use `$HOME/go/bin/httpx` explicitly in commands, or check `which httpx` in setup.

- **`gf` needs pattern files separately.** `go install tomnomnom/gf` installs the binary only.
  Must also clone `https://github.com/1ndianl33t/Gf-Patterns` to `~/.gf`.
  Without this, `gf xss`, `gf sqli` etc. produce no output silently.

- **`sqlmap` pip install.** May install as `sqlmap` or need `python3 -m sqlmap`.
  Check both during setup. Prefer `python3 -m sqlmap` for reliability.

- **`trufflehog` on Windows Git Bash.** The curl install script may fail.
  Fallback: download the binary directly from GitHub releases page.

- **`timeout` on macOS.** Not available by default. Use `gtimeout` from
  `brew install coreutils`. The `safe_timeout()` helper handles this.

- **`waybackurls` flood.** On large targets returns 50k+ URLs.
  Always pipe through `head -$WAYBACK_URL_LIMIT` before `anew`.

- **nuclei templates download.** First `nuclei` run downloads ~300MB of templates.
  Run `nuclei -update-templates` during setup so this doesn't happen mid-scan.

- **OpenRouter HTTP 429.** Free models are rate-limited per minute.
  Retry with `OPENROUTER_RETRY_DELAY` seconds wait, up to `OPENROUTER_RETRY_LIMIT` times.

- **DeepSeek R1 free.** Currently free on OpenRouter — can change. If HTTP 402 returned,
  fall back to `TIER2_MODEL` automatically.

- **`jq` not everywhere.** Required by `ai.sh`. Always check and install during setup.

- **WSL2 PATH collision.** Windows Go install may be found before Linux Go.
  Verify `go env GOPATH` returns a Linux path (e.g. `/home/user/go`), not a Windows path.

- **`paramspider` output.** Writes one URL per line to the output file.
  Always check `[ -s file ]` before passing to dalfox or sqlmap.

- **nmap `.xml` output is required.** The aggregator parses `nmap.xml` for structured data.
  Both `-oX` and `-oN` flags must be present in the nmap command.

---

## Example Runs

```bash
# First ever run — installs missing tools, then full scan
./bughawk.sh https://example.com

# Fast scan — recon + nuclei only, skip slow tools
./bughawk.sh https://example.com --depth quick

# Scope includes all subdomains
./bughawk.sh https://example.com --scope subdomains

# Skip sqlmap (slow), force Tier 3 AI
./bughawk.sh https://example.com --skip-scan sqlmap --ai-tier 3

# Quiet mode, tools already installed from previous run
./bughawk.sh https://example.com --quiet --skip-install-check

# Internal network target
./bughawk.sh http://192.168.1.1 --allow-internal

# No AI analysis — just raw tool findings
./bughawk.sh https://example.com --no-ai
```

Expected output directory after a full run:
```
output/example_com_20250516_1430/
├── subdomains.txt
├── httpx.json
├── whois.txt
├── nmap.txt
├── nmap.xml
├── wayback.txt
├── params_xss.txt
├── params_sqli.txt
├── params_lfi.txt
├── params_ssrf.txt
├── params_redirect.txt
├── paramspider.txt
├── nuclei.json
├── dalfox.json
├── sqlmap/
├── ffuf.json
├── trufflehog.json
├── manual_findings.txt
├── findings.json
├── ai_triage.json
├── report.md
├── h1_sqli_login_form.md
└── errors.log
```

---

## Task Checklist

Master build checklist. Tick boxes as you complete tasks.
Claude Code: update this file at the end of each session.
**Ask developer before starting Phases 5, 7, and 8.**

### Phase 1 — Scaffold
- [x] `bughawk.sh` — sources all libs, runs pipeline, sets `TOTAL_STEPS=7`
- [x] `lib/utils.sh` — all color vars, log functions, spinner, banner (exact text above), print_table, safe_timeout
- [x] `config.example.sh` — all variables with inline comments, placeholder values
- [x] `.gitignore` — ignores: `config.sh`, `output/`, `nuclei-templates/`, `*.log`, `tests/mock_outputs/*.json`
- [x] `README.md` — quickstart, requirements, all example commands
- [x] `PLAN.md` — architecture decisions and rationale

### Phase 2 — Setup & Tool Checker (`lib/setup.sh`)
- [x] `detect_os()` — Linux, macOS, WSL2, Git Bash, Cygwin
- [x] `detect_pkg_manager()` — apt, brew, pacman, winget, choco
- [x] `check_go_path()` — adds `$HOME/go/bin` to PATH if missing, writes to `.bashrc`/`.zshrc`
- [x] Tool check loop — all 18 tools in the reference table
- [x] `install_tool()` — per-tool install logic with exact import paths from table
- [x] `install_via_pkg()` — dispatches to apt/brew/pacman/winget/choco
- [x] gf pattern install — clones `Gf-Patterns` to `~/.gf` after gf binary install
- [x] nuclei template update — runs `nuclei -update-templates -silent` after nuclei install
- [x] trufflehog install — curl script with fallback to GitHub releases binary download
- [x] gitleaks install — GitHub releases binary download (parse latest from API)
- [x] Tool status table printed after check — aligned with printf, shows ✓/✗ and version
- [x] Warning shown for Git Bash without WSL2
- [x] `SKIP_INSTALL_CHECK` flag respected

### Phase 3 — Recon (`lib/recon.sh`)
- [x] `run_recon()` function
- [x] subfinder — saves to `subdomains.txt`
- [x] httpx — JSON output with status/title/tech-detect flags
- [x] whois — saves to `whois.txt`
- [x] nmap — both `-oX nmap.xml` and `-oN nmap.txt` outputs
- [x] waybackurls — piped through `head -$WAYBACK_URL_LIMIT` then `anew`
- [x] gf — all 5 patterns: xss, sqli, lfi, ssrf, redirect
- [x] paramspider — runs if `ENABLE_PARAMSPIDER=true`
- [x] All tools parallel (PIDS[] pattern)
- [x] `safe_timeout` on each tool
- [x] `[ -s file ]` guard before passing to next stage
- [x] `ENABLE_WAYBACK` flag respected

### Phase 4 — Scanning (`lib/scan.sh`)
- [x] `run_scans()` function
- [x] nuclei — exact flags, JSON export, `safe_timeout $TIMEOUT_NUCLEI`
- [x] dalfox — `[ -s params_xss.txt ]` guard, JSON format, `ENABLE_DALFOX` flag
- [x] sqlmap — `[ -s params_sqli.txt ]` guard, `--batch`, `safe_timeout $TIMEOUT_SQLMAP`, `ENABLE_SQLMAP` flag
- [x] ffuf — match codes and threads from config, JSON output, `ENABLE_FFUF` flag
- [x] `--depth quick` skips dalfox, sqlmap, ffuf
- [x] All scanners parallel (PIDS[] pattern)
- [x] Spinner shown during wait

### Phase 5 — Secrets (`lib/secrets.sh`) — ASK DEVELOPER BEFORE STARTING
- [x] `run_secrets()` function
- [x] trufflehog — HTTP mode, JSON output, `ENABLE_SECRETS` flag
- [x] `.git/config` check — CRITICAL if HTTP 200, triggers gitleaks
- [x] gitleaks — runs if .git exposed, JSON report
- [x] Sensitive path loop — full list from above section
- [x] `.git/config` → `CRITICAL` in `manual_findings.txt`
- [x] Other 200/206 paths → `HIGH` in `manual_findings.txt`
- [x] All curl calls include `--max-time 10`

### Phase 6 — Aggregator (`lib/aggregator.sh`)
- [x] `aggregate_findings()` — Python 3 heredoc
- [x] Nuclei NDJSON parser (one JSON object per line)
- [x] httpx JSON parser
- [x] dalfox JSON parser
- [x] sqlmap log parser (reads from `$OUTDIR/sqlmap/` directory)
- [x] ffuf JSON parser
- [x] trufflehog JSON parser
- [x] gitleaks JSON parser (check file exists first)
- [x] `manual_findings.txt` pipe-delimited parser
- [x] All findings merged to `findings.json` array
- [x] Sequential integer `id` assigned to each finding (0-indexed)
- [x] Finding counts printed by severity after aggregation
- [x] Missing/empty tool output files handled without crashing

### Phase 7 — AI Triage (`lib/ai.sh`) — ASK DEVELOPER BEFORE STARTING
- [x] `call_openrouter()` — curl, jq parse, HTTP code handling, 402 fallback
- [x] Retry logic — 429 → wait and retry; 402 → fall back to Tier 2
- [x] API key presence check — skip AI and warn if empty
- [x] `route_to_tier()` — finding count + chain detection thresholds
- [x] `detect_exploit_chain()` — checks type combinations from above
- [x] `FORCE_TIER` respected
- [x] Triage prompt — exact text from AI Prompts section
- [x] Chain analysis prompt — triggered for findings with non-null `chain_id`
- [x] H1 report prompt — triggered if critical/high + `ENABLE_H1_REPORT=true`
- [x] AI JSON response validated — fallback to `ai_triage_raw.txt` if invalid
- [x] Model name logged: `[*] AI tier: 3 — deepseek/deepseek-r1-0528:free`
- [x] `ENABLE_AI_TRIAGE=false` skips entire phase

### Phase 8 — Report (`lib/report.sh`) — ASK DEVELOPER BEFORE STARTING
- [x] `generate_report()` — Python 3 heredoc
- [x] Merges `findings.json` + `ai_triage.json` by finding `id`
- [x] `report.md` — summary table (counts by severity), per-finding sections
- [x] Each finding section: severity, type, URL, parameter, evidence, AI reason, CVSS
- [x] Exploit chains — dedicated section with chain title, numbered attack steps, impact
- [x] Final merged `findings.json` written (AI fields populated)
- [x] One `h1_<type>.md` per critical/high finding
- [x] `OPEN_REPORT_AFTER=true` opens report (`xdg-open` / `open` / `start`)
- [x] `ENABLE_H1_REPORT` flag respected

### Phase 9 — Tests
- [x] `tests/mock_outputs/nuclei.json` — 5 sample findings (mixed severity)
- [x] `tests/mock_outputs/httpx.json` — 3 sample live hosts with tech
- [x] `tests/mock_outputs/dalfox.json` — 2 XSS findings
- [x] `tests/mock_outputs/ffuf.json` — 4 directory findings
- [x] `tests/mock_outputs/trufflehog.json` — 1 secret finding
- [x] `tests/test_setup.sh` — mock tool check, no real installs
- [x] `tests/test_aggregator.sh` — parses all mock outputs, validates schema
- [x] `tests/test_ai.sh` — mocks OpenRouter with static JSON response
- [x] `tests/test_report.sh` — generates report from mock findings.json

### Phase 10 — Wordlists & Payloads
- [x] `wordlists/dirs.txt` — min 500 entries
- [x] `wordlists/params.txt` — min 200 entries
- [x] `wordlists/subdomains.txt` — min 1000 entries
- [x] `payloads/xss.txt` — min 50 payloads (include CSP bypass, polyglot variants)
- [x] `payloads/sqli.txt` — min 30 strings (error-based, blind, time-based)
- [x] `payloads/lfi.txt` — min 20 traversal strings (null byte variants included)

### Phase 11 — Polish & UX
- [x] Banner on start (exact text from utils.sh section)
- [x] Step tracker — `[1/7] Recon` through `[7/7] Report`, 7 total steps
- [x] Elapsed time per step (use `$SECONDS`)
- [x] Total scan time at end
- [x] First-run legal disclaimer — require `I AGREE`, store in `~/.bughawk_accepted`
- [x] `--help` flag — full usage, all flags, all examples
- [x] `--skip-scan <tool>` — comma-separated, validates tool names
- [x] `--scope single|subdomains|wildcard`
- [x] `--depth quick|full`
- [x] `--ai-tier 1|2|3|4` — maps to FORCE_TIER
- [x] `--no-ai` — sets ENABLE_AI_TRIAGE=false
- [x] `--quiet` — suppresses tool stdout
- [x] `--allow-internal` — bypasses private IP block
- [x] `--skip-install-check` — skips Phase 2
- [x] Private IP range check — blocks 10.x, 172.16-31.x, 192.168.x
- [x] `errors.log` written for every tool failure with timestamp
- [x] End summary — tools run, skipped, finding counts by severity, total time, report path

---

## Claude Code Session Rules

1. **Read this entire file first.** Every session. No exceptions.
2. **One phase at a time.** Complete and tick all tasks in Phase N before starting N+1.
3. **Tick checkboxes immediately** after completing each task. Save this file.
4. **Ask before Phases 5, 7, 8.** Say: "Phase X is unticked — should I start it?"
5. **Never hardcode API keys.** Always read from `$OPENROUTER_API_KEY` sourced from `config.sh`.
6. **Use mock data.** Never make real HTTP requests during development. Use `tests/mock_outputs/`.
7. **Functions ≤50 lines.** Split anything longer into helper functions.
8. **Comment non-obvious bash.** Especially: regex, process substitution, indirect expansion.
9. **`[ -s file ]` before every file-as-input.** Empty input to tools causes silent failures.
10. **Every `&` job PID in `PIDS[]`.** No untracked background jobs. Ever.
11. **Exact tool flags from this file.** Do not invent or change flags.
12. **Exact prompt text from this file.** Do not rewrite AI prompts.
