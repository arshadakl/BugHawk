#!/usr/bin/env bash
# BugHawk configuration — copy to config.sh and fill in values
# NEVER commit config.sh (it is git-ignored)
#
# Usage:
#   cp config.example.sh config.sh
#   nano config.sh   # fill in your API key

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

# ── Active Checks ─────────────────────────────────────────────────────────────
ENABLE_ACTIVE=true            # master switch for all active checks below
ENABLE_CORS_CHECK=true        # CORS misconfiguration (curl-based)
ENABLE_HEADERS_CHECK=true     # missing security headers (curl-based)
ENABLE_REDIRECT_CHECK=true    # open redirect injection on gf redirect params
ENABLE_LFI_ACTIVE=true        # LFI payload injection on gf lfi params
ENABLE_TAKEOVER=true          # subdomain takeover check via subzy
ENABLE_SSL_CHECK=true         # SSL/TLS analysis via testssl.sh
ENABLE_SSRF_OOB=false         # SSRF OOB via interactsh (requires interactsh-client)
TIMEOUT_SSL=180               # testssl timeout (seconds)

# ── JS Analysis ───────────────────────────────────────────────────────────────
ENABLE_JS_ANALYSIS=true       # extract endpoints + secrets from JavaScript files

# ── Output ────────────────────────────────────────────────────────────────────
OUTPUT_DIR="./output"
OPEN_REPORT_AFTER=true        # auto-open report.md when done
QUIET_MODE=false              # suppress tool stdout

# ── Rate Limiting ─────────────────────────────────────────────────────────────
OPENROUTER_RETRY_LIMIT=3
OPENROUTER_RETRY_DELAY=5      # seconds between retries on 429

# ── Cache ─────────────────────────────────────────────────────────────────────
# Cache lives at ~/.bughawk/cache/<domain>/
# Override individual TTLs (hours) if needed
# CACHE_TTL_SUBDOMAINS=24
# CACHE_TTL_HTTPX=12
# CACHE_TTL_WHOIS=168
# CACHE_TTL_NMAP=24
# CACHE_TTL_WAYBACK=72
# CACHE_TTL_PARAMS=24
