# BugHawk v2 — Architecture Reference
> Claude Code: read this for schemas, routing table, and architecture only.
> For what to build next → read `TASKS.md`. For rules → read `CLAUDE.md`.

---

## 5-Layer Architecture

```
TARGET (URL / domain / API endpoint)
         │
         ▼
┌────────────────────────────────────────────┐
│ L1 — SURFACE MAPPER                        │
│  subfinder → httpx → katana → gau          │
│  getJS → wafw00f → graphql → ws_detector   │
│  output → surface_map.json                 │
└──────────────┬─────────────────────────────┘
               │
               ▼
┌────────────────────────────────────────────┐
│ L2 — AI TRIAGE BRAIN                       │
│  model: claude-sonnet-4-6                  │
│  input: surface_map.json                   │
│  output: scan_plan.json                    │
│  (priority targets, modules, hypotheses)   │
└──────────────┬─────────────────────────────┘
               │
               ▼
┌────────────────────────────────────────────┐
│ L3 — PARALLEL SCAN ENGINE                  │
│  9 modules via concurrent.futures          │
│  nuclei / idor_engine / xss_engine         │
│  sqli_engine / graphql_engine              │
│  websocket_engine / jwt_engine             │
│  cors_engine / fuzz_engine                 │
│  output → findings.json (unified schema)   │
└──────────────┬─────────────────────────────┘
               │
               ▼
┌────────────────────────────────────────────┐
│ L4 — AI REASONING ENGINE                   │
│  idor_diff    → deepseek-r1:free           │
│  cvss_score   → llama-3.3-70b:free         │
│  chain_lite   → deepseek-v3-2              │
│  chain_full   → claude-sonnet-4-6          │
│  h1_report    → claude-sonnet-4-6          │
└──────────────┬─────────────────────────────┘
               │
               ▼
┌────────────────────────────────────────────┐
│ L5 — OUTPUT + INTEGRATIONS                 │
│  rich terminal / jinja2 HTML report        │
│  Flask API → Burp extension                │
│  Telegram bot / Discord webhook            │
│  SQLite scan history + diff engine         │
└────────────────────────────────────────────┘
```

---

## AI Model Routing Table

| Task key | Model | Cost | Tier |
|----------|-------|------|------|
| `parse_json` | `qwen/qwen3-coder-480b-a35b:free` | $0 | FREE |
| `classify_endpoint` | `openrouter/free` | $0 | FREE |
| `extract_ids` | `openrouter/free` | $0 | FREE |
| `tech_fingerprint` | `nvidia/nemotron-3-super:free` | $0 | FREE |
| `surface_structure` | `nvidia/nemotron-3-super:free` | $0 | FREE |
| `idor_diff` | `deepseek/deepseek-r1:free` | $0 | FREE |
| `cvss_score` | `meta-llama/llama-3.3-70b-instruct:free` | $0 | FREE |
| `next_steps` | `meta-llama/llama-3.3-70b-instruct:free` | $0 | FREE |
| `explain_finding` | `deepseek/deepseek-v3-2` | $0.14/M | CHEAP |
| `chain_detect_lite` | `deepseek/deepseek-v3-2` | $0.14/M | CHEAP |
| `triage_brain` | `claude-sonnet-4-6` | $3/$15/M | PREMIUM |
| `chain_detect_full` | `claude-sonnet-4-6` | $3/$15/M | PREMIUM |
| `draft_h1_report` | `claude-sonnet-4-6` | $3/$15/M | PREMIUM |

**Fallback order when rate limited:**
`deepseek-r1:free` → `llama-3.3-70b:free` → `openrouter/free` → `deepseek-v3-2` → `claude-haiku-4-5-20251001`

**Cost per full scan: ~$0.05–0.08 maximum**

**Prompt caching rule:** Always add `cache_control: {"type": "ephemeral"}` to system prompts
in all Claude calls. Saves 90% on input tokens for repeated calls.

---

## Unified Finding Schema

Defined in `modules/base_module.py`. Every module returns `list[Finding]`.

```python
@dataclass
class Finding:
    id: str                      # uuid4()
    tool: str                    # "nuclei" | "dalfox" | "idor_engine" | ...
    module: str                  # BugHawk module name
    title: str                   # short vuln title
    vuln_class: str              # "XSS"|"IDOR"|"SQLi"|"SSRF"|"CORS"|"JWT"|"RCE"
    description: str             # filled by ai/explainer.py
    target_url: str
    endpoint: str
    parameter: str | None
    method: str                  # GET|POST|PUT|DELETE|PATCH
    payload: str | None
    request: str | None          # raw HTTP request
    response_snippet: str | None
    severity: str                # "critical"|"high"|"medium"|"low"|"info"
    cvss_score: float | None     # filled by ai/cvss_scorer.py
    cvss_vector: str | None      # "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    confidence: int              # 0–100, from 3-pass verifier
    verified: bool               # True if passed 3-pass check
    chain_candidate: bool        # flagged by AI as chainable
    chain_ids: list[str]         # IDs of related findings
    timestamp: str               # datetime.utcnow().isoformat()
    ai_explanation: str | None
    ai_next_steps: list[str]
    ai_h1_draft: str | None      # only for top finding / chains
```

---

## Surface Map Schema

Output of Layer 1. Saved as `reports/raw/{scan_id}_surface_map.json`.

```python
{
    "scan_id": "uuid4",
    "target": "https://example.com",
    "timestamp": "ISO8601",
    "subdomains": ["sub1.example.com", ...],
    "live_hosts": [{"url": "", "status": 200, "title": "", "tech": []}],
    "endpoints": [{"url": "", "method": "", "params": []}],
    "tech_stack": ["React", "Node.js", "Nginx", "AWS"],
    "waf": "Cloudflare" | null,
    "graphql_endpoints": [{"url": "", "schema": {}}],
    "websocket_endpoints": ["wss://..."],
    "js_files": ["https://.../bundle.js"],
    "js_secrets": [{"type": "api_key", "value": "...", "file": "..."}],
    "interesting_paths": ["/admin", "/api/v1", "/.env"],
    "parameters": ["q", "user_id", "order_id"]
}
```

---

## AI Prompt Templates (Jinja2)

### `ai/prompts/triage.j2` — L2 Triage Brain input
```
Target: {{ target }}
Tech stack: {{ tech_stack }}
Live hosts: {{ live_hosts | length }} (interesting: {{ interesting_hosts }})
Endpoints: {{ endpoint_count }}
GraphQL: {{ graphql_detected }} — mutations: {{ graphql_mutations }}
WebSockets: {{ websocket_endpoints }}
JS secrets found: {{ js_secrets }}
WAF: {{ waf }}

Return JSON:
{
  "priority_targets": [{"url":"","reason":"","vuln_classes":[]}],
  "modules_to_run": [],
  "skip_targets": [{"url":"","reason":""}],
  "hypothesis": [{"vuln":"","target":"","test_steps":[]}]
}
```

### `ai/prompts/idor_verify.j2` — IDOR response diff
```
Endpoint: {{ endpoint }} [{{ method }}]
Attacker ID: {{ attacker_id }} | Victim ID: {{ victim_id }}

Attacker's own data:
{{ response_own }}

Victim's data accessed by attacker:
{{ response_victim }}

Return JSON:
{
  "is_idor": true|false,
  "confidence": 0-100,
  "evidence": "",
  "pii_exposed": [],
  "severity": "critical|high|medium|low",
  "access_type": "horizontal|vertical|both",
  "impact": ""
}
```

### `ai/prompts/chain_detect.j2` — exploit chain detection
```
Findings from {{ target }}:
{{ findings_json }}

Identify chains. Known patterns:
- SSRF + IMDS → IAM credential theft → cloud account takeover
- Open redirect + OAuth → token hijack → ATO
- CORS + XSS → cross-origin session theft
- JWT bypass + IDOR → access any account at any privilege
- SQLi → auth bypass → admin → RCE via file upload
- XXE → SSRF → internal enumeration
- GraphQL BOLA + sensitive mutation → unauthorized data/financial ops

Return JSON:
{
  "chains": [{
    "chain_id": "",
    "title": "",
    "finding_ids": [],
    "steps": [{"step":1,"action":"","finding_id":"","result":""}],
    "combined_impact": "",
    "cvss_score": 0.0,
    "cvss_vector": "",
    "feasibility": "confirmed|likely|theoretical",
    "next_steps": [],
    "report_priority": "submit_now|verify_first|document"
  }],
  "standalone_critical": [],
  "recommended_action": ""
}
```

### `ai/prompts/h1_report.j2` — HackerOne draft
```
Finding data: {{ finding_json }}
Program: {{ program_name }}
Handle: {{ researcher_handle }}

Write a HackerOne report. Use ONLY data from finding_json — no speculation.

# [Severity] Title — Specific Impact

## Summary
(2-3 sentences, non-technical)

## Severity
**{{ severity }}** — CVSS {{ cvss_score }} ({{ cvss_vector }})

## Steps to Reproduce
1. (exact URL)
2. (exact action + payload)
3. (exact response observed)

## Impact
(specific data/systems at risk, who is affected)

## Supporting Evidence
(what in the response proves this is real)

## Recommended Fix
(specific technical remediation)
```

---

## Tool Commands Reference

```python
# Exact subprocess commands for each Go tool (Windows-compatible)
TOOL_COMMANDS = {
    "subfinder": [
        "subfinder", "-d", "{domain}", "-silent", "-json"
    ],
    "httpx": [
        "httpx", "-l", "{input_file}", "-json", "-silent",
        "-title", "-tech-detect", "-status-code", "-follow-redirects"
    ],
    "katana": [
        "katana", "-u", "{url}", "-jc", "-silent", "-json",
        "-depth", "3", "-c", "20", "-H", "Cookie: {cookies}"
    ],
    "gau": [
        "gau", "{domain}", "--json"
    ],
    "nuclei": [
        "nuclei", "-u", "{url}", "-t", "{template_dir}",
        "-severity", "{severity}", "-json", "-silent", "-c", "25"
    ],
    "dalfox": [
        "dalfox", "url", "{url}", "--silence", "--format", "json"
    ],
    "ffuf": [
        "ffuf", "-u", "{url}/FUZZ", "-w", "{wordlist}",
        "-mc", "200,201,301,302,403", "-o", "{output}", "-of", "json",
        "-s"
    ],
    "getJS": [
        "getJS", "--url", "{url}", "--complete"
    ],
}

# Go tools to auto-install via `go install`
GO_INSTALL_PKGS = {
    "subfinder": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "httpx":     "github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "katana":    "github.com/projectdiscovery/katana/cmd/katana@latest",
    "nuclei":    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "dalfox":    "github.com/hahwul/dalfox/v2@latest",
    "ffuf":      "github.com/ffuf/ffuf/v2@latest",
    "gau":       "github.com/lc/gau/v2/cmd/gau@latest",
    "getJS":     "github.com/003random/getJS@latest",
}

# Pip packages to auto-install
PIP_PACKAGES = [
    "sqlmap", "wafw00f", "corsy",
    "trufflehog", "jwt_tool", "paramspider", "arjun"
]
```

---

## SQLite Tables

```sql
-- db/models.py — create these tables via SQLAlchemy

CREATE TABLE scans (
    scan_id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    mode TEXT NOT NULL,
    status TEXT DEFAULT 'running',  -- running|complete|failed
    finding_count INTEGER DEFAULT 0,
    chain_count INTEGER DEFAULT 0,
    cost_usd REAL DEFAULT 0.0
);

CREATE TABLE findings (
    id TEXT PRIMARY KEY,
    scan_id TEXT REFERENCES scans(scan_id),
    tool TEXT, module TEXT, title TEXT,
    vuln_class TEXT, severity TEXT,
    target_url TEXT, endpoint TEXT, method TEXT,
    payload TEXT, confidence INTEGER,
    verified INTEGER DEFAULT 0,
    chain_candidate INTEGER DEFAULT 0,
    cvss_score REAL, cvss_vector TEXT,
    ai_explanation TEXT, ai_next_steps TEXT,
    ai_h1_draft TEXT, timestamp TEXT,
    raw_json TEXT  -- full Finding as JSON
);

CREATE TABLE chains (
    chain_id TEXT PRIMARY KEY,
    scan_id TEXT REFERENCES scans(scan_id),
    title TEXT, combined_impact TEXT,
    cvss_score REAL, cvss_vector TEXT,
    feasibility TEXT, steps TEXT,  -- JSON array
    finding_ids TEXT,              -- JSON array
    next_steps TEXT,               -- JSON array
    timestamp TEXT
);

CREATE TABLE surface_maps (
    scan_id TEXT PRIMARY KEY REFERENCES scans(scan_id),
    target TEXT, timestamp TEXT,
    data TEXT  -- full surface_map as JSON, used for diffing
);

CREATE TABLE ai_usage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    model_id TEXT, task TEXT,
    input_tokens INTEGER, output_tokens INTEGER,
    cost_usd REAL, timestamp TEXT, scan_id TEXT
);
```

---

## Burp Integration — Flask API Endpoints

```
POST /scan/endpoint   body: {url, method, headers, body, cookies}
                      → run targeted nuclei+IDOR on this endpoint
                      → return: list[Finding]

POST /session         body: {session_id: "a"|"b", cookies: "...", token: "..."}
                      → update session A or B for IDOR testing

GET  /findings        → return all findings from current scan as JSON
GET  /findings/latest → return most recent 10 findings
GET  /status          → {status, scan_target, finding_count, uptime}
GET  /report          → {html_path, h1_draft_path}
```

---

## config.yaml Full Schema

```yaml
ai:
  anthropic_model_premium: "claude-sonnet-4-6"
  anthropic_model_fast: "claude-haiku-4-5-20251001"
  openrouter_base_url: "https://openrouter.ai/api/v1"
  enable_prompt_caching: true
  daily_free_limit: 180
  warn_at_remaining: 50
  max_cost_per_scan_usd: 0.50

scan:
  default_mode: "web"
  threads: 5
  verify_passes: 3
  confidence_threshold: 70
  rate_limit_rps: 10
  timeout: 30

tools:
  nuclei_templates: "~/.nuclei-templates"
  nuclei_severity: "critical,high,medium"
  ffuf_wordlist: "wordlists/common.txt"
  sqlmap_level: 2
  sqlmap_risk: 2

monitoring:
  enabled: false
  schedule_cron: "0 9 * * *"
  targets_file: "targets.txt"
  alerts:
    telegram:
      enabled: false
      bot_token: ""
      chat_id: ""
    discord:
      enabled: false
      webhook_url: ""

integrations:
  burp:
    enabled: false
    port: 7331
    host: "127.0.0.1"

output:
  terminal: true
  html_report: true
  report_dir: "reports/"
  save_raw: true
```
