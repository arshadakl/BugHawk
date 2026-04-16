# BugHawk — Task List for Claude Code

> **How to use this file:**
> - Find the first unchecked `[ ]` task. That is your starting point.
> - Complete it fully, run its test, then mark it `[x]`.
> - Never skip a task. Never mark done without running the test.
> - Update this file after each task.

---

## PHASE 1 — Foundation
**Goal:** Tool runs, maps a target, installs all tools automatically.

### Task 1.1 — Project Skeleton
- [ ] Create `requirements.txt` with all deps from CLAUDE.md
- [ ] Create `.env.example` with 5 keys (ANTHROPIC_API_KEY, OPENROUTER_API_KEY, TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, DISCORD_WEBHOOK_URL)
- [ ] Create `config.yaml` using the full schema from PLAN.md
- [ ] Create all `__init__.py` files: `core/`, `modules/`, `ai/`, `integrations/`, `output/`, `db/`
- [ ] Create empty `reports/.gitkeep` and `wordlists/.gitkeep`

**Test:** All directories exist. `python -c "import yaml; yaml.safe_load(open('config.yaml'))"` runs without error.

---

### Task 1.2 — CLI Entry Point (`bughawk.py`)
- [ ] Implement argparse with flags: `--target`, `--mode`, `--ai`, `--monitor`, `--report`, `--setup`, `--session-a`, `--session-b`, `--output`, `--config`, `--verbose`
- [ ] Print ASCII banner using `rich` (green color, monospace)
- [ ] Load `.env` via `python-dotenv` at startup
- [ ] Call `SetupManager.quick_check()` on every run — exit with message if fails
- [ ] If `--setup` flag: call `SetupManager.run_full_check()` and exit
- [ ] If no `--target` and not `--setup`: print usage and exit
- [ ] Import `Orchestrator` inside `main()` only (not at top level — keeps startup fast)
- [ ] Add `colorama.init()` call at startup for Windows color support

**Test:** `python bughawk.py --help` shows all flags. `python bughawk.py` (no args) exits cleanly with usage message.

---

### Task 1.3 — Setup Manager (`core/setup.py`)
- [ ] Class `SetupManager` with `__init__(self, config_path: str)`
- [ ] `quick_check() -> bool` — checks only: Python version >= 3.10, `.env` exists, `ANTHROPIC_API_KEY` set. Returns False if any fail.
- [ ] `run_full_check() -> None` — full check + auto-install. Uses `rich.table.Table` for checklist output.
- [ ] Check each Go tool: use `shutil.which(tool_name)`. If missing, run `go install <pkg>` from `GO_INSTALL_PKGS` in PLAN.md
- [ ] Add GOBIN to PATH: `Path(os.environ.get("USERPROFILE","")) / "go" / "bin"` — add to `os.environ["PATH"]`
- [ ] Check each pip package: use `importlib.util.find_spec(pkg)`. If missing, run `pip install -q <pkg>` via subprocess
- [ ] After install, re-check and show green ✓ or red ✗ per tool
- [ ] `check_nuclei_templates() -> None` — if `~/.nuclei-templates` missing, run `nuclei -update-templates`

**Test:** `python bughawk.py --setup` completes without crash. Shows a table with at least Python, Go, and 3 tool rows.

---

### Task 1.4 — Recon Engine (`core/recon.py`)
- [ ] Class `ReconEngine` with `__init__(self, config: dict)`
- [ ] `run(target: str) -> dict` — runs full recon, returns raw results dict
- [ ] `run_subfinder(domain: str) -> list[str]` — parse JSON lines from stdout, return list of subdomains
- [ ] `run_httpx(subdomains: list[str]) -> list[dict]` — write subdomains to temp file, run httpx, parse JSON lines. Each item: `{url, status, title, tech}`
- [ ] `run_katana(url: str, cookies: str = "") -> list[str]` — return list of crawled URLs
- [ ] `run_gau(domain: str) -> list[str]` — return list of archived URLs
- [ ] `run_wafw00f(url: str) -> str | None` — return WAF name or None
- [ ] `run_getjs(url: str) -> list[str]` — return list of JS file URLs
- [ ] All subprocess calls must use `creationflags=subprocess.CREATE_NO_WINDOW` and `encoding="utf-8"`
- [ ] Handle subprocess timeout (30s default). Log warning if tool times out, return empty list.
- [ ] Use `rich.progress.Progress` to show live progress bar while recon runs

**Test:** `python -c "from core.recon import ReconEngine; r = ReconEngine({}); print(r.run_subfinder('google.com'))"` returns a list with at least one subdomain.

---

### Task 1.5 — JS Hunter (`core/js_hunter.py`)
- [ ] Class `JSHunter` with `__init__(self, config: dict)`
- [ ] `run(js_urls: list[str]) -> dict` — returns `{secrets: [], endpoints: [], params: []}`
- [ ] `download_js(url: str) -> str` — download JS content via `requests.get()`, return text
- [ ] `extract_secrets(content: str) -> list[dict]` — regex scan for:
  - API keys: `(?i)(api[_-]?key|apikey)\s*[:=]\s*['"]([^'"]{10,})['"]`
  - AWS keys: `AKIA[0-9A-Z]{16}`
  - Generic tokens: `(?i)(token|secret|password)\s*[:=]\s*['"]([^'"]{8,})['"]`
  - Internal URLs: `https?://(?:10\.|192\.168\.|172\.|localhost|internal)`
  - Each match: `{type, value_preview (first 8 chars + ***), file_url}`
- [ ] `extract_endpoints(content: str) -> list[str]` — find strings matching `/api/...` patterns
- [ ] `extract_params(content: str) -> list[str]` — find query parameter names

**Test:** Create a fake JS string with a hardcoded `api_key = "test12345678"` and verify `extract_secrets()` finds it.

---

### Task 1.6 — GraphQL Mapper (`core/graphql_mapper.py`)
- [ ] Class `GraphQLMapper`
- [ ] `detect(url: str) -> list[str]` — try common GraphQL paths: `/graphql`, `/api/graphql`, `/v1/graphql`, `/query`. Return list of confirmed endpoints (200 OK with `{"data":` in response).
- [ ] `introspect(endpoint: str, cookies: str = "") -> dict` — POST introspection query, return schema dict
- [ ] `extract_mutations(schema: dict) -> list[dict]` — parse schema, return `[{name, args, is_sensitive}]`. Flag as sensitive if name contains: delete, update, transfer, admin, password, role, permission
- [ ] Handle introspection disabled (403/errors) — return `{"introspection_disabled": True}`

**Test:** Run `detect()` against a URL and verify it returns a list (empty is ok if target has no GraphQL).

---

### Task 1.7 — Surface Map Builder (`core/surface_map.py`)
- [ ] Class `SurfaceMapper`
- [ ] `build(target: str, recon_data: dict, js_data: dict, graphql_data: dict, ws_data: list) -> dict` — assemble all recon output into surface_map schema from PLAN.md
- [ ] `save(surface_map: dict, scan_id: str) -> Path` — save to `reports/raw/{scan_id}_surface_map.json` as formatted JSON
- [ ] `load(scan_id: str) -> dict` — load a saved surface map
- [ ] Deduplicate all lists (endpoints, subdomains, parameters) before saving

**Test:** Call `build()` with fake recon data dicts and verify output matches the schema in PLAN.md with all required keys.

---

## PHASE 2 — AI Router + Triage
**Goal:** AI reads surface map, returns scan plan. Multi-provider routing works.

### Task 2.1 — AI Client (`ai/client.py`)
- [ ] Class `AIClient` with `__init__(self, config: dict)`
- [ ] Load `ANTHROPIC_API_KEY` and `OPENROUTER_API_KEY` from env via `python-dotenv`
- [ ] Init `anthropic.Anthropic()` client
- [ ] Init `openai.OpenAI()` client with `base_url="https://openrouter.ai/api/v1"` and headers `{"HTTP-Referer": "https://github.com/bughawk", "X-Title": "BugHawk"}`
- [ ] `complete(model, system, user, json_mode=True, max_tokens=2000, use_cache=True) -> str`
  - If `model.startswith("claude-")`: use Anthropic SDK. Add `cache_control: {"type": "ephemeral"}` to system if `use_cache=True`
  - Else: use OpenRouter via OpenAI SDK. If `json_mode=True`, add `response_format={"type": "json_object"}`
- [ ] Wrap all API calls in try/except. On failure: log error with `rich`, raise custom `AIClientError`
- [ ] Strip markdown code fences from response before returning: `re.sub(r'```\w*\n?', '', text).strip()`
- [ ] Log model name + estimated token count before every paid call

**Test:**
```python
from ai.client import AIClient
client = AIClient({})
# Test free model
r = client.complete("deepseek/deepseek-r1:free", "You are helpful.", "Say hello in JSON: {\"message\": \"...\"}")
print(r)  # should be valid JSON string
# Test Claude
r2 = client.complete("claude-sonnet-4-6", "You are helpful.", "Say hello in JSON.")
print(r2)
```

---

### Task 2.2 — AI Router (`ai/router.py`)
- [ ] Class `AIRouter` with `__init__(self, client: AIClient, config: dict, db: Database)`
- [ ] Implement `TASK_MODEL_MAP` dict exactly as in PLAN.md routing table
- [ ] Implement `FALLBACK_ORDER` list from PLAN.md
- [ ] `route(task: str, system: str, user: str, **kwargs) -> str`
  - Get model from `TASK_MODEL_MAP[task]`
  - Check rate limit via `db.get_usage_count(model, window_hours=24)`
  - If near limit (< 20 remaining): use next model in `FALLBACK_ORDER`
  - Call `client.complete(model, system, user, **kwargs)`
  - On failure: try next fallback
  - Log: task name, model used, fallback reason if any
- [ ] `estimate_cost(model: str, input_tokens: int, output_tokens: int) -> float`
  - Use pricing table: sonnet-4-6 = $3/$15/M, haiku = $1/$5/M, deepseek-v3-2 = $0.14/$0.28/M, free models = $0
- [ ] `log_usage(model, task, input_tokens, output_tokens, cost, scan_id)` — save to `ai_usage` table

**Test:** Call `router.route("parse_json", "system", "user")` — verify it uses `qwen/qwen3-coder-480b-a35b:free` and not a paid model.

---

### Task 2.3 — System Prompt (`ai/prompts/system_security.txt`)
- [ ] Write the base system prompt (used for all Claude calls):
```
You are an expert bug bounty hunter and penetration tester with 10 years of experience
on HackerOne and Bugcrowd. You specialize in web application security, API testing,
GraphQL vulnerabilities, and chaining low-severity findings into critical exploit paths.

You always respond with valid JSON unless explicitly told otherwise.
You are direct, specific, and technical. No fluff, no disclaimers.
When you see findings, you think like an attacker — what is the worst case impact?
You know every common exploit chain: SSRF to IMDS to RCE, IDOR to ATO, XXE to SSRF,
JWT bypass to privilege escalation, open redirect plus OAuth to token theft.
```

---

### Task 2.4 — Prompt Templates (`ai/prompts/`)
- [ ] Create `triage.j2` — use template from PLAN.md exactly
- [ ] Create `idor_verify.j2` — use template from PLAN.md exactly
- [ ] Create `chain_detect.j2` — use template from PLAN.md exactly
- [ ] Create `h1_report.j2` — use template from PLAN.md exactly
- [ ] Create `cvss.j2`:
```
Finding: {{ finding_json }}

Score this using CVSS 3.1. Return JSON:
{
  "score": 0.0,
  "vector": "AV:.../AC:.../PR:.../UI:.../S:.../C:.../I:.../A:...",
  "justification": {
    "AV": "reason", "AC": "reason", "PR": "reason",
    "UI": "reason", "S": "reason", "C": "reason",
    "I": "reason", "A": "reason"
  }
}
```

---

### Task 2.5 — Triage Brain (`ai/triage.py`)
- [ ] Class `TriageBrain` with `__init__(self, router: AIRouter)`
- [ ] `run(surface_map: dict) -> dict` — render `triage.j2` with surface map data, call `router.route("triage_brain", ...)`, parse JSON response, return typed dict
- [ ] Validate response has required keys: `priority_targets`, `modules_to_run`, `hypothesis`
- [ ] On JSON parse error: retry once with explicit instruction to return valid JSON
- [ ] Save triage plan to `reports/raw/{scan_id}_triage.json`

**Test:** Call `run()` with a minimal surface map dict containing at least `target`, `tech_stack`, `subdomain_count`. Verify response has `modules_to_run` as a list.

---

## PHASE 3 — Scan Modules
**Goal:** All 9 modules run and return unified Finding objects.

### Task 3.1 — Base Module (`modules/base_module.py`)
- [ ] `Finding` dataclass — all fields from CLAUDE.md schema. Add `to_dict()` and `to_json()` methods.
- [ ] Abstract class `BaseModule` with:
  - `run(target: str, scan_plan: dict) -> list[Finding]` — must be implemented by each module
  - `run_tool(cmd: list[str], timeout: int = 60) -> tuple[str, str]` — subprocess wrapper, returns (stdout, stderr). Always adds `CREATE_NO_WINDOW`.
  - `verify(finding: Finding, passes: int = 3) -> Finding` — make `passes` requests, update `finding.verified` and `finding.confidence`
  - `normalize(raw: dict, tool: str) -> Finding` — convert raw tool output to Finding
  - `emit(findings: list[Finding]) -> None` — put findings on shared queue for live terminal display

**Test:** Instantiate a concrete stub subclass and call `run_tool(["python", "--version"])`. Verify stdout contains "Python".

---

### Task 3.2 — Nuclei Runner (`modules/nuclei_runner.py`)
- [ ] `class NucleiRunner(BaseModule)`
- [ ] `run(target, scan_plan) -> list[Finding]`
  - Get template tags from `scan_plan["modules_to_run"]` — map to nuclei template categories
  - Build command using `TOOL_COMMANDS["nuclei"]` from PLAN.md
  - Parse each JSON line of stdout into a Finding
  - Map nuclei severity → Finding severity (critical/high/medium/low/info)
  - Call `verify()` on each finding with confidence >= 50
- [ ] `parse_nuclei_line(line: str) -> Finding | None` — parse one JSON line, return None if parse fails

**Test:** Run against `https://scanme.nmap.org` or a known-safe target. Verify at least one Finding returned (even "info" level is fine).

---

### Task 3.3 — IDOR Engine (`modules/idor_engine.py`)
This is the most important module. Take your time.

- [ ] `class IDOREngine(BaseModule)`
- [ ] `run(target, scan_plan, session_a: str = "", session_b: str = "") -> list[Finding]`
- [ ] `crawl_endpoints(url: str, cookies: str) -> list[dict]` — run katana with session cookies, parse all endpoints with their request/response
- [ ] `extract_object_refs(endpoints: list[dict]) -> list[dict]` — for each endpoint, extract:
  - Numeric IDs: regex `r'/(\d{3,})'` and `r'[?&](\w*id\w*|order|user|account)=(\d+)'`
  - UUIDs: regex `r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'`
  - Return: `[{url, method, param, value, type: "numeric|uuid|slug"}]`
- [ ] `mass_test(refs: list[dict], session_a: str, session_b: str) -> list[dict]` — for each ref:
  - Request with session_a to get baseline
  - Request with session_b (swapped session) 
  - If response_b status == 200: add to candidates list
  - Return: `[{endpoint, request_a, response_a, request_b, response_b}]`
- [ ] `ai_verify(candidate: dict) -> Finding | None` — call `router.route("idor_diff", ...)` with `idor_verify.j2`. If `is_idor=True` and `confidence >= threshold`: return Finding. Else None.
- [ ] Also test GraphQL BOLA: for each mutation in `scan_plan["graphql_mutations"]`, swap user_id arg and check response

**Test:** Create two fake response dicts (one with user A data, one with user B data accessed by A) and call `ai_verify()`. Verify it returns a Finding with `vuln_class="IDOR"`.

---

### Task 3.4 — XSS Engine (`modules/xss_engine.py`)
- [ ] `class XSSEngine(BaseModule)`
- [ ] `run(target, scan_plan) -> list[Finding]`
- [ ] Collect URLs to test: from scan_plan endpoints + gau output
- [ ] Write URLs to temp file
- [ ] Run dalfox in pipe mode: `dalfox pipe -o {output} --silence --format json`
- [ ] Parse dalfox JSON output into Findings
- [ ] Set `confidence = 90` for reflected XSS, `70` for DOM-based

**Test:** Module runs without crashing on a target URL. Returns list (empty is ok).

---

### Task 3.5 — SQLi Engine (`modules/sqli_engine.py`)
- [ ] `class SQLiEngine(BaseModule)`
- [ ] `run(target, scan_plan) -> list[Finding]`
- [ ] Get parameterized URLs from scan_plan
- [ ] Run: `sqlmap -u {url} --batch --level {level} --risk {risk} --output-dir {tmpdir} --format=json`
- [ ] Parse sqlmap output directory for JSON results
- [ ] Return Findings with `vuln_class="SQLi"`

**Test:** Module runs without crashing. Returns list.

---

### Task 3.6 — GraphQL Engine (`modules/graphql_engine.py`)
- [ ] `class GraphQLEngine(BaseModule)`
- [ ] `run(target, scan_plan) -> list[Finding]`
- [ ] For each GraphQL endpoint in scan_plan:
  - Test introspection without auth (flag if enabled without auth)
  - Test BOLA: for each mutation with ID args, swap to victim ID
  - Test batch DoS: send 50 aliases of same query
  - Test field injection: inject `' OR '1'='1` in string variables
  - Test auth bypass: remove Authorization header, check if data returned
- [ ] All via `requests.post()` with appropriate headers

**Test:** Run against a mock GraphQL endpoint or a known-safe GraphQL target. Module returns list.

---

### Task 3.7 — WebSocket Engine (`modules/websocket_engine.py`)
- [ ] `class WebSocketEngine(BaseModule)`
- [ ] `run(target, scan_plan) -> list[Finding]`
- [ ] For each WebSocket endpoint in scan_plan:
  - Connect via `websocket.create_connection(url, header={"Cookie": cookies})`
  - Capture first 5 messages, detect schema
  - Test unauthenticated: reconnect without auth header, check if connection succeeds
  - Test XSS: send `{"message": "<img src=x onerror=alert(1)>"}`
  - Test IDOR: if schema has user_id field, swap to different ID
  - Test broadcast leak: monitor 10 messages, check if other users' data appears

**Test:** Module runs without crashing on a non-WS target (should return empty list gracefully).

---

### Task 3.8 — JWT Engine (`modules/jwt_engine.py`)
- [ ] `class JWTEngine(BaseModule)`
- [ ] `run(target, scan_plan, session_a: str = "") -> list[Finding]`
- [ ] Extract JWT from session_a cookies/headers if present
- [ ] Test alg:none: decode header, change `"alg"` to `"none"`, re-encode without signature
- [ ] Test weak secret: run jwt-tool wordlist attack with common secrets
- [ ] Test claims tampering: decode payload, change `"role"` to `"admin"` or `"is_admin"` to `true`
- [ ] For each modified JWT: re-send request and check if accepted
- [ ] Return Finding if any bypass succeeds

**Test:** Create a fake JWT string and run `extract_jwt()` against a mock cookie string. Verify it extracts the token.

---

### Task 3.9 — CORS Engine (`modules/cors_engine.py`)
- [ ] `class CORSEngine(BaseModule)`
- [ ] `run(target, scan_plan) -> list[Finding]`
- [ ] For each live host, test these Origin header values:
  - `null`
  - `https://evil.com`
  - `https://{target}.evil.com` (subdomain suffix bypass)
  - `https://evil{target}` (prefix bypass)
- [ ] Check response for `Access-Control-Allow-Origin: <injected>` AND `Access-Control-Allow-Credentials: true`
- [ ] Only flag as vuln if BOTH headers present (ACA + ACAC = exploitable)
- [ ] Severity: High if credentialed, Low if not

**Test:** Module runs against a URL. Returns list.

---

### Task 3.10 — Fuzz Engine (`modules/fuzz_engine.py`)
- [ ] `class FuzzEngine(BaseModule)`
- [ ] `run(target, scan_plan) -> list[Finding]`
- [ ] Directory brute force via ffuf — use `wordlists/common.txt`
- [ ] Parameter discovery via arjun on interesting endpoints from scan_plan
- [ ] Flag: `.env`, `.git`, `backup.zip`, `admin/`, `api/v1/` discovered → Finding
- [ ] Return Findings for each interesting path found (severity: medium for admin paths, low for info)

**Test:** Module runs without crashing. Returns list.

---

### Task 3.11 — Parallel Orchestrator (`core/orchestrator.py`)
- [ ] Class `Orchestrator` with `__init__(self, args, config, db, router)`
- [ ] `run() -> None` — main scan lifecycle:
  1. Run Layer 1 (ReconEngine + JSHunter + GraphQLMapper + SurfaceMapper)
  2. Run Layer 2 (TriageBrain) → get scan_plan
  3. Run Layer 3 (all modules in parallel via ThreadPoolExecutor)
  4. Run Layer 4 (ChainDetector + CVSSScorer + ReportDrafter)
  5. Run Layer 5 (TerminalOutput + HTMLReport)
- [ ] `run_modules_parallel(modules: list, target: str, scan_plan: dict) -> list[Finding]`
  - Use `concurrent.futures.ThreadPoolExecutor(max_workers=config.scan.threads)`
  - Stream findings to terminal as each module completes via `output.terminal.emit()`
- [ ] Load only modules listed in `scan_plan["modules_to_run"]`
- [ ] Save all findings to `findings.json` and SQLite after Layer 3

**Test:** Run in `--mode quick` which should only trigger nuclei_runner. Verify at least nuclei_runner is called.

---

## PHASE 4 — AI Reasoning + Reports
**Goal:** Chains detected. HTML report generated. H1 draft ready.

### Task 4.1 — CVSS Scorer (`ai/cvss_scorer.py`)
- [ ] Class `CVSSScorer` with `__init__(self, router: AIRouter)`
- [ ] `score(finding: Finding) -> Finding` — render `cvss.j2`, call `router.route("cvss_score", ...)` (free model), parse JSON, update `finding.cvss_score` and `finding.cvss_vector`, return updated Finding
- [ ] `score_batch(findings: list[Finding]) -> list[Finding]` — score all findings, max 10 at a time to avoid rate limits

**Test:** Score a mock Finding with `vuln_class="IDOR"` and verify result has a float `cvss_score` between 0.0 and 10.0.

---

### Task 4.2 — Chain Detector (`ai/chain_detector.py`)
- [ ] Class `ChainDetector` with `__init__(self, router: AIRouter)`
- [ ] Two-stage detection:
  1. `lite_pass(findings: list[Finding]) -> bool` — check if any chain pattern signatures exist among finding vuln_classes. Use `deepseek-v3-2`. Returns True if candidates found.
  2. `full_pass(findings: list[Finding]) -> list[dict]` — only called if lite_pass=True. Render `chain_detect.j2`, call `router.route("chain_detect_full", ...)` (Claude Sonnet 4.6), parse JSON, return list of chain dicts.
- [ ] `run(findings: list[Finding]) -> list[dict]` — lite pass first, full pass only if needed. Log cost saved if lite pass returns False.

**Test:** Pass a list of two mock Findings with `vuln_class="SSRF"` and `vuln_class="IDOR"` to `lite_pass()`. Verify it returns True (chain candidates exist).

---

### Task 4.3 — Report Drafter (`ai/report_drafter.py`)
- [ ] Class `ReportDrafter` with `__init__(self, router: AIRouter)`
- [ ] `draft(finding_or_chain: dict) -> str` — render `h1_report.j2`, call `router.route("draft_h1_report", ...)` (Claude Sonnet 4.6), return markdown string
- [ ] Only call for: findings with `confidence >= 85` OR any detected chain
- [ ] Save draft to `reports/h1_draft_{id}.md`
- [ ] Log: "Drafting H1 report for {title} — estimated cost: ${cost}"

**Test:** Draft a report for a mock IDOR finding dict. Verify output contains "## Steps to Reproduce" and "## Impact".

---

### Task 4.4 — HTML Report Generator (`output/html_report.py`)
- [ ] Class `HTMLReportGenerator` with `__init__(self, config: dict)`
- [ ] `generate(scan_id: str, findings: list[Finding], chains: list[dict], surface_map: dict, triage: dict) -> Path`
- [ ] Use Jinja2 to render `output/templates/report.html.j2`
- [ ] Template must include:
  - Header: target, scan date, mode, total findings, severity breakdown (Critical/High/Medium/Low/Info counts)
  - Findings table: sortable by severity, click row to expand detail
  - Finding detail: title, CVSS score+vector, endpoint, payload, request/response (collapsible), AI explanation, next steps
  - Chains section: each chain with step-by-step visualization
  - H1 draft section: syntax-highlighted markdown, copy button
  - Remediation section per finding
- [ ] Report must be **self-contained** — all CSS and JS inline, no external URLs
- [ ] Save to `reports/{target_clean}_{timestamp}.html`

**Test:** Generate a report with 2 mock findings. Open in browser. Verify no broken layout and findings visible.

---

### Task 4.5 — Terminal Output (`output/terminal.py`)
- [ ] Class `TerminalOutput` with `__init__(self, config: dict)`
- [ ] `emit(findings: list[Finding]) -> None` — print each finding as a rich-formatted line immediately when called
- [ ] `print_summary(findings, chains, scan_duration) -> None` — print final summary table
- [ ] `print_layer_header(layer_num: int, layer_name: str) -> None` — print section separator
- [ ] Finding line format: `[SEVERITY] [MODULE] Title — endpoint`
  - Critical: bright red
  - High: red
  - Medium: yellow
  - Low: blue
  - Info: dim white
- [ ] Summary table columns: Severity | Count | Highest CVSS | Modules

**Test:** Call `emit()` with one mock Critical finding. Verify colored output in terminal.

---

## PHASE 5 — Burp + Monitoring
**Goal:** Burp integration works. Monitoring daemon runs.

### Task 5.1 — Flask API Server (`api_server.py`)
- [ ] Flask app on `127.0.0.1:7331`
- [ ] `POST /scan/endpoint` — accepts `{url, method, headers, body, cookies}`, runs nuclei + IDOR targeted scan, returns `{findings: [...]}`
- [ ] `POST /session` — accepts `{session_id: "a"|"b", cookies: "..."}`, stores in memory
- [ ] `GET /findings` — returns all findings from current scan as JSON
- [ ] `GET /status` — returns `{status, target, finding_count, uptime_seconds}`
- [ ] `GET /report` — returns `{html_path, h1_draft_paths: []}`
- [ ] Run with `threaded=True` so it handles concurrent Burp requests
- [ ] Start via: `python api_server.py` (separate process from main scan)

**Test:** Start api_server.py, send `GET http://localhost:7331/status` with curl or requests. Verify JSON response.

---

### Task 5.2 — Burp Extension (`integrations/burp/BugHawkExtension.py`)
- [ ] Implement Burp Montoya API extension in Python
- [ ] Register HTTP handler: forward every in-scope request to `localhost:7331/scan/endpoint`
- [ ] Create Burp Scanner Issue for each finding returned (severity mapped to Burp severity levels)
- [ ] Add context menu item: "Deep Scan with BugHawk" on any request
- [ ] Create `integrations/burp/README.md` with step-by-step install instructions:
  1. Start BugHawk API: `python api_server.py`
  2. In Burp: Extender → Add → Python → select `BugHawkExtension.py`
  3. Verify: check Extensions tab for "BugHawk loaded" message

**Test:** Load extension in Burp (if available). If no Burp: verify the file has no syntax errors via `python -m py_compile integrations/burp/BugHawkExtension.py`.

---

### Task 5.3 — Database (`db/database.py` + `db/models.py`)
- [ ] SQLAlchemy models for all 5 tables defined in PLAN.md: `scans`, `findings`, `chains`, `surface_maps`, `ai_usage`
- [ ] Class `Database` with:
  - `__init__(self, db_path: str = "db/bughawk.db")` — create tables if not exist
  - `save_scan(scan_id, target, mode) -> None`
  - `save_findings(findings: list[Finding], scan_id: str) -> None`
  - `save_chains(chains: list[dict], scan_id: str) -> None`
  - `save_surface_map(surface_map: dict, scan_id: str) -> None`
  - `get_last_surface_map(target: str) -> dict | None`
  - `get_usage_count(model_id: str, window_hours: int) -> int`
  - `log_ai_usage(model_id, task, input_tokens, output_tokens, cost, scan_id) -> None`

**Test:** Create a Database instance, save a mock scan + one Finding, retrieve it back. Verify data matches.

---

### Task 5.4 — Diff Engine (`core/diff_engine.py`)
- [ ] Class `DiffEngine`
- [ ] `diff(current: dict, previous: dict) -> dict` — compare two surface_maps:
  - `new_subdomains = set(current["subdomains"]) - set(previous["subdomains"])`
  - `new_endpoints = set(current_ep_urls) - set(previous_ep_urls)`
  - `removed_endpoints = set(previous_ep_urls) - set(current_ep_urls)`
  - Return: `{new_subdomains: [], new_endpoints: [], removed_endpoints: [], has_changes: bool}`
- [ ] `diff_findings(current_ids: list[str], previous_ids: list[str]) -> list[str]` — return new finding IDs

**Test:** Create two surface_map dicts where the second has one extra subdomain. Verify `diff()` returns it in `new_subdomains`.

---

### Task 5.5 — Monitoring Daemon (`daemon.py`)
- [ ] Class `MonitorDaemon`
- [ ] `run() -> None` — infinite loop: load targets from `targets.txt`, scan each, diff, alert, sleep
- [ ] `register_scheduler() -> None` — register Windows Task Scheduler task:
  `schtasks /create /tn BugHawk-Monitor /tr "python daemon.py" /sc daily /st 09:00 /f`
- [ ] `load_targets() -> list[str]` — read `targets.txt`, skip blank lines and `#` comments
- [ ] `scan_target(target: str) -> tuple[dict, list[Finding]]` — run quick recon + nuclei only
- [ ] `alert_if_changes(target, diff_result, new_findings) -> None` — call Telegram + Discord if `diff.has_changes` or new findings

**Test:** Create a `targets.txt` with one URL. Call `load_targets()`. Verify it returns a list with that URL.

---

### Task 5.6 — Telegram Bot (`integrations/telegram_bot.py`)
- [ ] Class `TelegramAlerter`
- [ ] `send_alert(title: str, severity: str, target: str, finding_summary: str) -> None`
  - Uses `python-telegram-bot` library
  - Message format:
    ```
    🚨 NEW FINDING — {SEVERITY}
    Target: {target}
    Issue: {title}
    Summary: {finding_summary}
    ```
- [ ] `send_file(file_path: Path, caption: str) -> None` — send HTML report as attachment
- [ ] Handle `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID` missing gracefully — log warning, skip

**Test:** If TELEGRAM_BOT_TOKEN in env: send a test alert. If not: verify function returns None without crashing.

---

### Task 5.7 — Discord Webhook (`integrations/discord_webhook.py`)
- [ ] Class `DiscordAlerter`
- [ ] `send_alert(finding: Finding) -> None` — POST to DISCORD_WEBHOOK_URL with rich embed:
  - Color: red(critical), orange(high), yellow(medium), blue(low)
  - Fields: Target, Endpoint, Severity, CVSS Score, Confidence
- [ ] Handle missing webhook URL gracefully

**Test:** If DISCORD_WEBHOOK_URL in env: send test embed. If not: verify returns None without crashing.

---

## PHASE 6 — Polish + Verification
**Goal:** Everything works end-to-end. Clean install. Real target tested.

### Task 6.1 — End-to-End Test
- [ ] Fresh clone of the project
- [ ] Run `python bughawk.py --setup` — verify all tools install cleanly
- [ ] Run `python bughawk.py --target https://example.com --mode quick --ai`
- [ ] Verify: surface_map.json created, findings.json created, HTML report opens in browser
- [ ] Verify: no unhandled exceptions in any layer

### Task 6.2 — Wordlists Auto-Download
- [ ] In `SetupManager.run_full_check()`, add: if `wordlists/common.txt` missing, download SecLists `Discovery/Web-Content/common.txt` from GitHub raw URL via `requests.get()`
- [ ] Also download `Discovery/Web-Content/api-endpoints.txt`

### Task 6.3 — README.md
- [ ] Write `README.md` with:
  - Installation steps (Python, Go, `pip install -r requirements.txt`, `.env` setup)
  - Usage examples (all `--mode` options)
  - Burp integration setup
  - Monitoring setup
  - AI provider setup (how to get OpenRouter key — it's free)

### Task 6.4 — Final Checks
- [ ] All files under 300 lines — split any that exceed
- [ ] All functions have docstrings
- [ ] All type hints present
- [ ] No `print()` calls anywhere — all use `rich`
- [ ] No hardcoded paths or `/tmp` references
- [ ] `.env` is in `.gitignore`
- [ ] `reports/` is in `.gitignore`

---

## Quick Session Starter

When opening a new Claude Code session, paste this:

```
Read CLAUDE.md fully. Then read TASKS.md and find the first unchecked [ ] task.
Tell me which task you are starting, then implement it completely.
Run the test at the bottom of the task. If it passes, mark the task [x] in TASKS.md.
Then stop and wait for me to confirm before moving to the next task.
```
