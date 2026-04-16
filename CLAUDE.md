# BugHawk — Claude Code Instructions

## What This Project Is
Windows-native autonomous bug bounty scanner. Python CLI. Chains 15 open-source security
tools. Multi-provider AI routing (free models first, Claude only for chain detection and
H1 reports). Targets: HackerOne and Bugcrowd hunters on Windows 11.

## Read Before Every Session
1. Check `TASKS.md` — find the first unchecked task. Start there. Do not start from scratch.
2. Check existing files before creating anything. Never duplicate a file.
3. Run the test at the bottom of each task before marking it done.

---

## Absolute Rules — Never Break These

### Code Rules
- NEVER use `print()` — always use `from rich.console import Console; console = Console()`
- NEVER hardcode `/tmp` — use `tempfile.NamedTemporaryFile()` 
- NEVER use string paths — always use `pathlib.Path`
- NEVER use `shell=True` in subprocess — always pass a list
- NEVER write a file over 300 lines — split into smaller modules
- NEVER skip type hints — every function arg and return must be typed
- NEVER leave a function without a docstring

### Windows Rules (apply to every subprocess call)
```python
# Always add this to subprocess.run() on Windows:
creationflags=subprocess.CREATE_NO_WINDOW

# Always add GOBIN to PATH at module level:
import os
from pathlib import Path
GOBIN = Path(os.environ.get("USERPROFILE", "")) / "go" / "bin"
os.environ["PATH"] += os.pathsep + str(GOBIN)

# Always open files with explicit encoding:
open(path, "w", encoding="utf-8")
```

### AI Cost Rules
- NEVER call `claude-sonnet-4-6` for tasks in the FREE tier — check `PLAN.md` routing table
- ALWAYS add prompt caching to Claude calls — add `cache_control: {"type": "ephemeral"}` to system prompt
- ALWAYS log estimated cost before making any paid API call
- NEVER call any AI model in a loop without rate limit checks

### Testing Rules
- After writing each file, run its test immediately
- If a test fails, fix it before touching any other file
- Do not proceed to next task until current task test passes

---

## Project Structure (never add files outside this)

```
bughawk/
├── CLAUDE.md           ← you are here
├── PLAN.md             ← architecture + schemas + model routing
├── TASKS.md            ← current phase task list (tick as you go)
├── bughawk.py          ← CLI entry point only
├── daemon.py           ← monitoring daemon
├── api_server.py       ← Flask API for Burp integration
├── config.yaml         ← all config
├── requirements.txt
├── .env.example
├── core/               ← recon, setup, surface mapping
├── modules/            ← 9 scan modules
├── ai/                 ← router, client, prompts
├── integrations/       ← burp, telegram, discord
├── output/             ← terminal + HTML report
├── db/                 ← SQLite
├── wordlists/          ← auto-downloaded
└── reports/            ← all output (gitignored)
```

## How to Run the Project
```cmd
# First run — check and install all tools
python bughawk.py --setup

# Quick scan
python bughawk.py --target https://example.com --mode quick

# Full agent scan with AI
python bughawk.py --target https://example.com --mode agent --ai

# IDOR test with two sessions
python bughawk.py --target https://example.com --mode web --ai ^
  --session-a "token=eyJ..." --session-b "token=eyJ..."
```

## Python Environment
- Python 3.10+ required
- Install deps: `pip install -r requirements.txt`
- `.env` file must exist with API keys — see `.env.example`
- Go 1.21+ required for subfinder, httpx, nuclei, dalfox, ffuf, katana, gau, getJS

## Key Dependencies
```
anthropic>=0.40.0       # Anthropic SDK
openai>=1.50.0          # OpenRouter uses OpenAI-compatible API
rich>=13.7.0            # terminal UI — use this everywhere
jinja2>=3.1.4           # HTML reports + prompt templates
pyyaml>=6.0.1           # config.yaml parsing
sqlalchemy>=2.0.30      # SQLite ORM
flask>=3.0.3            # Burp integration API server
websocket-client>=1.8.0 # WebSocket scanner
python-dotenv>=1.0.1    # .env loading
colorama>=0.4.6         # Windows color support — init() at startup
```

## AI Model Quick Reference
```python
# FREE (OpenRouter) — use for most tasks
"qwen/qwen3-coder-480b-a35b:free"         # parsing, structuring JSON
"nvidia/nemotron-3-super:free"            # recon analysis, tech detection
"deepseek/deepseek-r1:free"               # IDOR diffing, reasoning
"meta-llama/llama-3.3-70b-instruct:free"  # CVSS, next steps
"openrouter/free"                          # auto-router fallback

# CHEAP (OpenRouter) — when free hits rate limits
"deepseek/deepseek-v3-2"                  # $0.14/M — security reasoning
"google/gemini-flash-1.5"                 # fast classification

# PREMIUM (Anthropic) — only these 3 tasks
"claude-sonnet-4-6"   # → triage_brain, chain_detect_full, draft_h1_report
"claude-haiku-4-5-20251001"  # → mid-tier fallback only
```

## Unified Finding Schema
Every module must return findings as this dataclass (defined in `modules/base_module.py`):
```python
@dataclass
class Finding:
    id: str                      # uuid4
    tool: str                    # which tool found it
    module: str                  # which BugHawk module
    title: str
    vuln_class: str              # XSS | IDOR | SQLi | SSRF | CORS | JWT | etc
    target_url: str
    endpoint: str
    parameter: str | None
    method: str
    payload: str | None
    request: str | None
    response_snippet: str | None
    severity: str                # critical | high | medium | low | info
    cvss_score: float | None
    cvss_vector: str | None
    confidence: int              # 0-100
    verified: bool               # passed 3-pass check
    chain_candidate: bool
    chain_ids: list[str]
    timestamp: str               # ISO 8601
    ai_explanation: str | None
    ai_next_steps: list[str]
    ai_h1_draft: str | None
```

## When You Get Stuck
- Cannot find a tool binary → check if GOBIN is in PATH, run `go install` again
- AI call returns non-JSON → wrap in try/except, strip markdown fences, retry once
- Subprocess returns empty stdout → check stderr, the tool may need different flags
- Rate limit hit on free model → switch to next in FALLBACK_ORDER in `ai/router.py`
- Windows path errors → replace all string paths with `pathlib.Path` objects
