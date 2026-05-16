# BugHawk — Architecture Plan

## Overview

BugHawk is a bash-orchestrated autonomous security scanner. One command, zero manual setup,
AI-assisted triage. Tools do scanning. AI does analysis.

## Design Decisions

### 1. Pure Bash Orchestration
All pipeline logic lives in bash. No Python for orchestration — only for JSON aggregation
(heredoc embedded in bash, executed via `python3 -c`). Avoids dependency on node, ruby, etc.
Bash is universally available on pentesting targets and CI systems.

### 2. Parallel-First Execution
Every phase that can run concurrent jobs does so via background `&` + `PIDS[]` array.
No sequential scans. This cuts scan time 3-5x on a real target.
Spinner shows progress without blocking.

### 3. AI as Analyst, Not Operator
AI never runs commands. It receives normalized JSON from tools and reasons about it.
This prevents prompt-injection attacks where a malicious server tricks AI into running commands.
The finding schema is fixed — AI can only fill its designated fields.

### 4. Tier-Based AI Routing
Four tiers, three free. Routing is automatic based on finding count + chain detection.
Paid tier (Claude Sonnet) only for HackerOne report writing, and only if opted in.
This keeps 80%+ of scans completely free.

### 5. Schema-First Aggregation
Every tool outputs to its own raw file. Aggregator normalizes all into one `findings.json`.
AI sees only normalized data. Report reads only normalized data.
This decouples tools from AI and reporting — swap any component independently.

### 6. Never Abort on Partial Failure
Tool fails → log to `errors.log` → continue. This is critical for real pentests
where some tools may time out or fail against hardened targets.
A partial result is better than no result.

### 7. Zero Trust on Windows
Windows Git Bash lacks many Linux tools. setup.sh detects env and adjusts install strategy.
Go tools install identically everywhere. Binary downloads handle gitleaks/trufflehog on Windows.
The script warns about unsupported tools and continues.

---

## Pipeline Architecture

```
bughawk.sh
  │
  ├─ [Phase 2] setup.sh      → tool check + auto-install (all 18 tools)
  │
  ├─ [Phase 3] recon.sh      → subfinder | httpx | whois | nmap | waybackurls | gf | paramspider
  │              └─ PARALLEL via PIDS[]
  │
  ├─ [Phase 4] scan.sh       → nuclei | dalfox | sqlmap | ffuf
  │              └─ PARALLEL via PIDS[]
  │
  ├─ [Phase 5] secrets.sh    → trufflehog | gitleaks | sensitive path loop
  │              └─ PARALLEL via PIDS[]
  │
  ├─ [Phase 6] aggregator.sh → Python heredoc → findings.json
  │              └─ Normalizes: nuclei + httpx + dalfox + sqlmap + ffuf + trufflehog + gitleaks + manual
  │
  ├─ [Phase 7] ai.sh         → route_to_tier() → call_openrouter() → ai_triage.json
  │              └─ Chain analysis if chain_id detected
  │              └─ H1 report prompt if critical/high + ENABLE_H1_REPORT
  │
  └─ [Phase 8] report.sh     → Python heredoc → report.md + h1_*.md
```

---

## File Layout Rationale

- `bughawk.sh` is orchestrator ONLY — no tool logic, no parsing
- Each `lib/*.sh` owns exactly one phase
- `utils.sh` is shared infrastructure — sourced first by all lib files
- `config.sh` is never committed — `config.example.sh` is the template
- `output/<target>_YYYYMMDD_HHMM/` isolates runs — no cross-contamination between scans
- `tests/mock_outputs/` enables unit testing without real network calls

---

## Security Controls in Code

| Control | Implementation |
|---------|----------------|
| Legal disclaimer | First-run check for `~/.bughawk_accepted`, require `I AGREE` |
| Private IP block | Regex check in `bughawk.sh` before any tool runs |
| No interactive sqlmap | Always `--batch` flag |
| Rate limiting | `--max-time 10` on all curl, `-t $FFUF_THREADS` on ffuf |
| API key protection | Read only from `$OPENROUTER_API_KEY`, never written to any output file |
| Tool failure isolation | `set -euo pipefail` only in `bughawk.sh`, lib files continue on error |

---

## Build Order (Phases)

| Phase | File | Depends On |
|-------|------|------------|
| 1 | Scaffold (bughawk.sh, utils.sh, config.example.sh, .gitignore, README.md) | nothing |
| 2 | setup.sh | utils.sh |
| 3 | recon.sh | utils.sh, setup.sh |
| 4 | scan.sh | utils.sh, recon.sh |
| 5 | secrets.sh | utils.sh — **ask first** |
| 6 | aggregator.sh | recon + scan + secrets output |
| 7 | ai.sh | aggregator.sh — **ask first** |
| 8 | report.sh | ai.sh — **ask first** |
| 9 | tests/ | all phases |
| 10 | wordlists/ + payloads/ | scan.sh |
| 11 | Polish & UX | all phases |

---

## Key Invariants (Never Break)

1. Every `&` job → `PIDS+=($!)` → `wait "$pid"` in loop
2. Every file used as input → `[ -s file ]` guard first
3. Every AI prompt → exact text from CLAUDE.md, no rewrites
4. Every finding → exact schema from CLAUDE.md, no extra fields
5. API key → never in logs, never in output files
6. Functions → ≤50 lines, split helpers if longer
