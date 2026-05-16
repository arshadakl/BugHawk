# BugHawk

Autonomous bug bounty scanner. One command, zero manual setup, AI-assisted triage.

```
  ██████╗ ██╗   ██╗ ██████╗ ██╗  ██╗ █████╗ ██╗    ██╗██╗  ██╗
  ██╔══██╗██║   ██║██╔════╝ ██║  ██║██╔══██╗██║    ██║██║ ██╔╝
  ██████╔╝██║   ██║██║  ███╗███████║███████║██║ █╗ ██║█████╔╝
  ██╔══██╗██║   ██║██║   ██║██╔══██║██╔══██║██║███╗██║██╔═██╗
  ██████╔╝╚██████╔╝╚██████╔╝██║  ██║██║  ██║╚███╔███╔╝██║  ██╗
  ╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝
```

## What it does

Give BugHawk a URL, domain, or IP. It:

1. Auto-installs all required tools (subfinder, httpx, nuclei, sqlmap, dalfox, ffuf, and more)
2. Runs full recon in parallel (subdomains, live hosts, ports, historical URLs, parameters)
3. Scans for vulnerabilities in parallel (nuclei, SQLi, XSS, directory fuzzing)
4. Detects secrets (trufflehog, gitleaks, sensitive path exposure)
5. Aggregates all findings into a normalized `findings.json`
6. Triages with AI — filters false positives, scores severity, detects exploit chains
7. Generates a Markdown report + HackerOne-ready writeups for critical findings

**Tools scan. AI thinks. You ship reports.**

## Requirements

- Linux, macOS, or Windows (WSL2 recommended; Git Bash partial support)
- `bash` 4+
- `curl`, `python3`, `git` (pre-installed on most systems)
- An OpenRouter API key (free at [openrouter.ai](https://openrouter.ai))

Everything else is auto-installed on first run.

## Quick Start

```bash
git clone https://github.com/arshadakl/BugHawk
cd BugHawk
cp config.example.sh config.sh
nano config.sh   # add your OpenRouter API key
chmod +x bughawk.sh
./bughawk.sh https://example.com
```

## Usage

```bash
./bughawk.sh <target> [options]
```

### Examples

```bash
# Full scan (default)
./bughawk.sh https://example.com

# Fast scan — recon + nuclei only
./bughawk.sh https://example.com --depth quick

# Scan including all subdomains
./bughawk.sh https://example.com --scope subdomains

# Skip slow tools, force Tier 3 AI
./bughawk.sh https://example.com --skip-scan sqlmap,dalfox --ai-tier 3

# Quiet mode, skip tool install check on repeat run
./bughawk.sh https://example.com --quiet --skip-install-check

# Internal network target
./bughawk.sh http://192.168.1.1 --allow-internal

# Raw findings only, no AI
./bughawk.sh https://example.com --no-ai

# Custom output directory
./bughawk.sh https://example.com --output /tmp/scan_results
```

### All Flags

| Flag | Description |
|------|-------------|
| `--scope single` | Scan only the given domain (default) |
| `--scope subdomains` | Also scan all discovered subdomains |
| `--scope wildcard` | Treat *.target.com as in-scope |
| `--depth quick` | Recon + nuclei only, skip sqlmap/dalfox/ffuf |
| `--depth full` | Full pipeline (default) |
| `--skip-scan <tool>` | Skip a tool, comma-separated (e.g. `sqlmap,dalfox`) |
| `--skip-install-check` | Skip tool check (faster on repeat runs) |
| `--allow-internal` | Allow scanning private IP ranges |
| `--ai-tier <1-4>` | Force AI tier (overrides auto-routing) |
| `--no-ai` | Skip AI triage, just produce raw findings |
| `--output <dir>` | Custom output directory |
| `--quiet` | Suppress tool stdout |
| `--no-report` | Skip report generation |
| `--help` | Show help |

## AI Tiers

| Tier | Model | Cost | When |
|------|-------|------|------|
| 1 | Gemma 3 27B | Free | <10 findings, no critical |
| 2 | Llama 3.3 70B | Free | 10–30 findings |
| 3 | DeepSeek R1 | Free* | >30 findings, critical, exploit chains |
| 4 | Claude Sonnet | Paid | HackerOne report writing (opt-in) |

*Currently free on OpenRouter.

## Output Structure

```
output/example_com_20250516_1430/
├── subdomains.txt       # subfinder results
├── httpx.json           # live hosts with tech stack
├── whois.txt            # registrar / ASN info
├── nmap.txt / nmap.xml  # port scan results
├── wayback.txt          # historical URLs
├── params_*.txt         # gf pattern matches (xss/sqli/lfi/ssrf/redirect)
├── nuclei.json          # vulnerability findings
├── dalfox.json          # XSS findings
├── sqlmap/              # SQLi results
├── ffuf.json            # directory fuzzing
├── trufflehog.json      # secrets in HTTP responses
├── findings.json        # all findings normalized
├── ai_triage.json       # AI analysis (confidence, chains, CVSS)
├── report.md            # final human-readable report
├── h1_*.md              # HackerOne writeups per critical/high
└── errors.log           # tool failures (non-fatal)
```

## Platform Support

| Platform | Support |
|----------|---------|
| Ubuntu / Debian | Full |
| Kali Linux | Full |
| Arch Linux | Full |
| macOS | Full |
| Windows WSL2 | Full |
| Windows Git Bash | Partial |

## License

MIT — for authorized security testing only.
