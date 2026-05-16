#!/usr/bin/env bash
# lib/aggregator.sh — merge all tool outputs into normalized findings.json

aggregate_findings() {
  local outdir="$1"

  log_info "Aggregating tool outputs..."

  python3 - "$outdir" << 'PYEOF'
import json, os, sys, re
from pathlib import Path

outdir = sys.argv[1]
findings = []
fid = 0

def add(tool, severity, ftype, url, parameter, evidence, description, raw):
    global fid
    findings.append({
        "id": fid,
        "tool": tool,
        "severity": severity.lower(),
        "type": ftype,
        "url": url,
        "parameter": parameter,
        "evidence": evidence,
        "description": description,
        "raw": raw,
        "is_real": None,
        "ai_confidence": None,
        "ai_reason": None,
        "chain_id": None,
        "cvss_score": None,
        "cvss_vector": None,
    })
    fid += 1

# ── Nuclei (NDJSON — one JSON object per line) ────────────────────────────────
nuclei_file = Path(outdir) / "nuclei.json"
if nuclei_file.exists() and nuclei_file.stat().st_size > 0:
    for line in nuclei_file.read_text(errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
            if not isinstance(r, dict):
                continue
            url = r.get("host") or r.get("matched-at", "")
            info = r.get("info", {})
            add(
                tool="nuclei",
                severity=info.get("severity", "info"),
                ftype=r.get("template-id", "nuclei-finding"),
                url=url,
                parameter=r.get("matcher-name", ""),
                evidence=str(r.get("extracted-results", r.get("curl-command", "")))[:500],
                description=info.get("name", ""),
                raw=line[:500],
            )
        except json.JSONDecodeError:
            pass

# ── httpx ─────────────────────────────────────────────────────────────────────
httpx_file = Path(outdir) / "httpx.json"
if httpx_file.exists() and httpx_file.stat().st_size > 0:
    for line in httpx_file.read_text(errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
            if not isinstance(r, dict):
                continue
            status = r.get("status_code", 0)
            tech = r.get("tech", [])
            # Only report interesting status codes or known risky tech
            risky_tech = [t for t in tech if any(
                x in t.lower() for x in ["apache/2.2", "php/5", "iis/6", "iis/7", "struts"]
            )]
            if risky_tech or status in [401, 403, 500]:
                add(
                    tool="httpx",
                    severity="info",
                    ftype="http-probe",
                    url=r.get("url", ""),
                    parameter="",
                    evidence=f"status={status} tech={','.join(tech)}",
                    description=f"Live host: {r.get('title','')}",
                    raw=line[:500],
                )
        except json.JSONDecodeError:
            pass

# ── Dalfox ────────────────────────────────────────────────────────────────────
dalfox_file = Path(outdir) / "dalfox.json"
if dalfox_file.exists() and dalfox_file.stat().st_size > 0:
    try:
        data = json.loads(dalfox_file.read_text(errors="ignore"))
        items = data if isinstance(data, list) else [data]
        for r in items:
            add(
                tool="dalfox",
                severity="high",
                ftype="xss",
                url=r.get("data", {}).get("url", r.get("url", "")),
                parameter=r.get("data", {}).get("param", r.get("param", "")),
                evidence=r.get("data", {}).get("payload", r.get("payload", ""))[:300],
                description="Cross-site scripting vulnerability detected by dalfox",
                raw=json.dumps(r)[:500],
            )
    except (json.JSONDecodeError, Exception):
        pass

# ── SQLMap (reads log files from sqlmap output dir) ───────────────────────────
sqlmap_dir = Path(outdir) / "sqlmap"
if sqlmap_dir.exists():
    for log_file in sqlmap_dir.rglob("*.log"):
        try:
            content = log_file.read_text(errors="ignore")
            if "sqlmap identified the following injection point" in content:
                url_match   = re.search(r"URL:\s+(\S+)", content)
                param_match = re.search(r"Parameter:\s+(\S+)", content)
                idx = content.find("sqlmap identified")
                add(
                    tool="sqlmap",
                    severity="critical",
                    ftype="sqli",
                    url=url_match.group(1) if url_match else str(log_file),
                    parameter=param_match.group(1) if param_match else "",
                    evidence=content[idx:idx+400] if idx >= 0 else "",
                    description="SQL injection confirmed by sqlmap",
                    raw=content[:500],
                )
        except Exception:
            pass

# ── ffuf ──────────────────────────────────────────────────────────────────────
ffuf_file = Path(outdir) / "ffuf.json"
if ffuf_file.exists() and ffuf_file.stat().st_size > 0:
    try:
        data = json.loads(ffuf_file.read_text(errors="ignore"))
        results = data.get("results", [])
        for r in results:
            status = r.get("status", 0)
            # Only interesting codes (not just 200 redirects to homepage)
            if status in [200, 201, 301, 302, 403, 405]:
                add(
                    tool="ffuf",
                    severity="info",
                    ftype="directory-found",
                    url=r.get("url", ""),
                    parameter="",
                    evidence=f"status={status} size={r.get('length',0)} words={r.get('words',0)}",
                    description=f"Directory/endpoint discovered: {r.get('input',{}).get('FUZZ','')}",
                    raw=json.dumps(r)[:500],
                )
    except (json.JSONDecodeError, Exception):
        pass

# ── Trufflehog ────────────────────────────────────────────────────────────────
trufflehog_file = Path(outdir) / "trufflehog.json"
if trufflehog_file.exists() and trufflehog_file.stat().st_size > 0:
    for line in trufflehog_file.read_text(errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
            det = r.get("DetectorName", r.get("detector_name", "secret"))
            add(
                tool="trufflehog",
                severity="critical",
                ftype=f"secret-{det.lower()}",
                url=r.get("SourceMetadata", {}).get("Data", {}).get("Http", {}).get("Link", ""),
                parameter="",
                evidence=f"Detector: {det} | Verified: {r.get('Verified', r.get('verified', False))}",
                description=f"Secret detected: {det}",
                raw=json.dumps(r)[:500],
            )
        except (json.JSONDecodeError, Exception):
            pass

# ── Gitleaks ──────────────────────────────────────────────────────────────────
gitleaks_file = Path(outdir) / "gitleaks.json"
if gitleaks_file.exists() and gitleaks_file.stat().st_size > 0:
    try:
        data = json.loads(gitleaks_file.read_text(errors="ignore"))
        items = data if isinstance(data, list) else []
        for r in items:
            add(
                tool="gitleaks",
                severity="critical",
                ftype=f"secret-{r.get('RuleID','leak').lower()}",
                url=r.get("File", ""),
                parameter="",
                evidence=r.get("Secret", "")[:100] + " [REDACTED]",
                description=f"Secret leaked in git: {r.get('Description','')}",
                raw=json.dumps({k: v for k, v in r.items() if k != "Secret"})[:500],
            )
    except (json.JSONDecodeError, Exception):
        pass

# ── manual_findings.txt (pipe-delimited) ──────────────────────────────────────
manual_file = Path(outdir) / "manual_findings.txt"
if manual_file.exists() and manual_file.stat().st_size > 0:
    for line in manual_file.read_text(errors="ignore").splitlines():
        parts = line.strip().split("|", 3)
        if len(parts) == 4:
            severity, ftype, url, evidence = parts
            add(
                tool="manual",
                severity=severity.lower(),
                ftype=ftype,
                url=url,
                parameter="",
                evidence=evidence,
                description=f"{ftype} detected at {url}",
                raw=line,
            )

# ── Write findings.json ───────────────────────────────────────────────────────
out_file = Path(outdir) / "findings.json"
with open(out_file, "w") as f:
    json.dump(findings, f, indent=2)

# ── Print severity summary ────────────────────────────────────────────────────
from collections import Counter
counts = Counter(f["severity"] for f in findings)
total = len(findings)
print(f"  Total findings: {total}")
for sev in ["critical", "high", "medium", "low", "info"]:
    if counts[sev]:
        print(f"    {sev.upper():10} {counts[sev]}")

PYEOF

  local exit_code=$?
  if [ $exit_code -ne 0 ]; then
    log_tool_error "aggregator" "Python script failed (exit $exit_code)"
    # Write empty findings.json so downstream doesn't crash
    echo "[]" > "$outdir/findings.json"
  fi

  [ -s "$outdir/findings.json" ] \
    && log_success "findings.json written" \
    || log_warn "findings.json is empty — no findings from any tool"
}
