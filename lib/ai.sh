#!/usr/bin/env bash
# lib/ai.sh — OpenRouter API calls, tier routing, exploit chain detection, triage

# ── Exploit Chain Detection ───────────────────────────────────────────────────
detect_exploit_chain() {
  local findings_file="$1"
  local types
  types=$(jq -r '[.[] | .type] | join(",")' "$findings_file" 2>/dev/null)

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

# ── Tier Router ───────────────────────────────────────────────────────────────
route_to_tier() {
  local findings_file="$1"

  # FORCE_TIER overrides all routing logic
  if [ -n "${FORCE_TIER:-}" ]; then
    echo "$FORCE_TIER"
    return
  fi

  local finding_count
  finding_count=$(jq length "$findings_file" 2>/dev/null || echo 0)

  local has_chain
  has_chain=$(detect_exploit_chain "$findings_file")

  local has_critical
  has_critical=$(jq '[.[] | select(.severity == "critical")] | length' "$findings_file" 2>/dev/null || echo 0)

  if [ "$has_chain" = "true" ] || [ "$has_critical" -gt 0 ]; then
    echo "3"
  elif [ "$finding_count" -gt "${TIER3_FINDING_THRESHOLD:-30}" ]; then
    echo "3"
  elif [ "$finding_count" -gt "${TIER2_FINDING_THRESHOLD:-10}" ]; then
    echo "2"
  else
    echo "1"
  fi
}

# ── Model for Tier ────────────────────────────────────────────────────────────
model_for_tier() {
  case "$1" in
    1) echo "${TIER1_MODEL:-google/gemma-3-27b-it:free}" ;;
    2) echo "${TIER2_MODEL:-meta-llama/llama-3.3-70b-instruct:free}" ;;
    3) echo "${TIER3_MODEL:-deepseek/deepseek-r1-0528:free}" ;;
    4) echo "${TIER4_MODEL:-anthropic/claude-sonnet-4-5}" ;;
    *) echo "${TIER1_MODEL:-google/gemma-3-27b-it:free}" ;;
  esac
}

# ── OpenRouter API Call ───────────────────────────────────────────────────────
call_openrouter() {
  local model="$1"
  local prompt="$2"
  local outdir="$3"
  local attempt=0

  while [ $attempt -lt "${OPENROUTER_RETRY_LIMIT:-3}" ]; do
    local response
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
      )" 2>/dev/null)

    local http_code body
    http_code=$(echo "$response" | tail -1)
    body=$(echo "$response" | head -n -1)

    if [ "$http_code" = "200" ]; then
      echo "$body" | jq -r '.choices[0].message.content'
      return 0
    elif [ "$http_code" = "429" ]; then
      log_warn "OpenRouter rate limit hit. Waiting ${OPENROUTER_RETRY_DELAY:-5}s..."
      sleep "${OPENROUTER_RETRY_DELAY:-5}"
      attempt=$((attempt + 1))
    elif [ "$http_code" = "402" ]; then
      log_warn "Model requires payment. Falling back to Tier 2..."
      model="${TIER2_MODEL:-meta-llama/llama-3.3-70b-instruct:free}"
      attempt=$((attempt + 1))
    else
      log_error "OpenRouter error: HTTP $http_code"
      # Strip API key from body before logging
      local safe_key
      safe_key=$(printf '%s\n' "$OPENROUTER_API_KEY" | sed 's/[[\.*^$()+?{|]/\\&/g')
      echo "$body" | sed "s|${safe_key}|[REDACTED]|g" >> "$outdir/errors.log"
      return 1
    fi
  done

  log_error "OpenRouter failed after ${OPENROUTER_RETRY_LIMIT:-3} retries"
  return 1
}

# ── Build Triage Prompt ───────────────────────────────────────────────────────
build_triage_prompt() {
  local target="$1"
  local findings_json="$2"

  cat << PROMPT
You are a senior bug bounty analyst and penetration tester.

Analyze the following automated tool findings from a security scan of ${target}.

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
${findings_json}
PROMPT
}

# ── Build Chain Analysis Prompt ───────────────────────────────────────────────
build_chain_prompt() {
  local chain_findings_json="$1"

  cat << PROMPT
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
${chain_findings_json}
PROMPT
}

# ── Build H1 Report Prompt ────────────────────────────────────────────────────
build_h1_prompt() {
  local finding_json="$1"
  local chain_json="${2:-null}"

  cat << PROMPT
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
${finding_json}

CHAIN CONTEXT (if applicable):
${chain_json}
PROMPT
}

# ── Validate JSON Response ────────────────────────────────────────────────────
validate_json() {
  local content="$1"
  echo "$content" | jq empty 2>/dev/null
}

# ── Run Triage ────────────────────────────────────────────────────────────────
run_triage() {
  local target="$1" outdir="$2" tier="$3" model="$4"
  local findings_json
  findings_json=$(cat "$outdir/findings.json")

  local prompt
  prompt=$(build_triage_prompt "$target" "$findings_json")

  local finding_count
  finding_count=$(jq length "$outdir/findings.json" 2>/dev/null || echo "?")
  log_info "AI tier $tier ($model) — triaging $finding_count findings for false positives + severity..."

  # Show spinner while waiting for AI response
  local ai_response ai_tmp
  ai_tmp=$(mktemp)
  { call_openrouter "$model" "$prompt" "$outdir" > "$ai_tmp"; } &
  local ai_pid=$!
  show_spinner "$ai_pid" "AI ($model): analysing findings, detecting exploit chains..."
  wait "$ai_pid" 2>/dev/null
  ai_response=$(cat "$ai_tmp" 2>/dev/null)
  rm -f "$ai_tmp"

  if validate_json "$ai_response" 2>/dev/null; then
    echo "$ai_response" > "$outdir/ai_triage.json"
    log_success "AI triage complete — saved to ai_triage.json"
  else
    log_warn "AI response was not valid JSON — saving to ai_triage_raw.txt"
    echo "$ai_response" > "$outdir/ai_triage_raw.txt"
  fi
}

# ── Run Chain Analysis ────────────────────────────────────────────────────────
run_chain_analysis() {
  local outdir="$1" tier="$2" model="$3"

  [ ! -f "$outdir/ai_triage.json" ] && return

  local chain_ids
  chain_ids=$(jq -r '[.[] | select(.chain_id != null) | .chain_id] | unique | .[]' \
    "$outdir/ai_triage.json" 2>/dev/null)

  [ -z "$chain_ids" ] && return

  log_info "Exploit chains detected — running chain analysis..."

  while IFS= read -r chain_id; do
    local chain_findings
    # Merge triage fields back with original findings for chain prompt
    chain_findings=$(python3 - "$outdir" "$chain_id" 2>/dev/null << 'PYEOF'
import json, sys
outdir   = sys.argv[1]
chain_id = int(sys.argv[2])
findings = json.load(open(f"{outdir}/findings.json"))
triage   = json.load(open(f"{outdir}/ai_triage.json"))
tmap     = {t["id"]: t for t in triage}
merged   = []
for f in findings:
    t = tmap.get(f["id"], {})
    if t.get("chain_id") == chain_id:
        f.update(t)
        merged.append(f)
print(json.dumps(merged, indent=2))
PYEOF
)

    [ -z "$chain_findings" ] && continue

    local prompt
    prompt=$(build_chain_prompt "$chain_findings")
    local chain_response
    chain_response=$(call_openrouter "$model" "$prompt" "$outdir")

    if validate_json "$chain_response" 2>/dev/null; then
      echo "$chain_response" > "$outdir/chain_${chain_id}.json"
      log_success "Chain $chain_id analysis saved to chain_${chain_id}.json"
    fi
  done <<< "$chain_ids"
}

# ── Run H1 Reports ────────────────────────────────────────────────────────────
run_h1_reports() {
  local outdir="$1"

  [ "${ENABLE_H1_REPORT:-true}" != "true" ] && return
  [ ! -f "$outdir/ai_triage.json" ] && return

  log_info "Generating HackerOne report writeups (Tier 4)..."
  local h1_model
  h1_model=$(model_for_tier 4)

  # Get IDs of critical/high real findings
  local crit_ids
  crit_ids=$(python3 - "$outdir" 2>/dev/null << 'PYEOF'
import json, sys
outdir = sys.argv[1]
findings = json.load(open(f"{outdir}/findings.json"))
triage   = json.load(open(f"{outdir}/ai_triage.json"))
tmap     = {t["id"]: t for t in triage}
for f in findings:
    t = tmap.get(f["id"], {})
    if t.get("is_real") and f.get("severity") in ("critical","high"):
        print(f["id"])
PYEOF
)

  [ -z "$crit_ids" ] && return

  while IFS= read -r fid; do
    local finding_json chain_json="null"
    finding_json=$(python3 - "$outdir" "$fid" 2>/dev/null << 'PYEOF'
import json, sys
outdir = sys.argv[1]
fid    = int(sys.argv[2])
findings = json.load(open(f"{outdir}/findings.json"))
triage   = json.load(open(f"{outdir}/ai_triage.json"))
tmap     = {t["id"]: t for t in triage}
for f in findings:
    if f["id"] == fid:
        f.update(tmap.get(fid, {}))
        print(json.dumps(f, indent=2))
        break
PYEOF
)

    # Include chain context if this finding is part of a chain
    local cid
    cid=$(jq -r --argjson fid "$fid" '.[] | select(.id == $fid) | .chain_id // "null"' "$outdir/ai_triage.json" 2>/dev/null)
    if [ "$cid" != "null" ] && [ -f "$outdir/chain_${cid}.json" ]; then
      chain_json=$(cat "$outdir/chain_${cid}.json")
    fi

    local prompt
    prompt=$(build_h1_prompt "$finding_json" "$chain_json")
    local h1_response
    h1_response=$(call_openrouter "$h1_model" "$prompt" "$outdir")

    if [ -n "$h1_response" ]; then
      local ftype
      ftype=$(python3 - "$outdir" "$fid" 2>/dev/null << 'PYEOF'
import json, sys
outdir = sys.argv[1]
fid    = int(sys.argv[2])
findings = json.load(open(f"{outdir}/findings.json"))
for f in findings:
    if f["id"] == fid:
        print(f.get("type","finding").replace("/","_").replace(" ","_"))
        break
PYEOF
      ) || ftype="finding_${fid}"
      echo "$h1_response" > "$outdir/h1_${ftype}.md"
      log_success "H1 report: h1_${ftype}.md"
    fi
  done <<< "$crit_ids"
}

# ── Main AI Triage Runner ─────────────────────────────────────────────────────
run_ai_triage() {
  local target="$1" outdir="$2"

  # Check API key
  if [ -z "${OPENROUTER_API_KEY:-}" ]; then
    log_warn "OPENROUTER_API_KEY not set — skipping AI triage"
    log_warn "Set it in config.sh to enable AI analysis"
    return
  fi

  # Check jq available
  if ! command -v jq &>/dev/null; then
    log_error "jq required for AI triage — not found"
    return 1
  fi

  # Check findings exist
  if [ ! -s "$outdir/findings.json" ]; then
    log_warn "findings.json empty — skipping AI triage"
    return
  fi

  local tier
  tier=$(route_to_tier "$outdir/findings.json")
  local model
  model=$(model_for_tier "$tier")

  log_info "AI tier: $tier — $model"

  run_triage "$target" "$outdir" "$tier" "$model"
  run_chain_analysis "$outdir" "$tier" "$model"
  run_h1_reports "$outdir"
}
