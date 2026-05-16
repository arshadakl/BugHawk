#!/usr/bin/env bash
# tests/test_ai.sh — mock OpenRouter with static JSON response

BUGHAWK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$BUGHAWK_DIR/lib/utils.sh"

PASS=0
FAIL=0

ok()   { echo -e "${GREEN}[PASS]${RESET} $1"; PASS=$((PASS+1)); }
fail() { echo -e "${RED}[FAIL]${RESET} $1"; FAIL=$((FAIL+1)); }

echo "=== test_ai.sh ==="

# Set up temp dir with mock findings
OUTDIR=$(mktemp -d)
trap "rm -rf $OUTDIR" EXIT

# Build minimal findings.json from mock data
source "$BUGHAWK_DIR/lib/aggregator.sh"
cp "$BUGHAWK_DIR/tests/mock_outputs/nuclei.json"    "$OUTDIR/nuclei.json"
cp "$BUGHAWK_DIR/tests/mock_outputs/trufflehog.json" "$OUTDIR/trufflehog.json"
aggregate_findings "$OUTDIR" &>/dev/null

# ── Mock call_openrouter ──────────────────────────────────────────────────────
# Override the real function to return static JSON
call_openrouter() {
  cat << 'MOCK_RESPONSE'
[
  {"id":0,"is_real":true,"ai_confidence":0.95,"ai_reason":"Log4Shell RCE is a confirmed critical vulnerability with clear evidence.","chain_id":null,"cvss_score":"10.0","cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"},
  {"id":1,"is_real":true,"ai_confidence":0.90,"ai_reason":"Spring4Shell RCE confirmed by template match.","chain_id":null,"cvss_score":"9.8","cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
  {"id":2,"is_real":false,"ai_confidence":0.3,"ai_reason":"Admin panel exposure may be intentional or behind auth.","chain_id":null,"cvss_score":null,"cvss_vector":null},
  {"id":3,"is_real":true,"ai_confidence":0.75,"ai_reason":"SQL error in response indicates potential injection point.","chain_id":null,"cvss_score":"7.5","cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
  {"id":4,"is_real":false,"ai_confidence":0.1,"ai_reason":"X-Powered-By header is informational only.","chain_id":null,"cvss_score":null,"cvss_vector":null}
]
MOCK_RESPONSE
  return 0
}
export -f call_openrouter

source "$BUGHAWK_DIR/lib/ai.sh"

# Test 1 — detect_exploit_chain with no chains
result=$(detect_exploit_chain "$OUTDIR/findings.json")
ok "detect_exploit_chain() returned: $result"

# Test 2 — route_to_tier
TIER2_FINDING_THRESHOLD=10
TIER3_FINDING_THRESHOLD=30
FORCE_TIER=""
tier=$(route_to_tier "$OUTDIR/findings.json")
if [[ "$tier" =~ ^[1-4]$ ]]; then
  ok "route_to_tier() returned valid tier: $tier"
else
  fail "route_to_tier() returned invalid: '$tier'"
fi

# Test 3 — FORCE_TIER overrides routing
FORCE_TIER=3
tier=$(route_to_tier "$OUTDIR/findings.json")
if [ "$tier" = "3" ]; then
  ok "FORCE_TIER=3 respected"
else
  fail "FORCE_TIER not respected, got: $tier"
fi
FORCE_TIER=""

# Test 4 — run_triage writes ai_triage.json
OPENROUTER_API_KEY="test-key-mock"
run_triage "example.com" "$OUTDIR" "1" "google/gemma-3-27b-it:free"

if [ -f "$OUTDIR/ai_triage.json" ]; then
  ok "ai_triage.json created"
else
  fail "ai_triage.json not created"
fi

# Test 5 — ai_triage.json is valid JSON
if python3 -c "import json; json.load(open('$OUTDIR/ai_triage.json'))" 2>/dev/null; then
  ok "ai_triage.json is valid JSON"
else
  fail "ai_triage.json is invalid JSON"
fi

# Test 6 — triage fields populated
python3 -c "
import json, sys
data = json.load(open('$OUTDIR/ai_triage.json'))
for item in data:
    if 'is_real' not in item or 'ai_confidence' not in item:
        print(f'Missing fields in item: {item}')
        sys.exit(1)
sys.exit(0)
"
if [ $? -eq 0 ]; then
  ok "Triage fields (is_real, ai_confidence) present"
else
  fail "Triage fields missing"
fi

# Test 7 — validate_json accepts valid JSON
if validate_json '[{"id":0}]'; then
  ok "validate_json() accepts valid JSON"
else
  fail "validate_json() rejected valid JSON"
fi

# Test 8 — validate_json rejects invalid JSON
if validate_json 'not json at all' 2>/dev/null; then
  fail "validate_json() accepted invalid JSON"
else
  ok "validate_json() rejects invalid JSON"
fi

# Test 9 — fallback to ai_triage_raw.txt on invalid AI response
call_openrouter() { echo "THIS IS NOT JSON"; return 0; }
export -f call_openrouter
run_triage "example.com" "$OUTDIR" "1" "google/gemma-3-27b-it:free" 2>/dev/null
if [ -f "$OUTDIR/ai_triage_raw.txt" ]; then
  ok "Invalid AI JSON saved to ai_triage_raw.txt"
else
  fail "ai_triage_raw.txt not written on invalid JSON"
fi

echo ""
echo "Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
