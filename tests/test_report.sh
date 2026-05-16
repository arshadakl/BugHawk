#!/usr/bin/env bash
# tests/test_report.sh — generate report from mock findings.json

BUGHAWK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$BUGHAWK_DIR/lib/utils.sh"

PASS=0
FAIL=0

ok()   { echo -e "${GREEN}[PASS]${RESET} $1"; PASS=$((PASS+1)); }
fail() { echo -e "${RED}[FAIL]${RESET} $1"; FAIL=$((FAIL+1)); }

echo "=== test_report.sh ==="

OUTDIR=$(mktemp -d)
trap "rm -rf $OUTDIR" EXIT

# Build findings.json from mock data
source "$BUGHAWK_DIR/lib/aggregator.sh"
cp "$BUGHAWK_DIR/tests/mock_outputs/nuclei.json"     "$OUTDIR/nuclei.json"
cp "$BUGHAWK_DIR/tests/mock_outputs/httpx.json"      "$OUTDIR/httpx.json"
cp "$BUGHAWK_DIR/tests/mock_outputs/dalfox.json"     "$OUTDIR/dalfox.json"
cp "$BUGHAWK_DIR/tests/mock_outputs/ffuf.json"       "$OUTDIR/ffuf.json"
cp "$BUGHAWK_DIR/tests/mock_outputs/trufflehog.json" "$OUTDIR/trufflehog.json"
aggregate_findings "$OUTDIR" &>/dev/null

# Write mock ai_triage.json
python3 -c "
import json
findings = json.load(open('$OUTDIR/findings.json'))
triage = []
for i, f in enumerate(findings):
    triage.append({
        'id': f['id'],
        'is_real': f['severity'] in ('critical','high'),
        'ai_confidence': 0.9 if f['severity'] == 'critical' else 0.7,
        'ai_reason': 'Mock triage reason for testing.',
        'chain_id': 1 if f['severity'] == 'critical' and i < 2 else None,
        'cvss_score': '9.8' if f['severity'] == 'critical' else '7.0',
        'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
    })
print(json.dumps(triage, indent=2))
" > "$OUTDIR/ai_triage.json"

# Write mock chain analysis
cat > "$OUTDIR/chain_1.json" << 'EOF'
{
  "chain_title": "Log4Shell + Spring4Shell RCE Chain",
  "chain_severity": "critical",
  "attack_steps": [
    "Step 1: Trigger Log4Shell via JNDI in User-Agent header at /api/login",
    "Step 2: Use RCE to deploy Spring4Shell exploit payload via class loader manipulation",
    "Step 3: Achieve full server compromise with persistent backdoor"
  ],
  "combined_impact": "An unauthenticated attacker can chain both vulnerabilities to achieve full remote code execution and persistent access to the server.",
  "cvss_score": "10.0",
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
}
EOF

# Disable auto-open for test
OPEN_REPORT_AFTER=false
source "$BUGHAWK_DIR/lib/report.sh"
generate_report "https://example.com" "$OUTDIR"

# Test 1 — report.md created
if [ -f "$OUTDIR/report.md" ]; then
  ok "report.md created"
else
  fail "report.md not created"
fi

# Test 2 — non-empty
if [ -s "$OUTDIR/report.md" ]; then
  ok "report.md is non-empty"
else
  fail "report.md is empty"
fi

# Test 3 — contains summary section
if grep -q "## Summary" "$OUTDIR/report.md"; then
  ok "report.md has ## Summary section"
else
  fail "report.md missing ## Summary"
fi

# Test 4 — contains findings section
if grep -q "## Findings" "$OUTDIR/report.md"; then
  ok "report.md has ## Findings section"
else
  fail "report.md missing ## Findings"
fi

# Test 5 — contains target
if grep -q "example.com" "$OUTDIR/report.md"; then
  ok "report.md contains target"
else
  fail "report.md missing target"
fi

# Test 6 — exploit chain section present (we wrote chain_1.json)
if grep -q "Exploit Chains" "$OUTDIR/report.md"; then
  ok "report.md has Exploit Chains section"
else
  fail "report.md missing Exploit Chains"
fi

# Test 7 — CVSS score present
if grep -q "CVSS" "$OUTDIR/report.md"; then
  ok "report.md includes CVSS data"
else
  fail "report.md missing CVSS data"
fi

# Test 8 — merged findings.json has ai fields populated
ai_populated=$(python3 -c "
import json, sys
data = json.load(open('$OUTDIR/findings.json'))
populated = sum(1 for f in data if f.get('is_real') is not None)
print(populated)
")
if [ "$ai_populated" -gt 0 ]; then
  ok "Merged findings.json has $ai_populated AI-annotated findings"
else
  fail "Merged findings.json has no AI annotations"
fi

# Test 9 — empty findings produces report without crashing
OUTDIR2=$(mktemp -d)
trap "rm -rf $OUTDIR2" EXIT
echo "[]" > "$OUTDIR2/findings.json"
generate_report "https://empty.example.com" "$OUTDIR2" &>/dev/null
if [ -f "$OUTDIR2/report.md" ]; then
  ok "Empty findings produces report without crash"
else
  fail "Empty findings crashed report generation"
fi

echo ""
echo "Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
