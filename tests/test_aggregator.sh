#!/usr/bin/env bash
# tests/test_aggregator.sh — parse mock outputs, validate findings.json schema

BUGHAWK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$BUGHAWK_DIR/lib/utils.sh"

PASS=0
FAIL=0

ok()   { echo -e "${GREEN}[PASS]${RESET} $1"; PASS=$((PASS+1)); }
fail() { echo -e "${RED}[FAIL]${RESET} $1"; FAIL=$((FAIL+1)); }

echo "=== test_aggregator.sh ==="

# Set up temp output dir with mock data
OUTDIR=$(mktemp -d)
trap "rm -rf $OUTDIR" EXIT

cp "$BUGHAWK_DIR/tests/mock_outputs/nuclei.json"    "$OUTDIR/nuclei.json"
cp "$BUGHAWK_DIR/tests/mock_outputs/httpx.json"     "$OUTDIR/httpx.json"
cp "$BUGHAWK_DIR/tests/mock_outputs/dalfox.json"    "$OUTDIR/dalfox.json"
cp "$BUGHAWK_DIR/tests/mock_outputs/ffuf.json"      "$OUTDIR/ffuf.json"
cp "$BUGHAWK_DIR/tests/mock_outputs/trufflehog.json" "$OUTDIR/trufflehog.json"

# Add a manual_findings.txt
cat > "$OUTDIR/manual_findings.txt" << 'EOF'
CRITICAL|git_exposure|https://example.com/.git/config|.git directory publicly exposed
HIGH|sensitive_path|https://example.com/.env|HTTP 200
EOF

# Source and run aggregator
source "$BUGHAWK_DIR/lib/aggregator.sh"
aggregate_findings "$OUTDIR"

# Test 1 — findings.json created
if [ -f "$OUTDIR/findings.json" ]; then
  ok "findings.json created"
else
  fail "findings.json not created"
fi

# Test 2 — valid JSON
if python3 -c "import json; json.load(open('$OUTDIR/findings.json'))" 2>/dev/null; then
  ok "findings.json is valid JSON"
else
  fail "findings.json is invalid JSON"
fi

# Test 3 — is array
is_array=$(python3 -c "import json; d=json.load(open('$OUTDIR/findings.json')); print(isinstance(d,list))")
if [ "$is_array" = "True" ]; then
  ok "findings.json is a JSON array"
else
  fail "findings.json is not a JSON array"
fi

# Test 4 — findings count > 0
count=$(python3 -c "import json; print(len(json.load(open('$OUTDIR/findings.json'))))")
if [ "$count" -gt 0 ]; then
  ok "findings count = $count (> 0)"
else
  fail "findings count = 0"
fi

# Test 5 — required schema fields present on every finding
python3 << 'PYEOF'
import json, sys
required = ["id","tool","severity","type","url","parameter","evidence","description","raw",
            "is_real","ai_confidence","ai_reason","chain_id","cvss_score","cvss_vector"]
data = json.load(open(sys.argv[1]))
bad = []
for f in data:
    for k in required:
        if k not in f:
            bad.append(f"id={f.get('id','?')} missing field '{k}'")
if bad:
    print("SCHEMA ERRORS:\n" + "\n".join(bad))
    sys.exit(1)
sys.exit(0)
PYEOF "$OUTDIR/findings.json"
if [ $? -eq 0 ]; then
  ok "All findings have required schema fields"
else
  fail "Schema validation failed"
fi

# Test 6 — IDs are sequential from 0
python3 -c "
import json, sys
data = json.load(open('$OUTDIR/findings.json'))
ids = [f['id'] for f in data]
expected = list(range(len(data)))
if ids == expected:
    sys.exit(0)
else:
    print(f'IDs: {ids[:10]}')
    sys.exit(1)
" 2>/dev/null
if [ $? -eq 0 ]; then
  ok "Finding IDs are sequential from 0"
else
  fail "Finding IDs not sequential"
fi

# Test 7 — nuclei findings present
nuclei_count=$(python3 -c "import json; d=json.load(open('$OUTDIR/findings.json')); print(sum(1 for f in d if f['tool']=='nuclei'))")
if [ "$nuclei_count" -gt 0 ]; then
  ok "Nuclei findings parsed: $nuclei_count"
else
  fail "No nuclei findings in output"
fi

# Test 8 — trufflehog findings present
tf_count=$(python3 -c "import json; d=json.load(open('$OUTDIR/findings.json')); print(sum(1 for f in d if f['tool']=='trufflehog'))")
if [ "$tf_count" -gt 0 ]; then
  ok "Trufflehog findings parsed: $tf_count"
else
  fail "No trufflehog findings in output"
fi

# Test 9 — manual findings present
manual_count=$(python3 -c "import json; d=json.load(open('$OUTDIR/findings.json')); print(sum(1 for f in d if f['tool']=='manual'))")
if [ "$manual_count" -gt 0 ]; then
  ok "Manual findings parsed: $manual_count"
else
  fail "No manual findings in output"
fi

echo ""
echo "Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
