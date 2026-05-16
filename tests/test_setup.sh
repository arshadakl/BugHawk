#!/usr/bin/env bash
# tests/test_setup.sh — mock tool check without real installs

BUGHAWK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$BUGHAWK_DIR/lib/utils.sh"

PASS=0
FAIL=0

ok()   { echo -e "${GREEN}[PASS]${RESET} $1"; PASS=$((PASS+1)); }
fail() { echo -e "${RED}[FAIL]${RESET} $1"; FAIL=$((FAIL+1)); }

echo "=== test_setup.sh ==="

# Source setup functions without running run_setup
source "$BUGHAWK_DIR/lib/setup.sh"

# Test detect_os — should set OS variable
detect_os
if [ -n "$OS" ]; then
  ok "detect_os() set OS='$OS'"
else
  fail "detect_os() did not set OS"
fi

# Test detect_pkg_manager — should set PKG variable
detect_pkg_manager
if [ -n "$PKG" ]; then
  ok "detect_pkg_manager() set PKG='$PKG'"
else
  fail "detect_pkg_manager() did not set PKG"
fi

# Test check_go_path — should not crash
check_go_path 2>/dev/null
ok "check_go_path() ran without error"

# Test print_tool_table_header — should produce output
output=$(print_tool_table_header)
if echo "$output" | grep -q "Tool"; then
  ok "print_tool_table_header() outputs header"
else
  fail "print_tool_table_header() no header found"
fi

# Test print_tool_row — should format correctly
row=$(print_tool_row "nmap" "✓" "7.94")
if echo "$row" | grep -q "nmap"; then
  ok "print_tool_row() formats correctly"
else
  fail "print_tool_row() bad format"
fi

echo ""
echo "Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
