#!/usr/bin/env bash

set -euo pipefail

BINARY="./artifacts/slacksecchk"
TEST_DIR="$(mktemp -d)"
OUTPUT="$TEST_DIR/output.txt"
trap 'rm -rf "$TEST_DIR"' EXIT

if [[ ! -x "$BINARY" ]]; then
    echo "Test setup error: $BINARY is missing or not executable. Run 'make' first." >&2
    exit 2
fi

# The audit performs recursive scans of the host filesystem. Stub find in this
# smoke test so CI verifies startup and completion without auditing the runner.
mkdir -p "$TEST_DIR/bin"
cat > "$TEST_DIR/bin/find" <<'EOF'
#!/usr/bin/env sh
exit 0
EOF
chmod +x "$TEST_DIR/bin/find"

echo "Running SlackSecChk smoke tests..."

if ! SLACKSECCHK_TEST_MODE=1 PATH="$TEST_DIR/bin:$PATH" "$BINARY" >"$OUTPUT" 2>&1; then
    echo "Test failed: the program returned a non-zero exit status."
    cat "$OUTPUT"
    exit 1
fi

if grep -Fq "Auditing system security" "$OUTPUT"; then
    echo "Test #1: PASS - audit starts"
else
    echo "Test #1: FAIL - audit start message not found"
    cat "$OUTPUT"
    exit 1
fi

if grep -Fq "Audit has finished" "$OUTPUT"; then
    echo "Test #2: PASS - audit completes"
else
    echo "Test #2: FAIL - audit completion message not found"
    cat "$OUTPUT"
    exit 1
fi

if grep -Fq "filesystem scan skipped in test mode" "$OUTPUT"; then
    echo "Test #3: PASS - filesystem scans are isolated from the CI host"
else
    echo "Test #3: FAIL - safe filesystem test mode was not applied"
    cat "$OUTPUT"
    exit 1
fi

echo "Smoke tests passed."
