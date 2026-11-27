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

echo "Running SlackSecChk smoke tests..."

if ! "$BINARY" --help >"$OUTPUT" 2>&1 || ! grep -Fq "Usage: slacksecchk" "$OUTPUT"; then
    echo "Test #1: FAIL - help output"
    cat "$OUTPUT"
    exit 1
fi
echo "Test #1: PASS - help output"

if ! "$BINARY" --version >"$OUTPUT" 2>&1 || ! grep -Fxq "slacksecchk 1.1.0.0" "$OUTPUT"; then
    echo "Test #2: FAIL - version output"
    cat "$OUTPUT"
    exit 1
fi
echo "Test #2: PASS - version output"

if "$BINARY" --invalid-option >"$OUTPUT" 2>&1; then
    echo "Test #3: FAIL - invalid option was accepted"
    exit 1
else
    status=$?
    if [[ $status -ne 2 ]]; then
        echo "Test #3: FAIL - invalid option returned $status instead of 2"
        cat "$OUTPUT"
        exit 1
    fi
fi
echo "Test #3: PASS - invalid option returns exit code 2"

if ! NO_COLOR=1 SLACKSECCHK_TEST_MODE=1 "$BINARY" >"$OUTPUT" 2>&1; then
    echo "Test #4: FAIL - NO_COLOR audit execution"
    cat "$OUTPUT"
    exit 1
fi
if grep -q 
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
\033' "$OUTPUT"; then
    echo "Test #4: FAIL - NO_COLOR did not suppress ANSI escapes"
    exit 1
fi
echo "Test #4: PASS - NO_COLOR suppresses ANSI escapes"

if ! SLACKSECCHK_TEST_MODE=1 "$BINARY" --color=always >"$OUTPUT" 2>&1; then
    echo "Test #5: FAIL - forced-color audit execution"
    cat "$OUTPUT"
    exit 1
fi
if ! grep -q 
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
\033' "$OUTPUT"; then
    echo "Test #5: FAIL - --color=always did not emit ANSI escapes"
    exit 1
fi
echo "Test #5: PASS - --color=always emits ANSI escapes"

if ! SLACKSECCHK_TEST_MODE=1 "$BINARY" --no-color >"$OUTPUT" 2>&1; then
    echo "Test #6: FAIL - no-color audit execution"
    cat "$OUTPUT"
    exit 1
fi
if grep -q 
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
\033' "$OUTPUT"; then
    echo "Test #6: FAIL - --no-color emitted ANSI escapes"
    exit 1
fi
echo "Test #6: PASS - --no-color suppresses ANSI escapes"


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
