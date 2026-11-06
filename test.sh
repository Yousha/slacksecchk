#!/usr/bin/env bash

set -euo pipefail

BINARY="./artifacts/slacksecchk"
OUTPUT="$(mktemp)"
trap 'rm -f "$OUTPUT"' EXIT

if [[ ! -x "$BINARY" ]]; then
    echo "Test setup error: $BINARY is missing or not executable. Run 'make' first." >&2
    exit 2
fi

echo "Running SlackSecChk smoke tests..."

if ! "$BINARY" >"$OUTPUT" 2>&1; then
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

echo "Smoke tests passed."
