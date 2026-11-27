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
    echo "FAIL - help output"
    cat "$OUTPUT"
    exit 1
fi
echo "PASS - help output"

if ! "$BINARY" --version >"$OUTPUT" 2>&1 || ! grep -Fxq "slacksecchk 1.1.0.0" "$OUTPUT"; then
    echo "FAIL - version output"
    cat "$OUTPUT"
    exit 1
fi
echo "PASS - version output"

if "$BINARY" --invalid-option >"$OUTPUT" 2>&1; then
    echo "FAIL - invalid option was accepted"
    exit 1
else
    status=$?
    if [[ $status -ne 2 ]]; then
        echo "FAIL - invalid option returned $status instead of 2"
        cat "$OUTPUT"
        exit 1
    fi
fi
echo "PASS - invalid option returns exit code 2"

if ! NO_COLOR=1 SLACKSECCHK_TEST_MODE=1 "$BINARY" >"$OUTPUT" 2>&1; then
    echo "FAIL - NO_COLOR audit execution"
    cat "$OUTPUT"
    exit 1
fi
if awk 'index($0, sprintf("%c", 27)) { found=1; exit } END { exit !found }' "$OUTPUT"; then
    echo "FAIL - NO_COLOR did not suppress ANSI escapes"
    exit 1
fi
echo "PASS - NO_COLOR suppresses ANSI escapes"

if ! SLACKSECCHK_TEST_MODE=1 "$BINARY" --color=always >"$OUTPUT" 2>&1; then
    echo "FAIL - forced-color audit execution"
    cat "$OUTPUT"
    exit 1
fi
if ! awk 'index($0, sprintf("%c", 27)) { found=1; exit } END { exit !found }' "$OUTPUT"; then
    echo "FAIL - --color=always did not emit ANSI escapes"
    exit 1
fi
echo "PASS - --color=always emits ANSI escapes"

if ! SLACKSECCHK_TEST_MODE=1 "$BINARY" --no-color >"$OUTPUT" 2>&1; then
    echo "FAIL - no-color audit execution"
    cat "$OUTPUT"
    exit 1
fi
if awk 'index($0, sprintf("%c", 27)) { found=1; exit } END { exit !found }' "$OUTPUT"; then
    echo "FAIL - --no-color emitted ANSI escapes"
    exit 1
fi
echo "PASS - --no-color suppresses ANSI escapes"

if ! SLACKSECCHK_TEST_MODE=1 "$BINARY" >"$OUTPUT" 2>&1; then
    echo "FAIL - automatic-color audit execution"
    cat "$OUTPUT"
    exit 1
fi
if awk 'index($0, sprintf("%c", 27)) { found=1; exit } END { exit !found }' "$OUTPUT"; then
    echo "FAIL - automatic color emitted ANSI escapes to redirected output"
    exit 1
fi
echo "PASS - automatic color is disabled for redirected output"

json_status=0
SLACKSECCHK_TEST_MODE=1 "$BINARY" --format=json >"$OUTPUT" 2>&1 || json_status=$?
if [[ $json_status -gt 2 ]]; then
    echo "FAIL - JSON mode returned unexpected exit code $json_status"
    cat "$OUTPUT"
    exit 1
fi
if [[ $(wc -l < "$OUTPUT") -ne 1 ]] ||
   [[ $(head -c 1 "$OUTPUT") != "{" ]] ||
   [[ $(tail -n 1 "$OUTPUT" | tr -d '\n' | tail -c 1) != "}" ]] ||
   ! grep -Fq '"schema_version":2' "$OUTPUT" ||
   ! grep -Fq '"tool":"slacksecchk"' "$OUTPUT" ||
   ! grep -Fq '"summary":' "$OUTPUT" ||
   ! grep -Fq '"passed":' "$OUTPUT" ||
   ! grep -Fq '"failed":' "$OUTPUT" ||
   ! grep -Fq '"unverified":' "$OUTPUT" ||
   ! grep -Fq '"findings":[' "$OUTPUT" ||
   ! grep -Fq '"rule_id":' "$OUTPUT" ||
   ! grep -Fq '"evidence":' "$OUTPUT"; then
    echo "FAIL - JSON output is not a single valid-shaped summary document"
    cat "$OUTPUT"
    exit 1
fi
echo "PASS - JSON output and audit exit status"

sarif_status=0
SLACKSECCHK_TEST_MODE=1 "$BINARY" --format=sarif >"$OUTPUT" 2>&1 || sarif_status=$?
if [[ $sarif_status -gt 2 ]]; then
    echo "FAIL - SARIF mode returned unexpected exit code $sarif_status"
    cat "$OUTPUT"
    exit 1
fi
if [[ $(wc -l < "$OUTPUT") -ne 1 ]] ||
   [[ $(head -c 1 "$OUTPUT") != "{" ]] ||
   [[ $(tail -n 1 "$OUTPUT" | tr -d '\n' | tail -c 1) != "}" ]] ||
   ! grep -Fq '"$schema":"https://json.schemastore.org/sarif-2.1.0.json"' "$OUTPUT" ||
   ! grep -Fq '"version":"2.1.0"' "$OUTPUT" ||
   ! grep -Fq '"tool":{"driver":' "$OUTPUT" ||
   ! grep -Fq '"rules":[' "$OUTPUT" ||
   ! grep -Fq '"results":[' "$OUTPUT"; then
    echo "FAIL - SARIF output is not a single SARIF 2.1.0 document"
    cat "$OUTPUT"
    exit 1
fi
echo "PASS - SARIF 2.1.0 output and audit exit status"

if ! SLACKSECCHK_TEST_MODE=1 PATH="$TEST_DIR/bin:$PATH" "$BINARY" >"$OUTPUT" 2>&1; then
    echo "FAIL - audit returned a non-zero exit status"
    cat "$OUTPUT"
    exit 1
fi

if grep -Fq "Auditing system security" "$OUTPUT"; then
    echo "PASS - audit starts"
else
    echo "FAIL - audit start message not found"
    cat "$OUTPUT"
    exit 1
fi

if grep -Fq "Audit has finished" "$OUTPUT"; then
    echo "PASS - audit completes"
else
    echo "FAIL - audit completion message not found"
    cat "$OUTPUT"
    exit 1
fi

if grep -Fq "filesystem scan skipped in test mode" "$OUTPUT"; then
    echo "PASS - filesystem scans are isolated from the CI host"
else
    echo "FAIL - safe filesystem test mode was not applied"
    cat "$OUTPUT"
    exit 1
fi

echo "Smoke tests passed."
