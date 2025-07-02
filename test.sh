#!/bin/bash

# Enable strict mode: Abort on errors, unset variables, and pipe failures.
set -o nounset  # Exit if an unbound variable is used.
set -o errexit  # Exit if any command fails.
set -o pipefail # Fail pipelines if any command in the pipeline fails.

# Environment / locale settings.
LANG=C
LC_ALL=C

# Compile the program.
echo "Compiling SlackSecChk..."
gcc -Wall -Wextra -O2 -o slacksecchk src/slacksecchk.c src/rules.c
if [ $? -ne 0 ]; then
   echo "Compilation failed. Exiting..."
   exit 1
fi

# Run the program.
echo "Running SlackSecChk..."
./slacksecchk >test_output.txt

# Check for specific results in output.
echo "Checking test results..."

# Example: Check if the tool reports OK for /etc/passwd permissions.
if grep -q "CIS: OK: /etc/passwd permissions are correctly set." test_output.txt; then
   echo "PASS: /etc/passwd permissions check passed."
else
   echo "FAIL: /etc/passwd permissions check failed."
fi

# Example: Check if unnecessary packages check works.
if grep -q "CIS: OK: No unnecessary packages found." test_output.txt; then
   echo "PASS: Unnecessary packages check passed."
else
   echo "FAIL: Unnecessary packages check failed."
fi

# Example: Check if unnecessary services check works.
if grep -q "CIS: OK: Unnecessary service 'telnet' is disabled." test_output.txt; then
   echo "PASS: Unnecessary services check passed."
else
   echo "FAIL: Unnecessary services check failed."
fi

# Clean up.
echo "Cleaning up..."
rm -f test_output.txt
echo "Testing complete."
