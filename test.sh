#!/bin/bash

# Enable strict mode: Abort on errors, unset variables, and pipe failures.
set -o nounset  # Exit if an unbound variable is used.
set -o errexit  # Exit if any command fails.
set -o pipefail # Fail pipelines if any command in the pipeline fails.

# Environment / locale settings.
LANG=C
LC_ALL=C

EXIT_CODE=0

# Build the program.
make clean
make

# Run the program.
echo "Testing..."
rm -f ./test_output.txt
./artifacts/slacksecchk > test_output.txt

if grep -q "Auditing system security" test_output.txt; then
   echo "Test #1: PASS!"
else
   EXIT_CODE=1
   echo "Test #1: FAIL!"
fi

if grep -q "Audit has finished" test_output.txt; then
   echo "Test #2: PASS!"
else
   EXIT_CODE=1
   echo "Test #2: FAIL!"
fi

rm -f ./test_output.txt
echo "Test finished."
exit $EXIT_CODE
