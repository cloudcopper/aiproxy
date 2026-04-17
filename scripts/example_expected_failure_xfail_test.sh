#!/bin/bash
# XFAIL: Demonstrates expected failure support — calls false intentionally
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/test_common.sh"

test_name "Example: expected failure demo"
test_description "This test always fails — used to verify XFAIL handling in the test runner"

test_execution_start
false
test_execution_end

status_failed "This test is expected to fail, but it did not!!!"
