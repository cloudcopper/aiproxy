#!/bin/bash
# Simplest test
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/test_common.sh"

test_name "Example: simplest test"
test_description "This test always pass"

test_execution_start
true
test_execution_end

test_pass
