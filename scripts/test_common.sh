#!/bin/bash
# Common library for test scripts
# Provides markdown output functions and test utilities

# Get test directory based on script name
# Returns: scripts/rm-<testname>.d/ (relative path)
get_test_dir() {
    local script_name=$(basename "${BASH_SOURCE[1]}")
    local test_name="${script_name%.sh}"
    echo "scripts/rm-${test_name}.d"
}

# Output test name as markdown header
test_name() {
    echo ""
    echo "## $1"
    echo ""
}

# Output test description
test_description() {
    echo "**Description**: $1"
    echo ""
}

# Internal EXIT trap — fires if the script exits inside the execution block
# without calling test_execution_end (e.g. set -e + failed command)
_test_execution_exit_trap() {
    local exit_code=$1
    set +x
    echo '```'
    echo ""
    echo "**Status**: FAIL"
    echo ""
    echo "**Reason**: Test exited with code $exit_code"
    exit "$exit_code"
}

# Start execution log block with set -x
# Installs an EXIT trap that closes the block if the script exits early
test_execution_start() {
    echo "**Execution**:"
    echo '```bash'
    # Redirect stderr to stdout so set -x traces are captured
    exec 2>&1
    set -x
    trap '_test_execution_exit_trap $?' EXIT
}

# End execution block and disable set -x
# Clears the EXIT trap so test_pass / test_fail can exit cleanly
test_execution_end() {
    set +x
    echo '```'
    echo ""
    trap - EXIT
}

# Output PASS status and exit 0
test_pass() {
    echo "**Status**: PASS"
    exit 0
}

# Output FAIL status with reason and exit 1
test_fail() {
    echo "**Status**: FAIL"
    echo ""
    echo "**Reason**: $1"
    exit 1
}
