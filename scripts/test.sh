#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
passed=0
failed=0
xfailed=0
xpassed=0
test_num=0

# Find all *_test.sh files, sorted
tests=( $(find "$SCRIPT_DIR" -name "*_test.sh" -type f | sort) )

for test_file in "${tests[@]}"; do
  test_num=$((test_num + 1))
  test_name=$(basename "$test_file")

  # Detect xfail tests by name
  is_xfail=false
  if [[ "$test_name" == *_xfail_* ]]; then
    is_xfail=true
  fi

  # Test runner output
  echo "# Test $test_num"
  echo ""
  echo "**Filename**: $test_name"
  echo ""

  # Run the test, capturing exit code without aborting the suite
  set +e
  "$test_file"
  exit_code=$?
  set -e

  if $is_xfail; then
    if [ $exit_code -eq 0 ]; then
      # Unexpected pass — treat as failure, stop immediately
      xpassed=$((xpassed + 1))
      echo ""
      echo "**XPASS**: Test was expected to fail but passed"
      echo ""
      echo "# Summary"
      echo ""
      echo "- Total:   ${#tests[@]}"
      echo "- Passed:  $passed"
      echo "- Failed:  $failed"
      echo "- XFailed: $xfailed"
      echo "- XPassed: $xpassed"
      echo ""
      echo "**Test suite stopped at unexpected pass (XPASS)**"
      exit 1
    else
      xfailed=$((xfailed + 1))
      echo ""
      echo "**XFAIL**: Expected failure confirmed"
    fi
  else
    if [ $exit_code -eq 0 ]; then
      passed=$((passed + 1))
    else
      failed=$((failed + 1))
      echo ""
      echo "**Failed**: Test exited with code $exit_code"
      echo ""
      echo "# Summary"
      echo ""
      echo "- Total:   ${#tests[@]}"
      echo "- Passed:  $passed"
      echo "- Failed:  $failed"
      echo "- XFailed: $xfailed"
      echo "- XPassed: $xpassed"
      echo ""
      echo "**Test suite stopped at first failure**"
      exit 1
    fi
  fi

  echo ""
  echo "---"
  echo ""
done

# Final summary
echo "# Summary"
echo ""
echo "- Total:   ${#tests[@]}"
echo "- Passed:  $passed"
echo "- Failed:  $failed"
echo "- XFailed: $xfailed"
echo "- XPassed: $xpassed"
echo ""
echo "**All tests passed**"
