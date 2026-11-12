#!/usr/bin/env bash
#
# mayhem/test.sh — runs the known-answer selftest that mayhem/build.sh built (normal flags, no sanitizers).
# It drives ftab/mbn/fls/img3/img4/ace3/ipsw through their public entry points on committed fixtures and
# asserts exact sizes, byte layouts and CRC-32s of the outputs.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
cd "$SRC"

emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

BIN=/mayhem/idevicerestore_selftest
if [ ! -x "$BIN" ]; then
  echo "missing $BIN: mayhem/build.sh did not build it" >&2
  emit_ctrf "idevicerestore-selftest" 0 1
  exit 1
fi

out="$("$BIN" "$SRC" 2>&1)"
rc=$?
printf '%s\n' "$out" | grep -E '^FAIL|^SELFTEST' >&2

summary="$(printf '%s\n' "$out" | sed -n 's/^SELFTEST passed=\([0-9]*\) failed=\([0-9]*\)$/\1 \2/p' | tail -1)"
if [ -z "$summary" ]; then
  echo "selftest printed no SELFTEST summary (exit $rc)" >&2
  emit_ctrf "idevicerestore-selftest" 0 1
  exit 1
fi
read -r passed failed <<<"$summary"
# A zero-test run, or a non-zero exit with no counted failure, is a failure too.
if [ "$passed" -lt 40 ] || { [ "$rc" -ne 0 ] && [ "$failed" -eq 0 ]; }; then
  failed=$(( failed + 1 ))
fi
emit_ctrf "idevicerestore-selftest" "$passed" "$failed"
