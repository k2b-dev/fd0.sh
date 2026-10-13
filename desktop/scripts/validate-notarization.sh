#!/usr/bin/env bash
set -euo pipefail

app=${1:?usage: validate-notarization.sh APP}

# stapler validate performs another CloudKit lookup even after stapling succeeds.
# Retry transport failures only; missing or invalid tickets remain hard failures.
for attempt in 1 2 3 4; do
  if output=$(xcrun stapler validate "$app" 2>&1); then
    printf '%s\n' "$output"
    exit 0
  else
    status=$?
  fi
  printf '%s\n' "$output" >&2
  if [[ "$status" -ne 68 || "$attempt" -eq 4 ]] ||
     ! grep -Eq 'NSURLErrorDomain Code=-(1001|1005)([^0-9]|$)' <<<"$output"; then
    exit "$status"
  fi
  delay=$((10 * 2 ** (attempt - 1)))
  printf 'Apple ticket connection failed; retrying validation (%s/4) in %ss.\n' "$((attempt + 1))" "$delay" >&2
  sleep "$delay"
done
