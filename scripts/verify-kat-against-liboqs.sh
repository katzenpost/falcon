#!/usr/bin/env bash
#
# Compare our vendored KAT fixtures against the SHA-256 digests
# published in Open Quantum Safe's liboqs. Pass means the bytes
# of our PQCsignKAT_*.rsp files equal what liboqs's KAT runner
# would emit.
#
# Run from the repo root:
#
#   scripts/verify-kat-against-liboqs.sh
#
# Dependencies: curl, jq, sha256sum.

set -euo pipefail

LIBOQS_REF="${LIBOQS_REF:-main}"
LIBOQS_KATS_URL="https://raw.githubusercontent.com/open-quantum-safe/liboqs/${LIBOQS_REF}/tests/KATs/sig/kats.json"

declare -a VARIANTS=(
  "Falcon-padded-512   padded512/testdata/PQCsignKAT_falcon-padded-512.rsp"
  "Falcon-padded-1024  padded1024/testdata/PQCsignKAT_falcon-padded-1024.rsp"
)

kats_json=$(curl -sSfL "$LIBOQS_KATS_URL")

failed=0
printf 'liboqs ref: %s\n' "$LIBOQS_REF"
printf 'kats.json:  %s\n\n' "$LIBOQS_KATS_URL"

for entry in "${VARIANTS[@]}"; do
  variant=$(echo "$entry" | awk '{print $1}')
  fixture=$(echo "$entry" | awk '{print $2}')

  if [ ! -f "$fixture" ]; then
    printf '%-22s  missing: %s\n' "$variant" "$fixture"
    failed=1
    continue
  fi

  ours=$(sha256sum "$fixture" | cut -d' ' -f1)
  theirs=$(printf '%s' "$kats_json" | jq -r --arg v "$variant" '.[$v].all')

  if [ "$ours" = "$theirs" ]; then
    printf '%-22s  OK   %s\n' "$variant" "$ours"
  else
    printf '%-22s  FAIL\n  ours:   %s\n  liboqs: %s\n' \
      "$variant" "$ours" "$theirs"
    failed=1
  fi
done

exit "$failed"
