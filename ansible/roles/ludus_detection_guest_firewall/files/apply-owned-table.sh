#!/bin/sh
set -eu
rules=${1:?rules file required}
candidate=$(mktemp)
trap 'rm -f "$candidate"' EXIT
if nft list table inet ludus_detection >/dev/null 2>&1; then
  printf '%s\n' 'delete table inet ludus_detection' > "$candidate"
fi
cat "$rules" >> "$candidate"
nft --check --file "$candidate"
nft --file "$candidate"
