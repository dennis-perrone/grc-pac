#!/usr/bin/env bash
# File: run-grc-check.sh

# Get the directory this script lives in
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Default scan dir relative to script
SCAN_DIR="${1:-$SCRIPT_DIR/../test-data/kubernetes}"

podman run --rm \
  --name grc-check \
  -v "${SCAN_DIR}:/data:Z" \
  grc-check \
  /data/