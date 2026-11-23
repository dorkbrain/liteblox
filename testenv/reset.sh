#!/bin/bash
# Stop the test container and wipe its state (users, DB, secret, backups).
set -e
cd "$(dirname "$0")"
podman compose -f compose.yaml down 2>/dev/null || true
rm -rf data backups
mkdir -p data backups
echo "✓ testenv reset"
