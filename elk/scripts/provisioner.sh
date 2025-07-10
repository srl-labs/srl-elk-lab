#!/usr/bin/env bash
set -euo pipefail

cd /scripts || {
  echo "Failed to change directory" >&2
  exit 1
}

./health_check.sh && ./builtin_pwd_setup.sh
sleep 60
./add-saved-objects.sh saved-objects.ndjson