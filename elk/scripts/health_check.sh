#!/usr/bin/env bash
set -euo pipefail

ELASTICSEARCH_URL="${ELASTICSEARCH_URL:-http://elastic:9200}" # clab default
ELASTICSEARCH_USERNAME="${ELASTICSEARCH_USERNAME:-elastic}" # default username for the elastic user
ELASTICSEARCH_PASSWORD="${ELASTICSEARCH_PASSWORD:-BIGsecret}"  # default password for the elastic user

MAX_RETRIES="${MAX_RETRIES:-30}"   # 30 × 2 s  ≈ 1 min total
SLEEP="${SLEEP:-2}"

echo "Waiting for Elasticsearch at $ELASTICSEARCH_URL …"

for i in $(seq 1 "$MAX_RETRIES"); do
  if curl --silent --fail -u "$ELASTICSEARCH_USERNAME:$ELASTICSEARCH_PASSWORD" \
          "$ELASTICSEARCH_URL/_cluster/health?wait_for_status=yellow&timeout=3s" \
          --cacert /tls/ca/ca.pem \
          > /dev/null; then
    echo "Elasticsearch is up (health ≥ yellow) after $i attempt(s)."
    exit 0
  fi

  echo "Attempt $i out of $MAX_RETRIES, retrying in ${SLEEP}s…"
  sleep "$SLEEP"
done

echo "Elasticsearch is not ready on time!"
exit 1