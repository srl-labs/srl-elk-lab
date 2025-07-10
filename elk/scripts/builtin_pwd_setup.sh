#!/usr/bin/env bash
set -euo pipefail

ELASTICSEARCH_URL="${ELASTICSEARCH_URL:-http://elastic:9200}" # clab default
# Verify availability of Elasticsearch (uncomment to use), normally done by health_check.sh
# curl -s -u elastic:${ELASTIC_PASSWORD} $ELASTICSEARCH_URL/_cluster/health?wait_for_status=yellow&timeout=10s

echo "Setting built-in passwords…"
for u in kibana_system logstash_system; do
    var=$(echo ${u^^}_PASS)
    pw=$(eval echo \$$var)
    [ -z "$pw" ] && continue         # skip if empty
    echo "Setting password for $u…"
    
    case "$ELASTICSEARCH_URL" in
        https://*)
            curl -s -u elastic:$ELASTIC_PASSWORD \
            -H "Content-Type: application/json" \
            -X POST $ELASTICSEARCH_URL/_security/user/$u/_password \
            -d "{\"password\":\"$pw\"}" \
            --cacert /tls/ca/ca.pem && echo "$u is done"
            ;;
        http://*)
            curl -s -u elastic:$ELASTIC_PASSWORD \
            -H "Content-Type: application/json" \
            -X POST $ELASTICSEARCH_URL/_security/user/$u/_password \
            -d "{\"password\":\"$pw\"}" && echo "$u is done"
            ;;
        *)
            echo "Unexpected URL format: $ELASTICSEARCH_URL"
            exit 1
            ;;
    esac
done