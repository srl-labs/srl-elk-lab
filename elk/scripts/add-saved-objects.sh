#!/usr/bin/env bash
set -euo pipefail

# import saved searches and dashboards (overwrites existing objects with the same name)
nc -zv $(echo ${KIBANA_URL} | sed -E 's|^https?://([^:/]+):([0-9]+).*|\1 \2|') > /dev/null 2>&1
if [ $? == 0  ]; then
    case "$KIBANA_URL" in
        https://*)
            curl -X POST -u "elastic:${ELASTIC_PASSWORD}" \
            "${KIBANA_URL}/api/saved_objects/_import?overwrite=true" \
            -H "kbn-xsrf: true" \
            --cacert /tls/ca/ca.pem \
            --form "file=@$1"
            ;;
        http://*)
            curl -X POST -s -u "elastic:${ELASTIC_PASSWORD}" \
            "${KIBANA_URL}/api/saved_objects/_import?overwrite=true" \
            -H "kbn-xsrf: true" \
            --form "file=@$1"
            ;;
        *)
            echo "Unexpected URL format: $KIBANA_URL"
            exit 1
            ;;
    esac
else 
    echo "Please wait a minute kibana isn't available yet (or maybe not started)."
fi