#/bin/sh
# this script creates an index pattern for the index created by logstash
# https://www.elastic.co/guide/en/kibana/7.17/index-patterns.html

curl -X POST 'http://localhost:5601/api/saved_objects/index-pattern' -H 'kbn-xsrf: true' -H 'Content-Type: application/json' \
  --data-raw '{"attributes":{"fieldAttrs":"{}","title":"fabric-logs-*","timeFieldName":"@timestamp","fields":"[]","typeMeta":"{}","runtimeFieldMap":"{}"}}'