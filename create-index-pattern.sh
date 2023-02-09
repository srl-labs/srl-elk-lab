#/bin/sh
# this script creates an index pattern for the index created by logstash
# see https://www.elastic.co/guide/en/kibana/current/index-patterns-api-create.html
# https://www.elastic.co/guide/en/kibana/7.17/index-patterns.html
curl -X POST "localhost:5601/api/index_patterns/index_pattern" -H 'kbn-xsrf: true' -H 'Content-Type: application/json' -d'
{
  "index_pattern": {
     "title": "fabric-logs-*"
  }
}
'