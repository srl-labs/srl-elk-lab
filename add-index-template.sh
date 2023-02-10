# import index template mappings
curl -X PUT "localhost:9200/_index_template/fabric?pretty" -H 'Content-Type: application/json' -d @elk/logstash/index-template.json