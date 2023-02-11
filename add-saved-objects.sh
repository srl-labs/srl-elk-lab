# import saved searches and dashboards (overwrites existing objects with the same name)
nc -zv localhost 5601 > /dev/null 2>&1
if [ $? == 0  ]; then
    curl -X POST 'http://localhost:5601/api/saved_objects/_import?overwrite=true' -H "kbn-xsrf: true" --form file=@elk/kibana/saved-objects.ndjson
else 
    echo "Please wait a minute kibana isn't available yet (or maybe not started)."
fi