# Intro

In old ages reading log files was normal excercise for sysadmin guru with assistnace of old school and robust tools like grep/egrep, awk, sed...
Today's infrastructure requirements go well beyond just looking for the root cause why your application is crashing, inforectly configured or ... just to realise that port occupied by another applciation.
For sure topics related to ML, close-loop automation, intrusion detection, security analysis and just keeping logs in structured form and programmatically accessible way are becoming a norm for system design and architecture.

This lab provides you with SR Linux / ELK playground to collect, handle and manage logs from your network devices. 
It comes with prefefined pipelines and configurations of ELK stack to let playing w/o hassle with SR Linux, as well as developing log management applications with ready to use infrastructure.

# Lab Topology

This lab was created to allow easily enter this domain with your SR Linux based fabric.
clab topology represents 3-tier fabric topology and with 3 containers  sitting within one L2 domain.

![ELK lab topology][topology]


Naming conventions are very simple:
* srl-elk-1-* - leafs,
* srl-elk-2-* - spines,
* srl-elk-3-* - border leafs.
cl11 connectivity is using one interface attached to leaf1 (srl-elk-1-1).
cl12 is connected as A/S to leaf3 (srl-elk-1-3) and leaf4 (srl-elk-1-4) with standby link signalling using LACP.
cl31 is attached via static LAG in A/A mode.
spine1 (srl-elk-2-1) and spine2 (srl-elk-2-2) are acting as BGP RR.
This setup is more than enougth to demonstrate the way to integrate farbic with ELK stack.

# Quick start 

1. Deploy your lab
```sh
cd <lab folder>
sudo clab deploy -t srl-elk.clab.yml
```
2. Create index template
```sh
curl -X PUT "localhost:9200/_index_template/fabric?pretty" -H 'Content-Type: application/json' -d @elk/logstash/index-template.json 
```
3. Import Kibana templates as decribed in [Kibana](#kibana) section. Kibana should available via [http://localhost:5601](http://localhost:5601)

4. Delete index created initially since it does not follow mappings and could not be adjusted any longer.

![Kibana delete index][index_deletion]

5. Run simulation in indest data into elasticsearch as decribed in [Simulation](#simulation)


# Simulation

In order to help quickly enrich ELK stack with logs ```outage_simulation.sh``` script could be executed with the following parameters:

```-S``` - to replace configuration for logstash remote server under ```/system/logging/remote-server[host=$LOGSTASHIP]"``` with new one.

```<WAITTIMER>``` - to adjust time interval between structive actions applied (10 sec by default).

Basic configuraion can found [here](./sys_log_logstash.json.tmpl), which reperesent default lab configuration, and can be adjusted per your needs and requirements.

```sh
./outage_simulation.sh -S
```

By default configuration for remote server using UDP:

```json
    {
      "host": "172.22.22.10",
      "remote-port": 1514,
      "subsystem": [
        {
          "priority": {
            "match-above": "informational"
          },
          "subsystem-name": "aaa"
        },
        {
          "priority": {
            "match-above": "informational"
          },
          "subsystem-name": "acl"
        },
<...output omitted for brevity...>
    }
```
In case TLS is a requirement, you can cosider to put rsyslog in front, simple docker image with self-signed and custom certificate can be found on [github.com/azyablov/rsyslogbase](https://github.com/azyablov/rsyslogbase)


To run simulation just execute ```./outage_simulation.sh``` or ```./outage_simulation.sh 15``` in case machine is a bit slow or you have another labs running on the same compute.

![Outage Simulation][outage_simulation]

# ELK Stack
## Index Template and Mappings

By default, logstash will create the following or similar to following mappings for the fabric indeces.

```json
{
  "mappings": {
    "_doc": {
      "properties": {
        "@timestamp": {
          "type": "date"
        },
        "facility": {
          "type": "long"
        },
        "facility_label": {
          "type": "text",
          "fields": {
            "keyword": {
              "type": "keyword",
              "ignore_above": 256
            }
          }
        },
        "host": {
          "properties": {
            "ip": {
              "type": "text",
              "fields": {
                "keyword": {
                  "type": "keyword",
                  "ignore_above": 256
                }
              }
            },
<...output omitted for brevity...>
        "severity_label": {
          "type": "text",
          "fields": {
            "keyword": {
              "type": "keyword",
              "ignore_above": 256
            }
          },
<...output omitted for brevity...>
        "srlproc": {
          "type": "text",
          "fields": {
            "keyword": {
              "type": "keyword",
              "ignore_above": 256
            }
          }
        },
        "srlsequence": {
          "type": "text",
          "fields": {
            "keyword": {
              "type": "keyword",
              "ignore_above": 256
            }
          }
        },
        "srlthread": {
          "type": "text",
          "fields": {
            "keyword": {
              "type": "keyword",
              "ignore_above": 256
            }
          }
        },
<...output omitted for brevity...>
      }
    }
  }
}
```
In order to have IP@ recognised and threated as IP as well as to have numric values considered as long, severity and facility as keywords only, assign appropriate types for the properties index teamplate should be created.
As part of this excercise index template example example available as well.
```sh
curl -X PUT "localhost:9200/_index_template/fabric?pretty" -H 'Content-Type: application/json' -d @elk/logstash/index-template.json 
{
  "acknowledged" : true
}
```
Of course, as soon as grok config is adjusted to remove/add new fields index teamplate must be udpated as well. In case you provide incorrect mappings that does not compatible with JSONs send by logstash, messages similar to provided below would appear in in logs, which could be easily viewed ```docker logs clab-srl-elk-lab-logstash```.

```sh
[2022-11-28T00:24:50,529][WARN ][logstash.outputs.elasticsearch][main][fabric-logs] Could not index event to Elasticsearch. {:status=>400, :action=>["index", {:_id=>nil, :_index=>"fabric-logs-2022.11.28", :routing=>nil}, {"srlthread"=>"1867", "facility_label"=>"local6", "srlnetinst"=>"default", "tags"=>["syslog", "srlinux"], "program"=>"sr_bfd_mgr", "facility"=>22, "srlsequence"=>"00167", "host.name"=>"srl-elk-1-1", "srlpid"=>"1867", "host.ip"=>"172.20.20.5", "severity"=>5, "timestamp"=>"Nov 28 01:24:50", "severity_label"=>"Notice", "priority"=>181, "@timestamp"=>2022-11-28T00:24:50.000Z, "srlproc"=>"bfd", "message"=>" - Session from 10.0.0.1:16416 to 10.0.0.6:16403 is UP"}], :response=>{"index"=>{"_index"=>"fabric-logs-2022.11.28", "_type"=>"_doc", "_id"=>"gqifu4QBS1bTYaEyTmJZ", "status"=>400, "error"=>{"type"=>"mapper_parsing_exception", "reason"=>"failed to parse field [timestamp] of type [date] in document with id 'gqifu4QBS1bTYaEyTmJZ'. Preview of field's value: 'Nov 28 01:24:50'", "caused_by"=>{"type"=>"illegal_argument_exception", "reason"=>"failed to parse date field [Nov 28 01:24:50] with format [strict_date_optional_time||epoch_millis]", "caused_by"=>{"type"=>"date_time_parse_exception", "reason"=>"Failed to parse with all enclosed parsers"}}}}}}
```

## Logstash configuration

Logstash configuration inludes three artefacts:
1. [Main configuration file](elk/logstash/logstash.yml)
2. [Patterns used pipeline](elk/logstash/patterns)
3. [Pipeline config](elk/logstash/pipeline/01-srl.main.conf) 

90% of work is to craft configuration file is about grok plugin. Most important configuration to carve out necessary fields form the syslog messsages are provided below.
Syntax is quite simple, so you can consult ELK [documentation for grok](https://www.elastic.co/guide/en/logstash/7.17/plugins-filters-grok.html), but in case it fits setup needs no adaptationg is required.

```r
 grok {
      patterns_dir => [ "/var/lib/logstash/patterns" ]
      match => { "message" => "%{SRLPROC:srlproc}\|%{SRLPID:srlpid}\|%{SRLTHR:srlthread}\|%{SRLSEQ:srlsequence}(?<message>(.*))" }
      overwrite => [ "message" ]
      add_field => { "host.ip" => "%{host}" }
      add_field => { "host.name" => "%{logsource}" }
  }

  grok {
      patterns_dir => [ "/var/lib/logstash/patterns" ]
      match => { "message" => [
          "\|%{SRLDOT:garbage1}: %{SRLGRBG:garbage2}etwork-instance %{SRLNETINST:srlnetinst}(?<message>(.*))",
          "\|%{SRLDOT:garbage1}: (?<message>(.*))"
          ] }
      overwrite => [ "message" ]
      remove_field => [ "@version", "host", "logsource", "garbage1", "garbage2" ]
  }
```
For sure, new SRL releases will be coming in the future and format could be adjusted in the way pipeline cofiguration will not be able to parse magges correctly.
In this case log messages should appear under ```elk/logstash/logs``` by defatult to easier troubleshooting.
When pattern is not covering specific log message ```_grokparsefailure``` tag should be observed in ```fail_to_parse_srl.log```.

```json
    "tags" => [
            [0] "syslog",
            [1] "srlinux",
            [2] "_grokparsefailure"
        ],
```

## Kibana

For the fast and convinient start of demo dashboard and discover search configuraion [objects](./elk/kibana/kibana-dashboard.ndjson) are provided as part of this lab.
It could be added in few clicks using Kibaba import under Stach Management.

![kibana import][kibaba_stask_mgmt]

Then you can go to to Discovery and Dashboard under Analytics and see simple dashboard.

![kibana discuvery][kibaba_dashboard]

![kibana dashboard][kibaba_dashboard_2]

## Howto ELK with K8s 

This section is coming to reduce hassle bringing ELK stack on K8s cluster, of course, assuming ELK used for lab purposes. 
In case you would like to advance your setup and run ELK stack on top of k8s, please consider to to fine tune your resources and ELK stack by itself.
Here you can find necessray intents:
1. Kibana: [Config Map](./k8s/kibana/kibana-configmap.yaml), [Deloyment](./k8s/kibana/kibana-deployment.yaml), [Service](./k8s/kibana/kibana-service.yaml)
2. Elasticsearch: [PVC](./k8s/elasticsearch/es-log-dev-persistentvolumeclaim.yaml), [Deloyment](./k8s/elasticsearch/es-log-dev-deployment.yaml), [Service](./k8s/elasticsearch/es-log-dev-es-services.yaml), [LBL Service](./k8s/elasticsearch/es-log-dev-service.yaml)
3. Logstash: [Deployment](./k8s/logstash/logstash-deployment.yaml), [Config Map](./k8s/logstash/logstash-configmap.yaml), [LBL Service](./k8s/logstash/logstash-service.yaml), [PVC](./k8s/logstash/logstash-pvc.yaml)

Confugurations were tested on real K8s cluster with Calico CNI and MelalLB as load-balancer.

[topology]: ./pic/toplogy.png "Lab topology"
[kibaba_stask_mgmt]: ./pic/kibana_import.png "Stack Management"
[kibaba_dashboard]: ./pic/kibana_dashboard.png "Kibana dashboard #1"
[kibaba_dashboard_2]: ./pic/kibana_dashboard_2.png "Kibana dashboard #2"
[index_deletion]: ./pic/delete_index.png "Kibana delete index"
[outage_simulation]: ./pic/outage_smulation.gif "Simulation"
