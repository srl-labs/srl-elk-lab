---
date: 2022-12-22
tags:
  - syslog
  - sr linux
  - elk
  - k8s
authors:
  - azyablov
---

# SR Linux lab setup with ELK stack

## Intro

Syslog one of the most widely and powerful instrumentation used almost everywhere. SR Linux is not an exclusion, while syslog client implementation uses powerful [rsyslog][rsyslog].


## Lab summary

This blog posts is based on a lab example that builds a SR Linux fabric and ELK stack attached to OOB management.
Fabric provides L2 domain and various connectivity types as well as underlying configuration to enable log simulation for majority of the SR Linux subsystems.

| Summary                   |                                                                           |
|: ------------------------ | :-------------------------------------------------------------------------|
| **Lab name**              | SR Linux lab setup with ELK stack                                              |
| **Lab components**        | Nokia SR Linux 22.6.4, ELK stack 7.17.7                                   |
| **Resource requirements** | :fontawesome-solid-microchip: 4 vCPU <br/>:fontawesome-solid-memory: 8 GB |
| **Lab**                   | [azyablov/srl-elk-lab][lab-repo]                                          |
| **Version information**   | [`containerlab:0.32.4`][clab-install], [`srlinux:22.6.4`][srl-container]  |
| **Authors**               | Anton Zyablov [azyablov-linkedin]                                         |

## Lab repository

[Lab repository][lab-repo] by itself provides all necessary artifacts and guidelines to ramp-up your own lab alongside with the following guidelines:

:material-check: Intro and lab topology

:material-check: Quick start

:material-check: Simulation capabilities

:material-check: Detailed ELK stack configuration

:material-check: How to bring up your own ELK stack on top of K8s, in case your aren't quite happy with docker or would like to make step further


## Prerequisites

The lab leverages the [Containerlab][containerlab] project to spin up a topology of network elements and couple it with containerized software such as openbgpd. A [one-click][clab-install] installation gets containerlab installed on any Linux system.

```bash title="Containerlab installation via installation-script"
bash -c "$(curl -sL https://get.containerlab.dev)"
```

Since containerlab uses containers as the nodes of a lab, Docker engine has to be [installed][docker-install] on the host system.

# A background of the syslog story

What's sitting in the core of this story is data flow and data transformation.
Log events flows from SR Linux to Logstash, where messages undergo a transformation and further feed into Elasticsearch.

![Data Flow Diagram][data-flow-diagram]

So, let's start from the syslog configuration on SR Linux. Basic logging configuration consists of specifying a source, filter and destination for log messages, which are coming from syslog facilities and SR Linux subsystems. So, let's start from there.

```json title="SR Linux syslog configuration"
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
        <<===snip===>>
    }
```

As it's easy to see, there are IP@ and port where syslog server is listening for messages from SR Linux clients, by default, transport is UDP (TCP and UDP are supported). Number fo subsystems specified with the same filter to match all messages above informational, which is motivated by the intention to have a much as possible message footprint from the simulated fabric. All other details aren't so much important for the quick start, but can be found in [official documentation][srl-off-doc]. Worse to mention that all configuration is coming from config, since manual configuration could be superseded by SR Linux.


Normally after syslog server saving received event into file it appears like below:

``` log
an 11 18:39:00 srl-1-2 sr_bgp_mgr: bgp|1894|1965|00071|W: In network-instance default, the BGP session with VR default (1): Group ebgp-underlay: Peer 10.1.2.5 moved from higher state ACTIVE to lower state IDLE due to event TCP SOCKET ERROR
Jan 11 18:39:00 srl-1-2 sr_bgp_mgr: bgp|1894|1965|00072|W: In network-instance default, the BGP session with VR default (1): Group ebgp-underlay: Peer 10.1.2.7 moved from higher state ACTIVE to lower state IDLE due to event TCP SOCKET ERROR
Jan 11 18:39:01 srl-1-2 sr_bgp_mgr: bgp|1894|1965|00073|N: In network-instance default, the BGP session with VR default (1): Group ebgp-underlay: Peer 10.1.2.5 moved into the ESTABLISHED state
Jan 11 18:39:01 srl-1-2 sr_linux_mgr: linux|1658|1658|00253|W: Memory utilization on ram module 1 is above 70%, current usage 83%
Jan 11 18:39:02 srl-1-2 sr_bgp_mgr: bgp|1894|1965|00074|N: In network-instance default, the BGP session with VR default (1): Group ebgp-underlay: Peer 10.1.2.7 moved into the ESTABLISHED state
Jan 11 18:39:02 srl-1-2 sr_bgp_mgr: bgp|1894|1965|00075|N: In network-instance default, the BGP session with VR default (1): Group ibgp-evpn: Peer 10.0.0.5 moved into the ESTABLISHED state
Jan 11 18:39:02 srl-1-2 sr_bfd_mgr: bfd|1879|1879|00062|N: BFD:  Network-instance default - The protocol BGP is now using BFD session from 10.0.0.2:16395 to 10.0.0.5:0
Jan 11 18:39:02 srl-1-2 sr_bfd_mgr: bfd|1879|1879|00063|N: BFD:  Network-instance default - Session from 10.0.0.2:16395 to 10.0.0.5:16405 is UP
Jan 11 18:39:04 srl-1-2 sr_bgp_mgr: bgp|1894|1965|00076|W: In network-instance default, the BGP session with VR default (1): Group ibgp-evpn: Peer 10.0.0.6 was closed because the router sent this neighbor a NOTIFICATION with code CEASE and subcode CONN_COLL_RES
Jan 11 18:39:04 srl-1-2 sr_bgp_mgr: bgp|1894|1965|00077|N: In network-instance default, the BGP session with VR default (1): Group ibgp-evpn: Peer 10.0.0.6 moved into the ESTABLISHED state
Jan 11 18:39:04 srl-1-2 sr_bfd_mgr: bfd|1879|1879|00064|N: BFD:  Network-instance default - The protocol BGP is now using BFD session from 10.0.0.2:16396 to 10.0.0.6:0
Jan 11 18:39:04 srl-1-2 sr_bfd_mgr: bfd|1879|1879|00065|N: BFD:  Network-instance default - Session from 10.0.0.2:16396 to 10.0.0.6:16405 is UP
Jan 11 18:39:04 srl-1-2 sr_bfd_mgr: bfd|1879|1879|00065|N: BFD:  Network-instance default - Session from 10.0.0.2:16396 to 10.0.0.6:16405 is UP
Jan 11 18:39:31 srl-1-2 sr_linux_mgr: linux|1658|1658|00254|W: Memory utilization on ram module 1 is above 70%, current usage 83%
Jan 11 18:40:01 srl-1-2 sr_linux_mgr: linux|1658|1658|00255|W: Memory utilization on ram module 1 is above 70%, current usage 83%
Jan 11 18:40:31 srl-1-2 sr_linux_mgr: linux|1658|1658|00256|W: Memory utilization on ram module 1 is above 70%, current usage 83%
```

Log event message sent to remote destination has the following format:

```r
<TIMESTAMP> <HOSTNAME> <APPLICATION>: <SUBSYSTEM>|<PID>|<THREAD_ID>|<SEQUENCE>|<??>: <MESSAGE>
```
where
```r
    <TIMESTAMP> := DATE-MONTH DATE-MDAY TIME-HOUR ":" TIME-MINUTE ":" TIME-SECOND; Traditional form - MMM DD HH:MM:SS.
    <MESSAGE> := *OCTET; Application free-form message that provides information about the event, that could contain network-instance name, 
                like ```Network-instance default```.
    <HOSTNAME> := *OCTET; SR Linux hostname.
    <APPLICATION> := *OCTET; SR Linux application name.
    <SUBSYSTEM> := *OCTET; SR Linux subsystem name, which is configured under ```/system/logging/remote-server``` 
    <PID> := *DIGIT; Process ID.
    <THREAD_ID> := *DIGIT; Thread ID.
    <SEQUENCE> := *DIGIT; Sequence number, which allows to reproduce order of the messages sent by SR Linux.
    <??> := 1OCTET; What is it?
```

Now it's time to deploy your own lab.

# Quick start 

In order to bring up your lab follow the next simple steps:

1. Clone repo

```sh
git clone https://github.com/azyablov/srl-elk-lab.git
cd srl-elk-lab
```

2. Deploy the lab

```sh
cd <lab folder>
sudo clab deploy -t srl-elk.clab.yml
```

3. Create index template (to avoid automatic template creation by elastic)

```sh
curl -X PUT "localhost:9200/_index_template/fabric?pretty" -H 'Content-Type: application/json' -d @elk/logstash/index-template.json 
```

4. Import Kibana templates as described in [Kibana](#kibana) section. Kibana should available via [http://localhost:5601](http://localhost:5601)

5. Delete index created initially since it does not follow mappings and could not be adjusted any longer.

![Kibana delete index][index_deletion]

5. Run simulation to quickly ingest data into elasticsearch as described in [Simulation](#simulation)


## Simulation

In order to help quickly enrich ELK stack with logs ```outage_simulation.sh``` script could be executed with the following parameters:

```-S``` - to replace configuration for logstash remote server under ```/system/logging/remote-server[host=$LOGSTASHIP]"``` with new one.

```<WAITTIMER>``` - to adjust time interval between destructive actions applied (10 sec by default).

Basic configuration can found [here](../sys_log_logstash.json.tmpl), which represent default lab configuration, and can be adjusted per your needs and requirements.

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
In case TLS is a requirement, you can consider to put rsyslog in front, simple docker image with self-signed and custom certificate can be found on [github.com/azyablov/rsyslogbase](https://github.com/azyablov/rsyslogbase)


To run simulation just execute ```./outage_simulation.sh``` or ```./outage_simulation.sh 15``` in case machine is a bit slow or you have another labs running on the same compute.

![Outage Simulation][outage_simulation]


# ELK Stack

ELK stack configuration is covered in order or data flow appearance, so let's start with logstash first.

## Logstash

Logstash configuration includes three artifacts:
1. [Main configuration file](elk/logstash/logstash.yml)
2. [Patterns used pipeline](elk/logstash/patterns)
3. [Pipeline config](elk/logstash/pipeline/01-srl.main.conf) 


So far Logstash configuration takes this format as a baseline for [pipeline filter configuration][logstash-pipeline].
90% of work is to craft configuration file is about grok plugin. Most important configuration to carve out necessary fields form the syslog messages are provided below.
Syntax is quite simple, so you can consult ELK [documentation for grok](https://www.elastic.co/guide/en/logstash/7.17/plugins-filters-grok.html), but in case it fits setup needs no adaptation is required.

```r 
filter {
    if "srlinux" in [tags] {
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
        
        date {
            match => [ "timestamp",
            "MMM  d YYYY HH:mm:ss.SSS",
            "MMM d YYYY HH:mm:ss.SSS",
            "MMM dd YYYY HH:mm:ss.SSS",
            "MMM  d HH:mm:ss.SSS",
            "MMM dd HH:mm:ss",
            "MMM  d HH:mm:ss",
            "YYYY MMM dd HH:mm:ss.SSS ZZZ",
            "YYYY MMM dd HH:mm:ss ZZZ",
            "YYYY MMM dd HH:mm:ss.SSS",
            "ISO8601"
            ]
            timezone => "Europe/Rome"
        }
    }
}
```
then, after parsing and building necessary JSON documents, feeding it to Elasticsearch via output plugin:
```r
output {
    if "srlinux" in [tags] {
        if "_grokparsefailure" in [tags] {
            file {
                path => "/logs/fail_to_parse_srl.log"
                codec => rubydebug
            }
        } else {
            elasticsearch {
                        hosts => ["http://es01"]
                        ssl => false
                        manage_template => false
                        index           => "fabric-logs-%{+YYYY.MM.dd}"
                        id => "fabric-logs"
            }
        }
    }
}
```
Final outgoing JSON document from provided pipeline configuration follows the next self-descriptive format:
```json
{
    "timestamp": "Jan 11 19:39:02",
    "severity": 5,
    "srlsequence": "00102",
    "host.ip": "172.22.22.26",
    "program": "sr_bgp_mgr",
    "@timestamp": "2023-01-11T18:39:02.000Z",
    "srlthread": "1970",
    "srlproc": "bgp",
    "facility_label": "local6",
    "srlnetinst": "default",
    "host.name": "srl-2-2",
    "srlpid": "1903",
    "severity_label": "Notice",
    "tags": [
      "syslog",
      "srlinux"
    ],
    "facility": 22,
    "message": ", the BGP session with VR default (1): Group ebgp-underlay: Peer 10.1.2.6 moved into the ESTABLISHED state",
    "priority": 181
}
```

It could happen that new SR Linux releases could bring a new format due to some reasons, so pipeline configuration would require adjustments to parse messages correctly.
In this case log messages should appear under ```elk/logstash/logs/fail_to_parse_srl.log``` by default to easier troubleshooting.
Logstash solving it elegant way by adding  ```_grokparsefailure``` tag, if pattern is not covering specific log messages by grok config.

```json
    "tags" => [
            [0] "syslog",
            [1] "srlinux",
            [2] "_grokparsefailure"
        ],
```

In the next turn ```_dateparsefailure``` tag appears in case date plugin unable to parse specified field correctly, so date format should be revised and adjusted if necessary.
For example, uring demo preparation I've encountered trivial issue and had to add line with ```"MMM  d HH:mm:ss", ```.

```json
        date {
            match => [ "timestamp",
            "MMM  d YYYY HH:mm:ss.SSS",
            "MMM d YYYY HH:mm:ss.SSS",
            "MMM dd YYYY HH:mm:ss.SSS",
            "MMM  d HH:mm:ss.SSS",
            "MMM dd HH:mm:ss",
            "MMM  d HH:mm:ss", 
            "YYYY MMM dd HH:mm:ss.SSS ZZZ",
            "YYYY MMM dd HH:mm:ss ZZZ",
            "YYYY MMM dd HH:mm:ss.SSS",
            "ISO8601"
            ]
            timezone => "Europe/Rome"
        }
```

## Elasticsearch

### Index Template and Mappings

If necessary index templates aren't created at the very begging, elasticsearch will create automatically the following or similar to following mappings for the fabric indices.
Of course, that's not desirable result in many cases and in many cases recognized by elasticsearch just as type ```text```.

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
      }
    }
  }
}
```
In order to have IP@ recognized and threated as IP as well as to have numeric values considered as long, severity and facility as keywords only, assign appropriate types for the properties index template should be created.
As part of this exercise index template example example available as well.
```sh
curl -X PUT "localhost:9200/_index_template/fabric?pretty" -H 'Content-Type: application/json' -d @elk/logstash/index-template.json 
{
  "acknowledged" : true
}
```
Worse to mention, that as soon as grok config is adjusted to remove/add new fields index template must be updated as well.
In case you provide incorrect mappings that does not compatible with JSONs send by logstash, messages similar to provided below would appear in logs, which could be easily viewed ```docker logs clab-srl-elk-lab-logstash```.

```sh
[2022-11-28T00:24:50,529][WARN ][logstash.outputs.elasticsearch][main][fabric-logs] Could not index event to Elasticsearch. {:status=>400, :action=>["index", {:_id=>nil, :_index=>"fabric-logs-2022.11.28", :routing=>nil}, {"srlthread"=>"1867", "facility_label"=>"local6", "srlnetinst"=>"default", "tags"=>["syslog", "srlinux"], "program"=>"sr_bfd_mgr", "facility"=>22, "srlsequence"=>"00167", "host.name"=>"srl-elk-1-1", "srlpid"=>"1867", "host.ip"=>"172.20.20.5", "severity"=>5, "timestamp"=>"Nov 28 01:24:50", "severity_label"=>"Notice", "priority"=>181, "@timestamp"=>2022-11-28T00:24:50.000Z, "srlproc"=>"bfd", "message"=>" - Session from 10.0.0.1:16416 to 10.0.0.6:16403 is UP"}], :response=>{"index"=>{"_index"=>"fabric-logs-2022.11.28", "_type"=>"_doc", "_id"=>"gqifu4QBS1bTYaEyTmJZ", "status"=>400, "error"=>{"type"=>"mapper_parsing_exception", "reason"=>"failed to parse field [timestamp] of type [date] in document with id 'gqifu4QBS1bTYaEyTmJZ'. Preview of field's value: 'Nov 28 01:24:50'", "caused_by"=>{"type"=>"illegal_argument_exception", "reason"=>"failed to parse date field [Nov 28 01:24:50] with format [strict_date_optional_time||epoch_millis]", "caused_by"=>{"type"=>"date_time_parse_exception", "reason"=>"Failed to parse with all enclosed parsers"}}}}}}
```
In the next turn Elasticsearch applies own [index template][index-template] mappings, which results in the structure below:

![Indexed document][index-struture]

### Working with API

Playing with Kibana and creating dashboards is relatively easy to [start](#kibana) , but let's have a look how can we continue working with data via API. 
Not being Machine Learning expect, you can query and search data, apply aggregations for metrics, stats, create watchers and many other things.
So, let's demonstrate some of them to give feel and taste of available functionality.


```sh title="Cluster health status"
[azyablov@ecartman srl-elk-lab]$ curl -XGET "http://localhost:9200/_cat/health"
1673636289 18:58:09 es-docker-cluster green 3 3 60 30 0 0 0 0 - 100.0%
```

Logstash configuration implies creation of indices every day.

```sh title="Cluster indices"
[azyablov@ecartman srl-elk-lab]$ curl -XGET "http://localhost:9200/_cat/indices?pretty"
green open .kibana_task_manager_7.17.7_001 QkmljFNsRoSgECCImqVKKA 1 1    17 3864  29.9mb  15.1mb
green open .apm-agent-configuration        TW376NnUSXuVZJoCWyMqmA 1 1     0    0    452b    226b
green open fabric-logs-2022.12.09          METj7zB5SFqig1MiCaWKgQ 1 1 23965    0   4.8mb   2.4mb
green open fabric-logs-2022.12.08          -Qkv3kHMTWuAfk9gk-vW0g 1 1  3435    0   1.1mb 663.5kb
green open fabric-logs-2022.12.07          _eIWMeKMSjGxHH8T1vuuug 1 1 18990    0   6.1mb   3.1mb
green open fabric-logs-2022.11.29          nxwKJSoYQ0S5pLDl7pxxhw 1 1    18    0    79kb  45.3kb
green open fabric-logs-2022.12.05          Ofgk5VR0TN2fOyQgjoRx1Q 1 1   706    0 525.6kb 281.3kb
green open .tasks                          DGIOOyXnSlukZdTOM6VLOQ 1 1    36    0 151.7kb  60.9kb
green open .geoip_databases                ThDXigdwQoepGBV8vAgo7A 1 1    40    8  78.2mb  40.4mb
green open fabric-logs-2023.01.08          lMCUukPiRk6PYxzm0W2Cyg 1 1 22957    0   4.3mb   2.1mb
green open fabric-logs-2023.01.09          kol7RFLXRsuFt0aKJVNW-A 1 1 23924    0   4.5mb   2.2mb
green open fabric-logs-2023.01.06          rS0hPcLjRYKlBFJFdOQMSg 1 1 22963    0   4.2mb   2.1mb
green open .apm-custom-link                wlGW3YT-TM6R-g6EdWbs8w 1 1     0    0    452b    226b
green open fabric-logs-2023.01.07          Zn-w1VymS1KA3xRskqS8rA 1 1 22964    0   4.2mb     2mb
green open fabric-logs-2023.01.04          wk5mI3glT8Cp6jn5wg1YjQ 1 1  9915    0   2.1mb     1mb
green open fabric-logs-2023.01.05          LkCxU3xeQaCehzj0Hd1UNA 1 1 22962    0   4.3mb   2.1mb
green open fabric-logs-2023.01.13          bJCTzSgDSk6tY0-_a93iYA 1 1 17912    0   3.7mb   1.8mb
green open fabric-logs-2023.01.11          5_zVAdRtQf6VhUVDufOSkQ 1 1 24017    0   4.8mb   2.4mb
green open fabric-logs-2023.01.12          a9FefbcaSIWDxPNYZiRkiw 1 1 22951    0   4.3mb   2.1mb
green open .async-search                   0rPjO2ZlS0-BbGIiAglKPQ 1 1     0    0   9.9kb   3.4kb
green open .kibana_7.17.7_001              W82S1QRQSICQY-XH0k6KXQ 1 1   426   18   4.9mb   2.4mb
green open fabric-logs-2023.01.10          PBQ9kBbvTA-ZEHHactgqMQ 1 1 22964    0   4.3mb   2.1mb
```

Sometimes you need to verify indece mappings are correct and done in accordance with defined index template.

```sh title="Index mapping"
[azyablov@ecartman srl-elk-lab]$ curl -XGET "http://localhost:9200/fabric-logs-2023.01.13/_mapping?pretty"
```
```json
{
  "fabric-logs-2023.01.13" : {
    "mappings" : {
      "properties" : {
        "@timestamp" : {
          "type" : "date"
        },
        "facility" : {
          "type" : "long"
        },
        "facility_label" : {
          "type" : "keyword"
        },
        "host" : {
          "properties" : {
            "ip" : {
              "type" : "ip",
              "fields" : {
                "keyword" : {
                  "type" : "keyword",
                  "ignore_above" : 256
                }
              }
            },
            "name" : {
              "type" : "keyword"
            }
          }
        },
        "message" : {
          "type" : "text",
          "fields" : {
            "keyword" : {
              "type" : "keyword",
              "ignore_above" : 256
            }
          }
        },
        "priority" : {
          "type" : "long"
        },
        "program" : {
          "type" : "text",
          "fields" : {
            "keyword" : {
              "type" : "keyword",
              "ignore_above" : 256
            }
          }
        },
        "severity" : {
          "type" : "long"
        },
        "severity_label" : {
          "type" : "keyword"
        },
        "srlnetinst" : {
          "type" : "text",
          "fields" : {
            "keyword" : {
              "type" : "keyword",
              "ignore_above" : 256
            }
          }
        },
        "srlpid" : {
          "type" : "long"
        },
        "srlproc" : {
          "type" : "text",
          "fields" : {
            "keyword" : {
              "type" : "keyword",
              "ignore_above" : 256
            }
          }
        },
        "srlsequence" : {
          "type" : "long"
        },
        "srlthread" : {
          "type" : "long"
        },
        "tags" : {
          "type" : "text",
          "fields" : {
            "keyword" : {
              "type" : "keyword",
              "ignore_above" : 256
            }
          }
        },
        "timestamp" : {
          "type" : "text"
        }
      }
    }
  }
}
```

Let's imagine lag subsystem log messages are needed to check what's happening with access LAGs.

```sh
[azyablov@ecartman srl-elk-lab]$ curl -XGET "http://es01:9200/fabric-logs-2023.01.13/_search?pretty" -H 'Content-Type: application/json' -d'
{
  "query": {
    "match": {
      "program": "sr_lag_mgr" # (1)!
    }
  },
  "size": 100
}'
```
```json
{
  "took" : 467,
  "timed_out" : false,
  "_shards" : {
    "total" : 1,
    "successful" : 1,
    "skipped" : 0,
    "failed" : 0
  },
  "hits" : {
    "total" : {
      "value" : 24,
      "relation" : "eq"
    },
    "max_score" : 6.6501994,
    "hits" : [
      {
        "_index" : "fabric-logs-2023.01.13",
        "_type" : "_doc",
        "_id" : "q-k8rIUBQMUwMGaGYV6C",
        "_score" : 6.6501994,
        "_source" : {
          "srlsequence" : "00011",
          "priority" : 181,
          "host.name" : "srl-1-4",
          "srlthread" : "1649",
          "severity_label" : "Notice",
          "srlproc" : "lag",
          "facility" : 22,
          "@timestamp" : "2023-01-13T16:45:16.000Z",
          "severity" : 5,
          "program" : "sr_lag_mgr",
          "message" : "LAG Interface lag1: The operational state has transitioned to Up",
          "facility_label" : "local6",
          "tags" : [
            "syslog",
            "srlinux"
          ],
          "timestamp" : "Jan 13 17:45:16",
          "srlpid" : "1649",
          "host.ip" : "172.22.22.24"
        }
      },
      {
        "_index" : "fabric-logs-2023.01.13",
        "_type" : "_doc",
        "_id" : "rOk8rIUBQMUwMGaGYV6D",
        "_score" : 6.6501994,
        "_source" : {
          "srlsequence" : "00012",
          "priority" : 180,
          "host.name" : "srl-1-4",
          "srlthread" : "1649",
          "severity_label" : "Warning",
          "srlproc" : "lag",
          "facility" : 22,
          "@timestamp" : "2023-01-13T16:45:16.000Z",
          "severity" : 4,
          "program" : "sr_lag_mgr",
          "message" : "LAG Interface lag1: The member-link ethernet-1/10 operational state has transitioned to Up",
          "facility_label" : "local6",
          "tags" : [
            "syslog",
            "srlinux"
          ],
          "timestamp" : "Jan 13 17:45:16",
          "srlpid" : "1649",
          "host.ip" : "172.22.22.24"
        }
      },
      <<==snip==>>
      {
        "_index" : "fabric-logs-2023.01.13",
        "_type" : "_doc",
        "_id" : "AelDrIUBQMUwMGaGs2Hg",
        "_score" : 6.6501994,
        "_source" : {
          "srlsequence" : "00028",
          "priority" : 180,
          "host.name" : "srl-1-4",
          "srlthread" : "1649",
          "severity_label" : "Warning",
          "srlproc" : "lag",
          "facility" : 22,
          "@timestamp" : "2023-01-13T16:53:16.000Z",
          "severity" : 4,
          "program" : "sr_lag_mgr",
          "message" : "LAG Interface lag1: The member-link ethernet-1/10 operational state has transitioned to Up",
          "facility_label" : "local6",
          "tags" : [
            "syslog",
            "srlinux"
          ],
          "timestamp" : "Jan 13 17:53:16",
          "srlpid" : "1649",
          "host.ip" : "172.22.22.24"
        }
      }
    ]
  }
}
```

As per index template mapping, ```severity_label``` is defined as a term, so all messages with ```Notice``` severity could be easily queried.

```sh
[azyablov@ecartman srl-elk-lab]$ curl -XGET "http://es01:9200/fabric-logs-2023.01.13/_search?pretty" -H 'Content-Type: application/json' -d'
> {
>   "query": {
>     "bool": {
>       "filter": [
>         {
>           "term": {
>             "severity_label": "Notice"
>           }
>         }
>       ]
>     }
>   },
>   "size": 3
> }'
```
```json
{
  "took" : 420,
  "timed_out" : false,
  "_shards" : {
    "total" : 1,
    "successful" : 1,
    "skipped" : 0,
    "failed" : 0
  },
  "hits" : {
    "total" : {
      "value" : 550,
      "relation" : "eq"
    },
    "max_score" : 0.0,
    "hits" : [
      {
        "_index" : "fabric-logs-2023.01.13",
        "_type" : "_doc",
        "_id" : "q-k8rIUBQMUwMGaGYV6C",
        "_score" : 0.0,
        "_source" : {
          "srlsequence" : "00011",
          "priority" : 181,
          "host.name" : "srl-1-4",
          "srlthread" : "1649",
          "severity_label" : "Notice",
          "srlproc" : "lag",
          "facility" : 22,
          "@timestamp" : "2023-01-13T16:45:16.000Z",
          "severity" : 5,
          "program" : "sr_lag_mgr",
          "message" : "LAG Interface lag1: The operational state has transitioned to Up",
          "facility_label" : "local6",
          "tags" : [
            "syslog",
            "srlinux"
          ],
          "timestamp" : "Jan 13 17:45:16",
          "srlpid" : "1649",
          "host.ip" : "172.22.22.24"
        }
      },
      {
        "_index" : "fabric-logs-2023.01.13",
        "_type" : "_doc",
        "_id" : "rek8rIUBQMUwMGaGYV6D",
        "_score" : 0.0,
        "_source" : {
          "srlsequence" : "00022",
          "priority" : 181,
          "host.name" : "srl-1-4",
          "srlthread" : "1590",
          "severity_label" : "Notice",
          "srlproc" : "evpn",
          "facility" : 22,
          "@timestamp" : "2023-01-13T16:45:16.000Z",
          "severity" : 5,
          "program" : "sr_evpn_mgr",
          "message" : "The Oper DF preference value changed to 100 and/or the DP value changed to true on ethernet-segment cl12",
          "facility_label" : "local6",
          "tags" : [
            "syslog",
            "srlinux"
          ],
          "timestamp" : "Jan 13 17:45:16",
          "srlpid" : "1590",
          "host.ip" : "172.22.22.24"
        }
      },
      {
        "_index" : "fabric-logs-2023.01.13",
        "_type" : "_doc",
        "_id" : "sOk8rIUBQMUwMGaGY17N",
        "_score" : 0.0,
        "_source" : {
          "srlsequence" : "00011",
          "priority" : 181,
          "host.name" : "srl-1-3",
          "srlthread" : "1645",
          "severity_label" : "Notice",
          "srlproc" : "lag",
          "facility" : 22,
          "@timestamp" : "2023-01-13T16:45:16.000Z",
          "severity" : 5,
          "program" : "sr_lag_mgr",
          "message" : "LAG Interface lag1: The operational state has transitioned to Up",
          "facility_label" : "local6",
          "tags" : [
            "syslog",
            "srlinux"
          ],
          "timestamp" : "Jan 13 17:45:16",
          "srlpid" : "1645",
          "host.ip" : "172.22.22.23"
        }
      }
    ]
  }
}
```

Finally, a bit of classic regexp, which is searching for BGP keyword in the ```message``` field.

```sh title="Search API with DSL query"
[azyablov@ecartman ~]$ curl -XGET "http://es01:9200/fabric-logs-2023.01.13/_search?pretty" -H 'Content-Type: application/json' -d'
> {
>   "query": {
>     "bool": {
>       "must": [
>         {
>           "regexp": {
>             "message": ".*[bB][gG][pP].*"
>           }
>         }
>       ],
>       "filter": [
>         {
>           "term": {
>             "severity": "5"
>           }
>         }
>       ]
>     }
>   },
>   "size": 3 # (2)!
> }'
```
```json
{
  "took" : 932,
  "timed_out" : false,
  "_shards" : {
    "total" : 1,
    "successful" : 1,
    "skipped" : 0,
    "failed" : 0
  },
  "hits" : {
    "total" : {
      "value" : 243,
      "relation" : "eq"
    },
    "max_score" : 1.0,
    "hits" : [
      {
        "_index" : "fabric-logs-2023.01.13",
        "_type" : "_doc",
        "_id" : "lulCrIUBQMUwMGaGa1-N",
        "_score" : 1.0,
        "_source" : {
          "priority" : 181,
          "severity_label" : "Notice",
          "srlproc" : "bfd",
          "@timestamp" : "2023-01-13T17:51:51.000Z",
          "program" : "sr_bfd_mgr",
          "srlnetinst" : "default",
          "message" : " - The protocol BGP using BFD session from 10.0.0.8:16385 to 10.0.0.5:16385 has been cleared",
          "tags" : [
            "syslog",
            "srlinux"
          ],
          "timestamp" : "Jan 13 18:51:51",
          "srlpid" : "1859",
          "host.ip" : "172.22.22.28",
          "srlsequence" : "00017",
          "host.name" : "srl-3-2",
          "srlthread" : "1859",
          "facility" : 22,
          "severity" : 5,
          "facility_label" : "local6"
        }
      },
      {
        "_index" : "fabric-logs-2023.01.13",
        "_type" : "_doc",
        "_id" : "nulCrIUBQMUwMGaGa1-N",
        "_score" : 1.0,
        "_source" : {
          "priority" : 181,
          "severity_label" : "Notice",
          "srlproc" : "bfd",
          "@timestamp" : "2023-01-13T17:51:51.000Z",
          "program" : "sr_bfd_mgr",
          "srlnetinst" : "default",
          "message" : " - The protocol BGP using BFD session from 10.0.0.7:16385 to 10.0.0.5:16386 has been cleared",
          "tags" : [
            "syslog",
            "srlinux"
          ],
          "timestamp" : "Jan 13 18:51:51",
          "srlpid" : "1850",
          "host.ip" : "172.22.22.27",
          "srlsequence" : "00017",
          "host.name" : "srl-3-1",
          "srlthread" : "1850",
          "facility" : 22,
          "severity" : 5,
          "facility_label" : "local6"
        }
      },
      {
        "_index" : "fabric-logs-2023.01.13",
        "_type" : "_doc",
        "_id" : "pulCrIUBQMUwMGaGa1-N",
        "_score" : 1.0,
        "_source" : {
          "priority" : 181,
          "severity_label" : "Notice",
          "srlproc" : "bfd",
          "@timestamp" : "2023-01-13T16:51:51.000Z",
          "program" : "sr_bfd_mgr",
          "srlnetinst" : "default",
          "message" : " - The protocol BGP using BFD session from 10.0.0.4:16385 to 10.0.0.5:16390 has been cleared",
          "tags" : [
            "syslog",
            "srlinux"
          ],
          "timestamp" : "Jan 13 17:51:51",
          "srlpid" : "1857",
          "host.ip" : "172.22.22.24",
          "srlsequence" : "00016",
          "host.name" : "srl-1-4",
          "srlthread" : "1857",
          "facility" : 22,
          "severity" : 5,
          "facility_label" : "local6"
        }
      }
    ]
  }
}
```


## Kibana

For the fast and convinient start of demo dashboard and discover search configuraion [objects](./elk/kibana/kibana-dashboard.ndjson) are provided as part of this lab.
It could be added in few clicks using Kibaba import under Stach Management.

![kibana import][kibaba_stask_mgmt]

Then you can go to to Discovery and Dashboard under Analytics and see simple dashboard.

![kibana discuvery][kibaba_dashboard]

![kibana dashboard][kibaba_dashboard_2]


# Howto ELK with K8s 

This section is coming to reduce hassle bringing ELK stack on K8s cluster, of course, assuming ELK used for lab purposes. 
In case you would like to advance your setup and run ELK stack on top of k8s, please consider to to fine tune your resources and ELK stack by itself.
Here you can find necessray intents:
1. Kibana: [Config Map](../k8s/kibana/kibana-configmap.yaml), [Deloyment](../k8s/kibana/kibana-deployment.yaml), [Service](../k8s/kibana/kibana-service.yaml)
2. Elasticsearch: [PVC](../k8s/elasticsearch/es-log-dev-persistentvolumeclaim.yaml), [Deloyment](../k8s/elasticsearch/es-log-dev-deployment.yaml), [Service](../k8s/elasticsearch/es-log-dev-es-services.yaml), [LBL Service](../k8s/elasticsearch/es-log-dev-service.yaml)
3. Logstash: [Deployment](../k8s/logstash/logstash-deployment.yaml), [Config Map](../k8s/logstash/logstash-configmap.yaml), [LBL Service](../k8s/logstash/logstash-service.yaml), [PVC](../k8s/logstash/logstash-pvc.yaml)

Confugurations were tested on real K8s cluster with Calico CNI and MelalLB as load-balancer.


1.    srlproc can be used as well, but program name is coming as standard part syslog message.

2.    Setting number of documents to return to avoid very chatty responce for the sake fo brevity, can be used to limit documents retrieved.

[topology]: ../pic/toplogy.png "Lab topology"
[index-struture]: ../pic/index_doc_structure.png "Indexed document"
[data-flow-diagram]: ../pic/data_flow.png


[rsyslog]: https://documentation.nokia.com/srlinux/22-6/html/product/OAM.html
[srl-off-doc]: https://documentation.nokia.com/srlinux/22-6/SR_Linux_Book_Files/Configuration_Basics_Guide/configb-logging.html#ariaid-title1
[lab]: https://github.com/hellt/openbgpd-lab
[containerlab]: https://containerlab.dev
[clab-install]: https://containerlab.dev/install/#install-script
[docker-install]: https://docs.docker.com/engine/install/
[srl-container]: https://github.com/nokia/srlinux-container-image
[azyablov-linkedin]: https://linkedin.com/in/anton-zyablov
[lab-repo]: https://github.com/azyablov/srl-elk-lab
[logstash-pipeline]: https://github.com/azyablov/srl-elk-lab/blob/main/elk/logstash/pipeline/01-srl.main.conf
[index-template]: https://github.com/azyablov/srl-elk-lab/blob/main/elk/logstash/index-template.json

[kibaba_stask_mgmt]: ../pic/kibana_import.png "Stack Management"
[kibaba_dashboard]: ../pic/kibana_dashboard.png "Kibana dashboard #1"
[kibaba_dashboard_2]: ../pic/kibana_dashboard_2.png "Kibana dashboard #2"
[index_deletion]: ../pic/delete_index.png "Kibana delete index"
[outage_simulation]: ../pic/outage_smulation.gif "Simulation"
