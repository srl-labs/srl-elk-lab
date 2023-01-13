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

# SRL lab setup with ELK stack

## Intro

Syslog one of the most widely and powerfull instumentation used almost everywhere. SR Lunix is not an exclusion, while syslog client implementation uses powerful (rsyslog)[https://documentation.nokia.com/srlinux/22-6/html/product/OAM.html].


## Lab summary

This blog posts is based on a lab example that builds a SRL fabric and ELK stack attacehd to OOB management.
Fabric provides L2 domain and various connectivity types as well as underlaying configuration to enable log simulation for majority of the SR Linux subsystems.

| Summary                   |                                                                           |
|: ------------------------ | :-------------------------------------------------------------------------|
| **Lab name**              | SRL lab setup with ELK stack                                              |
| **Lab components**        | Nokia SR Linux 22.6.4, ELK stack 7.17.7                                   |
| **Resource requirements** | :fontawesome-solid-microchip: 4 vCPU <br/>:fontawesome-solid-memory: 8 GB |
| **Lab**                   | [azyablov/srl-elk-lab][lab-repo]                                          |
| **Version information**   | [`containerlab:0.32.4`][clab-install], [`srlinux:22.6.4`][srl-container]  |
| **Authors**               | Anton Zyablov [azyablov-linkedin]                                         |

## Lab repository

[Lab repository][lab-repo] by itself provides all necessary artefasts and guidelines to ramp-up your own lab alongisde with the following guidelines:
:material-check: Intro and lab topology
:material-check: Quick start
:material-check: Simulation capabilities
:material-check: Detailed ELK stack configuration
:material-check: How to bring up your own ELK stack on top of K8s, in case your aren't quite happy with docker or would like to make step further


## Prerequisites

The lab leverages the [Containerlab][containerlab] project to spin up a topology of network elements and couple it with containerized software such as openbgpd. A [one-click][clab-install] installation gets containerlab intstalled on any Linux system.

```bash title="Containerlab installation via installation-script"
bash -c "$(curl -sL https://get.containerlab.dev)"
```

Since containerlab uses containers as the nodes of a lab, Docker engine has to be [installed][docker-install] on the host system.

# Background of the syslog story

What really complements [guidelines][lab-repo] coming with lab repository is data flow and data transformation.
Log events flows from SRL to Logstash, where messages undergo a transformation and futher feeded into Elasticsearch.

![Data Flow Diagram][data-flow-diagram]

So, let's start from the syslog configuration on SRL. Basic logging configuration consists of specifying a source, filter and destination for log messages, which are coming from syslog facilities and SRL subsystems. So, let's start from there.

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

As it's easy to see, there are IP@ and port where syslog server is listening for messages from SRL clients, by default, transport is UDP (TCP and UDP are supported). Number fo subsystems specified with the same filter to match all messages above informational, which is motivated by the intention to have a much as possible message footprint from the simulated fabric. All other details aren't so much important for quick start, but can be found in (official documentation)[https://documentation.nokia.com/srlinux/22-6/SR_Linux_Book_Files/Configuration_Basics_Guide/configb-logging.html#ariaid-title1]. Worse to mention that all configuration is coming from config, since manual configuration could be supersided by SR Linux.


Normaly after syslog server saving received event into file it appears like below:

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
<TIMESTAMP> <HOSTNAME> <APPLICATION>: <SUBSYSTEM>|<PID>|<THREAD_ID>|<SEQUENCE>|<??>: <MESSAGE>
where
    <TIMESTAMP> := DATE-MONTH DATE-MDAY TIME-HOUR ":" TIME-MINUTE ":" TIME-SECOND; Traditional form - MMM DD HH:MM:SS.
    <MESSAGE> := *OCTET; Application free-form message that provides information about the event, that could contain network-instance name, 
                like ```Network-instance default```.
    <HOSTNAME> := *OCTET; SRL hostname.
    <APPLICATION> := *OCTET; SRL application name.
    <SUBSYSTEM> := *OCTET; SRL subsystemname name, which is configured under ```/system/loggging/remote-server``` 
    <PID> := *DIGIT; Process ID.
    <THREAD_ID> := *DIGIT; Thread ID.
    <SEQUENCE> := *DIGIT; Sequence number, which allows to reproduce order of the messages sent by SRL.
    <??> := 1OCTET; What is it?

So far Logstash configuration takes this format as a beline for [pipeline filter configuration][logstash-pipeline], 
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
In the next turn Elasticserach applies own [index template][index-template] mappings, which results in the structure below:

![Indexed document][index-struture]

Playing with Kibana and creating dashboards is pretty obvious, but let's have a look how can we coninue working with data. 
Not being Machine Learning expect, you can query and search data, apply aggregations for metrics, stats, create watchers and many other things.
So, let's demonstrate some of them to give feel and taste of available funstionality.


```sh title="Cluster health status"
[azyablov@ecartman srl-elk-lab]$ curl -XGET "http://localhost:9200/_cat/health"
1673636289 18:58:09 es-docker-cluster green 3 3 60 30 0 0 0 0 - 100.0%
```

Logstash configuration implies creation of indeces every day.

```sh title="Cluster indeces"
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

Let's imagine lag subsystem log messages are required.

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

As per index template mapping, severity_label is defined as a term, so all messages with ```Notice``` severity could be easily requeried.

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

Finally, a bit of classic regexp, which trying to search of BGP keyword in the ```message``` field.

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


1.    srlproc can be used as well, but program name is coming as standard part syslog message.

2.    Setting number of documents to return to avoid very chatty responce for the sake fo brevity, can be used to limit documents retrieved.

[topology]: ../pic/toplogy.png "Lab topology"
[index-struture]: ../pic/index_doc_structure.png "Indexed document"
[data-flow-diagram]: ../pic/data_flow.png


[lab]: https://github.com/hellt/openbgpd-lab
[containerlab]: https://containerlab.dev
[clab-install]: https://containerlab.dev/install/#install-script
[docker-install]: https://docs.docker.com/engine/install/
[srl-container]: https://github.com/nokia/srlinux-container-image
[azyablov-linkedin]: https://linkedin.com/in/anton-zyablov
[lab-repo]: https://github.com/azyablov/srl-elk-lab
[logstash-pipeline]: https://github.com/azyablov/srl-elk-lab/blob/main/elk/logstash/pipeline/01-srl.main.conf
[index-template]: https://github.com/azyablov/srl-elk-lab/blob/main/elk/logstash/index-template.json