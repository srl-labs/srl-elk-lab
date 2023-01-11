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

What really complements [guidelines][lab-repo] coming with lab repository is data flow and data transformation. So, let's start from the syslog configuration on SRL. Basic logging configuration consists of specifying a source, filter and destination for log messages, which are coming from syslog facilities and SRL subsystems. So, let's start from there.

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
<...output omitted for brevity...>
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

[topology]: ../pic/toplogy.png "Lab topology"
[index-struture]: ../pic/index_doc_structure.png "Indexed document"


[lab]: https://github.com/hellt/openbgpd-lab
[containerlab]: https://containerlab.dev
[clab-install]: https://containerlab.dev/install/#install-script
[docker-install]: https://docs.docker.com/engine/install/
[srl-container]: https://github.com/nokia/srlinux-container-image
[azyablov-linkedin]: https://linkedin.com/in/anton-zyablov
[lab-repo]: https://github.com/azyablov/srl-elk-lab
[logstash-pipeline]: https://github.com/azyablov/srl-elk-lab/blob/main/elk/logstash/pipeline/01-srl.main.conf
[index-template]: https://github.com/azyablov/srl-elk-lab/blob/main/elk/logstash/index-template.json