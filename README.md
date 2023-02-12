# Intro

This repo contains containerlab-based labs demonstrating how logs from SR Linux network elements can be collected, parsed, and stored using Elasticsearch/Logstash/Kibana (ELK) stack.

A series of blog posts go into the details of various ELK deployment models:

1. [SR Linux logging with ELK][srk-with-elk-post] - an introduction to the modern logging infrastructure using ELK stack.

## Lab Topology

The [srl-elk.clab.yml](srl-elk.clab.yml) topology represents a 2-tier Clos fabric with 2 clients participating in a single L2 EVPN domain.

![ELK lab topology][topology]

Naming conventions are straighforward:

* leaf[1-3] - leaves
* spine[1,2] - spines
* client[1,2] - emulated clients

client1 connectivity uses a single interface attached to leaf1.
client2 is connected as A/S to leaf2 and leaf3 with standby link signalling using LACP.

spine1 and spine2 are acting as BGP RR. This setup is sufficient to demonstrate a way to integrate a fabric with ELK stack.

## Quick start

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

3. For the fast and convenient start of demo, dashboard and discover search configuration [objects](./elk/kibana/kibana-dashboard.ndjson) are provided as part of the lab.

Run `add-saved-objects.sh` in order to avoid manual import and creation.

```sh
./add-saved-objects.sh
```

Demo dashboard can be adjusted as necessary.

4. Run simulation to quickly ingest data into elasticsearch as described in [Simulation](#simulation)

> Note! Index template is created automatically by logstash (to avoid automatic template creation by elastic).
> `manage_template` and `template*` configuration option stanzas are defining such logstash behavior.

```r
output {
    if "srlinux" in [tags] {
        if "_grokparsefailure" in [tags] {
            file {
                path => "/srl/fail_to_parse_srl.log"
                codec => rubydebug
            }
        } else {
            elasticsearch {
                hosts => ["http://elastic"]
                ssl => false
                index => "fabric-logs-%{+YYYY.MM.dd}"
                manage_template => true
                template => "/tmp/index-template.json"
                template_name => "fabric-template"
                template_overwrite => true
                id => "fabric-logs"
            }
        }
    }
}
```

## Simulation

In order to help quickly enrich ELK stack with logs ```outage_simulation.sh``` script could be executed with the following parameters:

```-S``` - to replace configuration for logstash remote server under ```/system/logging/remote-server[host=$LOGSTASHIP]"``` with new one.

```<WAITTIMER>``` - to adjust time interval between destructive actions applied (20 sec by default).

Basic configuration can found [here](./sys_log_logstash.json.tmpl), which represent default lab configuration, and can be adjusted per your needs and requirements.

```sh
./outage_simulation.sh -S
```

By default configuration for remote server using UDP:

```json
    {
      "host": "172.22.22.11",
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

> Note! In case TLS is a requirement, you can consider to put rsyslog in front, simple docker image with self-signed and custom certificate can be found on [github.com/azyablov/rsyslogbase](https://github.com/azyablov/rsyslogbase)

To run simulation just execute ```./outage_simulation.sh``` or ```./outage_simulation.sh 15``` in case machine is a bit slow or you have another labs running on the same compute.

![Outage Simulation][outage_simulation]

## Kibana

Your pre-configured Kibana should available via [http://localhost:5601](http://localhost:5601).
Now you can go to to Discovery and Dashboard under Analytics and see a demo dashboard.

![kibana discovery][kibaba_dashboard]

![kibana dashboard][kibaba_dashboard_2]

[kibaba_dashboard]: ./pic/kibana_dashboard.png "Kibana dashboard #1"
[kibaba_dashboard_2]: ./pic/kibana_dashboard_2.png "Kibana dashboard #2"
[outage_simulation]: ./pic/outage_simulation.gif "Simulation"
[srk-with-elk-post]: https://learn.srlinux.dev/blog/2023/sr-linux-logging-with-elk/
[topology]: ./pic/topology.png
