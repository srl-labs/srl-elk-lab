#!/bin/bash
WTIME=20
NETWORK=`grep -E '^[ ]*network' srl-elk.clab.yml | sed -e 's/.*network[^:\/\/]*:[^:\/\/]//g;s/ //g'`
SEP="***"
LEAFS="1"
SPINES="2"

# Function defenitions == start ==
function get_value (){
    gnmic -d -a  srl-$1-$2 get --path $3 --values-only
}

function set_value (){
    echo -e "\t$SEP Setting value for srl-$1-$2 $SEP"
    RETVAL=`gnmic -d -a  srl-$1-$2 set --update-path $3  --update-value $4`
    echo $RETVAL | grep -e '"operation": "UPDATE"' > /dev/null #2>&1 
    if [ $? == 0 ]; then
        echo -e "\t\tDONE"
    else
        echo -e "\t\tFAIL"
    fi
}

function set_value_all (){
    LAST=2
    if [ $1 == 1 ]; then
        LAST=4
    fi
    for i in `seq 1 $LAST`; do 
        set_value $1 $i $2 $3
    done
}

function configure_syslog_for_all (){
    local IPINSPPATH="{{.NetworkSettings.Networks.$NETWORK.IPAMConfig.IPv4Address}}"
    local LOGSTASHIP=`docker container inspect logstash -f $IPINSPPATH`
    local SYSLOGPATH="/system/logging/remote-server[host=$LOGSTASHIP]"
    local SYSLOGCONFIG="sys_log_logstash.json"
    sed -e "s/LOGSTASHIP/$LOGSTASHIP/g" sys_log_logstash.json.tmpl > $SYSLOGCONFIG
    echo -e "$SEP Configuring $SYSLOGPATH for leafs $SEP"
    replace_config_all $LEAFS $SYSLOGPATH $SYSLOGCONFIG
    echo -e "$SEP Configuring $SYSLOGPATH for spines $SEP"
    replace_config_all $SPINES $SYSLOGPATH $SYSLOGCONFIG
}

function update_config_all(){
    LAST=2
    if [ $1 == 1 ]; then
        LAST=4
    fi
    for i in `seq 1 $LAST`; do 
        local RETVAL=`gnmic -d -a  srl-$1-$i set --update-path $2 --update-file $3`
        echo $RETVAL | grep -e '"operation": "UPDATE"' > /dev/null 2>&1 
        if [ $? == 0 ]; then
            echo -e "\tDONE"
        else
            echo -e "\tFAIL"
        fi
    done
}

function replace_config_all(){
    LAST=2
    if [ $1 == 1 ]; then
        LAST=4
    fi
    for i in `seq 1 $LAST`; do 
        local RETVAL=`gnmic -d -a  srl-$1-$i set --replace-path $2 --replace-file $3`
        echo $RETVAL | grep -e '"operation": "REPLACE"' > /dev/null 2>&1 
        if [ $? == 0 ]; then
            echo -e "\tDONE"
        else
            echo -e "\tFAIL"
        fi
    done
}

# Function defenitions == stop ==

# Pre-checks
if [ ! -e ./.gnmic.yml ]; then
    echo "WARNING: gnmic local config is not found, please make sure you provide necesssary params in config fle under \$HOME \$XDG_CONFIG_HOME"
fi
# Flags
for FLAG in "$@"; do
    #echo "|$FLAG|"
    case $FLAG in
        "-S" )
            configure_syslog_for_all
            exit 0
            ;;

        [0-9]* )
            WTIME=$FLAG
            ;;
    esac
done

echo -e "$SEP Shutdown ibgp group on spine1 srl-2-1 $SEP"
set_value $SPINES 1 /network-instance[name="default"]/protocols/bgp/group[group-name=ibgp-evpn]/admin-state disable

echo -e "$SEP Wait $WTIME sec... $SEP"
sleep $WTIME
echo -e "$SEP Shutdown ibgp group on spine2 srl-2-2 $SEP"
set_value $SPINES 2 /network-instance[name="default"]/protocols/bgp/group[group-name=ibgp-evpn]/admin-state disable

echo -e "$SEP Wait $WTIME sec... $SEP"
sleep $WTIME
echo -e "$SEP Bring up ibgp group on spine1 and spine2 srl-2-1/2 $SEP"
set_value_all $SPINES /network-instance[name="default"]/protocols/bgp/group[group-name=ibgp-evpn]/admin-state enable

echo -e "$SEP Wait $WTIME sec... $SEP"
sleep $WTIME

echo -e "$SEP Shutdown active port for cl12 $SEP"
get_value $LEAFS 3 /interface[name=lag1]/oper-state | grep "up" > /dev/null && get_value $LEAFS 4 /interface[name=lag1]/oper-state | grep "down"
if [ $? == 0 ]; then
    set_value $LEAFS 3 /interface[name=lag1]/admin-state disable
else
    echo -e "\tPort in not operationaly active shutting down port on leaf4"
    set_value $LEAFS 4 /interface[name=lag1]/admin-state disable
fi

echo -e "$SEP Wait $WTIME sec... $SEP"
sleep $WTIME

echo -e "$SEP Unshut the port for cl12 $SEP"
set_value $LEAFS 3 /interface[name=lag1]/admin-state enable
set_value $LEAFS 4 /interface[name=lag1]/admin-state enable

echo -e "$SEP Round-robin shut/noshut spine ports for"
echo -e "\tspine1 srl-2-1"
for i in `seq 1 6` ; do
    set_value $SPINES 1 /interface[name="ethernet-1/$i"]/admin-state disable
    sleep 2
done 

for i in `seq 1 6` ; do
    set_value $SPINES 1 /interface[name="ethernet-1/$i"]/admin-state enable
    sleep 2
done 
sleep 5
echo -e "\tand spine2 srl-2-2 $SEP"
for i in `seq 1 6` ; do
    set_value $SPINES 2 /interface[name="ethernet-1/$i"]/admin-state disable
    sleep 2
done 

for i in `seq 1 6` ; do
    set_value $SPINES 2 /interface[name="ethernet-1/$i"]/admin-state enable
    sleep 2
done 


echo -e "$SEP Wait $WTIME sec... $SEP"
sleep $WTIME

echo -e "$SEP Triggering LLDP on leafs"
set_value_all $LEAFS /system/lldp/admin-state disable
sleep $WTIME
set_value_all $LEAFS /system/lldp/admin-state enable


