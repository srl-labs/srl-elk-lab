#!/bin/bash
# Pre-checks
if [ ! -e ./.gnmic.yml ]; then
    echo "WARNING: gnmic local config is not found, please make sure you provide necesssary params in config fle under \$HOME \$XDG_CONFIG_HOME"
fi

for i in 21 22 23 25 26; do 
        gnmic set --update-path '/system/logging/remote-server[host=172.22.22.41]' --update-file syslog/srl_syslog.json -a 172.22.22.${i} -d
done