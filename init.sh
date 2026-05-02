#!/bin/bash

set -eu

CONFIG="/base.cfg"
CONFIG_LOCK="/first_boot"
CLI="/usr/bin/Cli"

# Wait for the Cli app to be unpacked during first boot
while [ ! -f ${CLI} ]
do
    sleep 1
done

# Only apply the bootstrap config if this is the first boot
if [ ! -f "${CONFIG_LOCK}" ]
then
    # Wait for the EOS config agent to become ready
    while ! ${CLI} -c "show hostname" | grep -E "^Hostname: "
    do
        sleep 1
    done
    ${CLI} -e "${CONFIG}"
    touch "${CONFIG_LOCK}"
fi
