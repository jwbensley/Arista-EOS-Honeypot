#!/bin/sh

set -eu

DURATION=$1

copy_file() {
    if [ -f "$1" ]; then
        cp "$1" "$2"
        gzip "$2"
        echo "$(date): Copied and compressed $1 to $2.gz"
    else
        echo "$(date): File $1 does not exist, skipping."
    fi
}

sleep $DURATION

while true
do
    echo "Starting log copy at $(date)"

    for file in messages secure
    do
        SRC="/eos_logs/${file}"
        DST="/logs/${file}.$(date +%Y%m%d-%H%M%S)"
        copy_file "$SRC" "$DST"
    done

    SRC="/eos_flash/startup-config"
    DST="/logs/startup-config.$(date +%Y%m%d-%H%M%S)"
    copy_file "$SRC" "$DST"

    cp -n /eos_flash/schedule/tech-support/* /logs/

    chmod a+rw /logs/*

    echo "Finished log copy at $(date)"

    # Use zero to allow for one-time copy
    if [ $DURATION -eq 0 ]; then
        exit 0
    fi
    sleep $DURATION
done
