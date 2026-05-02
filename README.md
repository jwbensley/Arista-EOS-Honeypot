# EOS Honeypot

This repo contains an Arista EOS based honeypot.

* A Docker container is used to run cEOS, which is a containerized version of EOS.
* The container is configured to automatically apply a base configuration on first boot, and log all commands.
* The EOS device is configured with SSH and Telnet enabled, with a default username and password of `admin`/`admin`.
* The output of the "show version" command is modified to make it look my like a physical device and not like cEOS.

## Base Configuration

* A custom [`rc.local`](./init/rc.local) script is mounted which in turn calls [`init.sh`](./init/init.sh).
* [`init.sh`](./init/init.sh) applies the base EOS configuration ([`base.cfg`](./init/base.cfg)) but only if it hasn't been applied before.
* The base config is applied using the `Cli` command, meaning it is applied interactively. An alternative method would be to put the required config in the `startup-config` file, but one time commands like those needed for generating the self-signed cert for eAPI don't work when applied via the `startup-config`.

## Logging

* The [`bashrc`](./init/bashrc) file is one copied from EOS and `export PROMPT_COMMAND` is added at the end to export all bash commands to syslog.
* All BASH commands are written to /var/log/messages (and also /var/log/secure of course, but now we have EOS commands _and_ BASH commands in the same log file).
* A separate container is used to copy the logs from the EOS container to the host machine periodically. This is because mounting a host directory directly to /var/log and /mnt/flash doesn't seem to work with cEOS. Also this means there isn't a rw mount between host and the EOS container which may be better from a security perspective. Instead a shared ro volume is used to access the logs from the second container, and the logs are copied to the host machine from there.
* EOS generates tech-support dumps periodically, and these are also copied to the host machine by the second container.

## Running cEOS

Start the containers:

```shell
docker compose up -d
```

During boot up, several messages are displayed as part of a normal boot. The system is ready for use when the following log message is shown:

```text
eos_honeypot  | [  OK  ] Started Update UTMP about System Runlevel Changes.
```

Stop the containers:

```shell
docker compose stop
```

Remove the containers:

```shell
docker compose down
```

## Connectivity

The host machine needs to have TCP ports 22 and 23 available for use by the EOS container.

Container traffic will be NAT masqueraded to the host machine IP address (standard docker behaviour), meaning that the EOS container can reach out to the public Internet using the host machines connectivity, equally, SSH and Telnet access to the EOS container will be via the host machine IP address.

## Interacting with cEOS

When booting the EOS container for the first time the bootstrap configuration needs to be applied (to set an IPv4/v6 address, enable SSH + Telnet, and generate a self-signed cert for eAPI), otherwise the container won't be remotely reachable. This is done automatically.

After this EOS should be locally reachable on the host machine via SSH by using the following:

```shell
ssh admin@10.214.33.2
ssh admin@fd:10:214:33::2
```

The password is `admin`.

Alternatively, EOS should also be reachable via the eAPI (using a self-signed cert) by using:

`https://10.214.33.2:443/eapi/`

This is not currently exposed in the docker-compose file, meaning the public Internet can't reach the eAPI, but the host machine will be able to reach the eAPI.

To programmatically check if the container is operational, try to get the device hostname via the API. Once the bootstrap config has been automatically applied during start up the device should return the hostname `arista_eos`.

Example run locally:

```shell
curl -s -k -d \
'{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "runCmds",
    "params": {
        "version": 1,
        "cmds": ["show hostname"]
    }
}' \
https://admin:admin@10.214.33.2:443/command-api \
| jq '."result"[0]."hostname"'

# Response:
"arista_eos"
```
