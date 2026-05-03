#!/bin/bash

set -eu

cd "$(dirname "$0")" || exit

# Copy logs before resetting containers
docker compose -f docker-compose.yml exec log_copier /copy_logs.sh 0

# Stop and remove containers and volumes
docker compose -f docker-compose.yml down -v

# Start containers again
docker compose -f docker-compose.yml up -d
