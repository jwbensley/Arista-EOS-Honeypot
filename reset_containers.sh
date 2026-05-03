#!/bin/bash

set -eu

cd "$(dirname "$0")" || exit

# Stop and remove all containers
docker compose -f docker-compose.yml down

# Start containers again
docker compose -f docker-compose.yml up -d
