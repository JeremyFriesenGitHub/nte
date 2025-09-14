#!/usr/bin/env bash
#+ executable:chmod=755
set -euo pipefail

# Start a minimal Malcolm stack with low memory settings.
# This brings up only the essentials: opensearch, dashboards-helper, dashboards,
# api, arkime, nginx-proxy, filebeat (optional), and logstash. Heavy optional
# services like NetBox, Keycloak, Postgres, Redis, NetBox helpers are omitted.

cd "$(dirname "$0")/.."

COMPOSE_FILES=(-f docker-compose.yml -f docker-compose.lowmem.yml)

# Choose a minimal set of services that provide the core UI and search
SERVICES=(opensearch dashboards-helper dashboards logstash arkime api nginx-proxy)

echo "Bringing up low-memory Malcolm stack..."
docker compose "${COMPOSE_FILES[@]}" up -d "${SERVICES[@]}"

echo "\nLow-memory stack started. URLs:"
echo "  - https://localhost (nginx proxy)"
echo "  - https://localhost:9200 (OpenSearch proxied)"
echo "Use 'docker compose -f docker-compose.yml -f docker-compose.lowmem.yml down' to stop."
