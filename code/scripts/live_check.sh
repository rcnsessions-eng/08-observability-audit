#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
compose() {
  docker compose --env-file ../../05-identity-delegation/code/.env "$@"
}
compose up -d --build --wait gateway keycloak opa collector
compose run --rm smoke
trap 'compose start collector' EXIT
compose stop collector
compose run --rm smoke
compose run --rm --entrypoint python smoke -c 'import httpx; response = httpx.get("http://gateway:8000/health/telemetry", timeout=5, trust_env=False); response.raise_for_status(); assert response.json()["delivery_failures"] > 0; print("Telemetry delivery failure is visible")'
compose start collector
trap - EXIT
compose run --rm smoke
compose logs --no-color collector gateway | awk '
  /FAKE-SECRET-OBSERVABILITY-DO-NOT-LOG/ {canary++}
  /Name: learning.authorization.decisions/ {metrics++}
  /Name[[:space:]]*: mcp.evidence.record/ {mcp++}
  /Name[[:space:]]*: api.evidence.record/ {api++}
  /Name[[:space:]]*: policy.evidence.record/ {policy++}
  /Name[[:space:]]*: repository.evidence.record/ {repository++}
  END {
    printf "Collected metrics=%d mcp=%d api=%d policy=%d repository=%d canary=%d\n", metrics, mcp, api, policy, repository, canary
    if (canary || !metrics || !mcp || !api || !policy || !repository) exit 1
  }'