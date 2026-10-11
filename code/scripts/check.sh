#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
docker compose --env-file ../../05-identity-delegation/code/.env build checks
docker compose --env-file ../../05-identity-delegation/code/.env run --rm checks sh -c 'ruff check --config /telemetry/pyproject.toml /app/app/observability /telemetry-tests /telemetry-scripts && ruff format --check --config /telemetry/pyproject.toml /app/app/observability /telemetry-tests /telemetry-scripts && mypy --config-file /telemetry/pyproject.toml /app/app/observability && python -m pytest -p no:cacheprovider /telemetry-tests -q'