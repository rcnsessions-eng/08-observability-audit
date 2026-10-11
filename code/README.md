# Privacy-Aware Observability and Audit

PRD 08 instrumentation overlay; earlier business and identity implementations are inherited through explicit local images. Compose project: `zero-trust-observability-audit`. Local acceptance criteria are verified, not production readiness.

## Run

From the sequence root, first build the preceding identity runtime with its existing ignored environment file:

```bash
docker compose --env-file 05-identity-delegation/code/.env -f 05-identity-delegation/code/docker-compose.yml build gateway
bash 08-observability-audit/code/scripts/check.sh
bash 08-observability-audit/code/scripts/live_check.sh
```

The existing identity fixture environment file must be initialized using that project's setup procedure. Never commit it. API: <http://127.0.0.1:8228/docs>; local fixture IdP: <http://localhost:8428>. The collector has no host-published port. The live check stops only this project's collector and restores it on failure; earlier stacks and the Kubernetes context are untouched.

## Evidence

Nine focused tests, Ruff formatting/lint and strict mypy pass. A real HTTP OTLP test decodes official trace/metric protobufs and exercises rejected exports. Live Keycloak issuance, privacy-preserving foreign-resource 404, official MCP evidence write, collector receipt and collector outage were exercised. During outage, the same allowed/denied operations remain correct and delivery failures are visible at `/health/telemetry`. Gateway and collector logs contain no synthetic secret canary.

Inspect bounded collector output with:

```bash
cd 08-observability-audit/code
docker compose --env-file ../../05-identity-delegation/code/.env logs --tail=250 collector
```

Decision counts use `learning.authorization.decisions` with bounded layer, action, decision and reason attributes. `learning.operation.duration` is a millisecond histogram; `learning.telemetry.failures` reports export/sink failures. Join canonical authorization span events and JSON audit records by `trace_id`; use `request_id` for HTTP correlation. No dashboard or query backend is deployed.

## Security Limits

Only sanitized attributes are exported. Resource/principal/tenant references use category-separated HMACs; the random process-local key means references are not stable across processes or restarts. Only validated trace context and replacement request IDs propagate; baggage and tracestate do not. Tokens, content and exporter exception bodies are not recorded.

The private local collector uses HTTP without authentication. Docker-daemon access permits reading logs; this is not production access control. Collector and gateway JSON logs rotate at 10 MiB with two files, not a time-based retention or immutable audit guarantee. Debug collection is local inspection, not durable storage. SDK batching is bounded but queue overflow is not individually counted. Export failures do not change authorization, and high-risk writes do not wait for durable audit acknowledgment. Production use requires authenticated transport, restricted readers, stable managed HMAC keys, durable audit storage and an explicit fail-closed audit policy where mandated.

Legacy API policy/service instrumentation is tested for allow, pre-policy foreign denial and policy failure. Inherited 107 Python tests, 21 Rego tests, tenant mutation, live mesh and collector outage/recovery checks passed after naming changes. [Incident queries](observability/queries.md) cover latency, errors and decision distribution. Existing kind cluster and older running containers retain historical names; guarded compatibility preserves the cluster. Production audit/access/retention requirements remain documented limits.