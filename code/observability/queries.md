# Incident Queries

The local collector prints sanitized OTLP records, not a query backend. These PromQL examples assume an external Prometheus-compatible exporter translating OTel names and units. Confirm actual exported names first.

```promql
sum by (decision) (rate(learning_authorization_decisions_total{layer="policy"}[5m]))
sum(rate(learning_authorization_decisions_total{layer="policy",decision="error"}[5m]))
histogram_quantile(0.95, sum by (le, action) (rate(learning_operation_duration_milliseconds_bucket{layer="policy"}[5m])))
sum(rate(learning_telemetry_failures_total[5m]))
```

For the executed local environment, select JSON audit records with `layer=policy`, group by `decision` or `reason_code`, and use `duration_ms` for decision latency. `policy_unavailable` covers timeout/unavailable errors. Filter collector output by the response's `x-trace-id` to reconstruct MCP, API, service, policy and repository spans. Foreign-resource rejection has a service `not_found` event without a policy call.

Triage: establish action and trace ID; compare service/policy outcomes; distinguish pre-policy denial from policy failure; inspect delivery failures; confirm denied writes returned no receipt. Never paste tokens or private payloads into incident notes. Missing export data does not prove absence of an operation. All spans are sampled in this local fixture. Production sampling and durable audit policy require explicit operational approval.