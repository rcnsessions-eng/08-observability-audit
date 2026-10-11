import asyncio
import json

import httpx
from fastapi.testclient import TestClient
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from test_tokens import WORKLOAD_SUBJECT, token, verifier
from test_tokens import signing_key as signing_key

from app.observability.gateway import create_app
from app.observability.relay import ObservedRelay
from app.observability.telemetry import Telemetry

CANARY = "FAKE-SECRET-PRD08-DO-NOT-LOG"


def test_legacy_api_audits_allow_foreign_denial_and_policy_failure(signing_key):
    exporter = InMemorySpanExporter()
    events = []
    requests = []
    available = True

    def opa(request):
        requests.append(request)
        return policy_response(request) if available else httpx.Response(503)

    telemetry = Telemetry(exporter, sink=events.append)
    application = create_app(
        telemetry, verifier(signing_key), httpx.MockTransport(opa), httpx.MockTransport(opa)
    )
    with TestClient(application) as client:
        allowed = client.get(
            "/v1/learners/learner-red-1/progress", headers=headers(signing_key)
        )
        assert allowed.status_code == 200
        trace = int(allowed.headers["x-trace-id"], 16)
        assert {span.name.split(".")[0] for span in exporter.get_finished_spans()} >= {
            "api",
            "service",
            "policy",
            "repository",
        }
        assert {span.context.trace_id for span in exporter.get_finished_spans()} == {trace}
        assert (
            requests[-1].headers["traceparent"].split("-")[1] == allowed.headers["x-trace-id"]
        )
        count = len(requests)
        denied = client.get(
            "/v1/learners/learner-blue-1/progress", headers=headers(signing_key)
        )
        assert denied.status_code == 404 and len(requests) == count
        assert events[-1].decision == "deny" and events[-1].reason_code == "not_found"
        available = False
        failed = client.get("/v1/content", headers=headers(signing_key))
        assert failed.status_code == 503
        assert events[-1].decision == "error"
        assert any(
            event.layer == "policy" and event.reason_code == "policy_unavailable"
            for event in events
        )


def headers(key):
    return {
        "Authorization": "Bearer "
        + token(key, scope="progress.read evidence.record content.search"),
        "X-Workload-Authorization": "Bearer "
        + token(
            key,
            aud="learning-gateway-workload",
            sub=WORKLOAD_SUBJECT,
            azp="agent-adapter",
            scope="tools.invoke",
        ),
    }


def policy_response(request):
    action = json.loads(request.content)["input"]["action"]
    return httpx.Response(
        200,
        json={
            "result": {
                "allow": True,
                "reason_code": "TENANT_APPROVED_CONTENT"
                if action == "content.search"
                else "OWNER_AND_TENANT_MATCH",
                "policy_version": "1.1.0" if action == "evidence.record" else "1.0.0",
            }
        },
    )


def test_gateway_policy_repository_trace_and_prepolicy_denial(signing_key, caplog):
    exporter = InMemorySpanExporter()
    events = []
    requests = []
    telemetry = Telemetry(exporter, sink=events.append)

    def opa(request):
        requests.append(request)
        return policy_response(request)

    application = create_app(
        telemetry, verifier(signing_key), httpx.MockTransport(opa), httpx.MockTransport(opa)
    )
    with TestClient(application) as client:
        result = client.post(
            "/v1/delegated/tools/progress.read",
            headers={
                **headers(signing_key),
                "X-Request-ID": CANARY,
                "baggage": "secret=" + CANARY,
                "tracestate": "private=" + CANARY,
            },
            json={"args": {"learner_id": "learner-red-1"}},
        )
        assert result.status_code == 200
        trace_id = int(result.headers["x-trace-id"], 16)
        spans = exporter.get_finished_spans()
        assert {span.name.split(".")[0] for span in spans} >= {
            "api",
            "service",
            "policy",
            "repository",
        }
        assert {span.context.trace_id for span in spans} == {trace_id}
        assert events[0].request_id == result.headers["x-request-id"]
        assert requests[0].headers["traceparent"].split("-")[1] == result.headers["x-trace-id"]
        assert json.loads(requests[0].content)["input"]["request"]["id"] == events[0].request_id
        assert "baggage" not in requests[0].headers and "tracestate" not in requests[0].headers
        calls = len(requests)
        denied = client.post(
            "/v1/delegated/tools/progress.read",
            headers=headers(signing_key),
            json={"args": {"learner_id": "learner-blue-1"}},
        )
        assert denied.status_code == 404 and len(requests) == calls
        assert events[-1].decision == "deny" and events[-1].reason_code == "not_found"
        assert application.state.telemetry_repository.evidence_count() == 0
        assert CANARY not in caplog.text + json.dumps(
            [span.to_json() for span in exporter.get_finished_spans()]
        )


def test_real_relay_context_reaches_gateway_without_payload_capture(signing_key):
    exporter = InMemorySpanExporter()
    telemetry = Telemetry(exporter, sink=lambda event: None)
    application = create_app(
        telemetry,
        verifier(signing_key),
        httpx.MockTransport(policy_response),
        httpx.MockTransport(policy_response),
    )

    async def run():
        auth = headers(signing_key)
        relay = ObservedRelay(
            telemetry,
            "http://gateway",
            auth["Authorization"].removeprefix("Bearer "),
            auth["X-Workload-Authorization"].removeprefix("Bearer "),
        )
        await relay.client.aclose()
        relay.client = httpx.AsyncClient(
            base_url="http://gateway",
            transport=httpx.ASGITransport(app=application),
            headers=auth,
            event_hooks={"request": relay.client.event_hooks["request"]},
        )
        try:
            result = await relay.invoke(
                "content.search", {"query": CANARY, "collection": "approved", "limit": 1}
            )
            assert result == {"items": []}
        finally:
            await relay.client.aclose()

    with TestClient(application):
        asyncio.run(run())
        spans = exporter.get_finished_spans()
        assert {span.name.split(".")[0] for span in spans} >= {
            "mcp",
            "api",
            "service",
            "policy",
            "repository",
        }
        assert len({span.context.trace_id for span in spans}) == 1
        assert CANARY not in json.dumps([span.to_json() for span in spans])
