import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from opentelemetry.sdk.metrics.export import InMemoryMetricReader
from opentelemetry.sdk.trace.export import SpanExporter
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from pydantic import ValidationError

from app.errors import ServiceError
from app.observability.runtime import create_telemetry
from app.observability.telemetry import AuditEvent, Telemetry

CANARY = "FAKE-SECRET-PRD08-DO-NOT-LOG"


def test_redacted_audit_spans_and_bounded_metric_labels(caplog):
    exporter = InMemorySpanExporter()
    reader = InMemoryMetricReader()
    events = []
    telemetry = Telemetry(exporter, [reader], events.append, b"k" * 32)
    with telemetry.span("api", "progress.read"):
        with telemetry.span("policy", "progress.read"):
            telemetry.decision(
                CANARY,
                CANARY,
                CANARY,
                "progress.read",
                "policy",
                "deny",
                CANARY,
                "1.0.0",
                time.monotonic(),
            )
    assert len(events) == 1 and events[0].reason_code == "internal_error"
    assert events[0].principal_reference != events[0].tenant_reference
    spans = exporter.get_finished_spans()
    assert spans[0].context.trace_id == spans[1].context.trace_id
    assert spans[0].parent.span_id == spans[1].context.span_id
    assert CANARY not in json.dumps([span.to_json() for span in spans])
    assert CANARY not in events[0].model_dump_json() + caplog.text
    data = reader.get_metrics_data()
    assert data is not None
    for resource in data.resource_metrics:
        for scope in resource.scope_metrics:
            for metric in scope.metrics:
                for point in metric.data.data_points:
                    assert set(point.attributes) <= {"action", "layer", "decision", "outcome"}
                    assert CANARY not in str(point.attributes)
    telemetry.close()


def test_exception_details_are_not_recorded():
    exporter = InMemorySpanExporter()
    telemetry = Telemetry(exporter)
    with pytest.raises(ServiceError):
        with telemetry.span("service", CANARY):
            raise ServiceError(404, "not_found", CANARY)
    span = exporter.get_finished_spans()[0]
    assert span.name == "service.other"
    assert not span.events and CANARY not in span.to_json()
    telemetry.close()


@pytest.mark.parametrize("failure", ["export", "audit"])
def test_pipeline_failure_visible_without_changing_authorization(failure, caplog):
    class FailedExporter(SpanExporter):
        def export(self, spans):
            raise RuntimeError(CANARY)

    def failed_sink(event):
        raise RuntimeError(CANARY)

    telemetry = Telemetry(
        FailedExporter() if failure == "export" else InMemorySpanExporter(),
        sink=failed_sink if failure == "audit" else None,
    )
    with telemetry.span("service", "evidence.record"):
        telemetry.decision(
            "user",
            "tenant",
            "resource",
            "evidence.record",
            "service",
            "allow",
            "OWNER_AND_TENANT_MATCH",
            "1.1.0",
            time.monotonic(),
        )
    assert telemetry.failure_count >= 1
    assert "telemetry_delivery_failed" in caplog.text and CANARY not in caplog.text
    telemetry.close()


def test_audit_schema_rejects_extra_payloads_and_bad_references():
    with pytest.raises(ValidationError):
        AuditEvent.model_validate({"token": CANARY})
    with pytest.raises(ValueError, match="at least 32 bytes"):
        Telemetry(InMemorySpanExporter(), reference_key=b"short")


def test_real_otlp_encoding_and_safe_http_failure(caplog):
    from opentelemetry.proto.collector.metrics.v1.metrics_service_pb2 import (
        ExportMetricsServiceRequest,
    )
    from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import (
        ExportTraceServiceRequest,
    )

    received = []

    class Receiver(BaseHTTPRequestHandler):
        def do_POST(self):
            received.append((self.path, self.rfile.read(int(self.headers["Content-Length"]))))
            self.send_response(200 if self.server.deliver else 400)
            self.end_headers()
            self.wfile.write(b"{}" if self.server.deliver else CANARY.encode())

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Receiver)
    server.deliver = True
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    telemetry = create_telemetry("http://127.0.0.1:" + str(server.server_port))
    try:
        with telemetry.span("policy", "progress.read"):
            telemetry.decision(
                CANARY,
                CANARY,
                CANARY,
                "progress.read",
                "policy",
                "deny",
                "ACCESS_DENIED",
                "1.0.0",
                time.monotonic(),
            )
        assert telemetry.provider.force_flush(2000)
        assert telemetry.metrics.force_flush(2000)
        trace_payload = ExportTraceServiceRequest.FromString(
            next(body for path, body in received if path == "/v1/traces")
        )
        metric_payload = ExportMetricsServiceRequest.FromString(
            next(body for path, body in received if path == "/v1/metrics")
        )
        assert "authorization.decision" in str(trace_payload)
        assert "learning.authorization.decisions" in str(metric_payload)
        assert CANARY not in str(trace_payload) + str(metric_payload) + caplog.text
        server.deliver = False
        with telemetry.span("service", "evidence.record"):
            pass
        assert telemetry.provider.force_flush(2000)
        assert telemetry.failure_count > 0
        assert "telemetry_delivery_failed" in caplog.text
        assert CANARY not in caplog.text
    finally:
        telemetry.close()
        server.shutdown()
        server.server_close()
        worker.join()
