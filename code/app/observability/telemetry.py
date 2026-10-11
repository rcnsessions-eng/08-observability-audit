import hashlib
import hmac
import logging
import secrets
import time
import uuid
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Literal

from opentelemetry import trace
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import MetricReader
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import ReadableSpan, TracerProvider
from opentelemetry.sdk.trace.export import (
    BatchSpanProcessor,
    SimpleSpanProcessor,
    SpanExporter,
    SpanExportResult,
)
from opentelemetry.trace import Span, StatusCode
from pydantic import BaseModel, ConfigDict, Field

from app.authz.contracts import CanonicalAction
from app.errors import ServiceError

ACTIONS = frozenset({"content.search", "progress.read", "assessment.create", "evidence.record"})
LAYERS = frozenset({"api", "mcp", "service", "policy", "repository"})
REASONS = frozenset(
    {
        "TENANT_APPROVED_CONTENT",
        "OWNER_AND_TENANT_MATCH",
        "ACCESS_DENIED",
        "not_found",
        "insufficient_scope",
        "unauthenticated",
        "membership_required",
        "policy_unavailable",
        "service_timeout",
        "idempotency_conflict",
        "internal_error",
    }
)
request_reference: ContextVar[str] = ContextVar("telemetry_request", default="")
audit_log = logging.getLogger("learning.security.audit")
pipeline_log = logging.getLogger("learning.telemetry.pipeline")


class AuditEvent(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    schema_version: Literal["1.0"] = "1.0"
    request_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    trace_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    span_id: str = Field(pattern=r"^[a-f0-9]{16}$")
    principal_reference: str = Field(pattern=r"^[a-f0-9]{32}$")
    tenant_reference: str = Field(pattern=r"^[a-f0-9]{32}$")
    resource_reference: str = Field(pattern=r"^[a-f0-9]{32}$")
    workload: Literal["agent-adapter"]
    action: Literal["content.search", "progress.read", "assessment.create", "evidence.record"]
    layer: Literal["service", "policy"]
    decision: Literal["allow", "deny", "error"]
    reason_code: str
    policy_version: Literal["1.0.0", "1.1.0"] | None
    duration_ms: float = Field(ge=0)


class GuardedExporter(SpanExporter):
    def __init__(self, exporter: SpanExporter, failed: Callable[[], None]) -> None:
        self.exporter = exporter
        self.failed = failed

    def export(self, spans: Sequence[ReadableSpan]) -> SpanExportResult:
        try:
            result = self.exporter.export(spans)
            if result is SpanExportResult.SUCCESS:
                return result
        except Exception:
            pass
        self.failed()
        return SpanExportResult.FAILURE

    def shutdown(self) -> None:
        try:
            self.exporter.shutdown()
        except Exception:
            self.failed()


class Telemetry:
    def __init__(
        self,
        exporter: SpanExporter,
        readers: Sequence[MetricReader] = (),
        sink: Callable[[AuditEvent], None] | None = None,
        reference_key: bytes | None = None,
        background: bool = False,
    ) -> None:
        self.reference_key = reference_key or secrets.token_bytes(32)
        if len(self.reference_key) < 32:
            raise ValueError("Audit reference key must be at least 32 bytes")
        self.sink = sink or self.log_event
        resource = Resource(
            {"service.name": "zero-trust-observability-audit", "service.version": "0.1.0"}
        )
        self.metrics = MeterProvider(metric_readers=readers, resource=resource)
        meter = self.metrics.get_meter("learning.security", "0.1.0")
        self.decisions = meter.create_counter("learning.authorization.decisions", unit="1")
        self.duration = meter.create_histogram("learning.operation.duration", unit="ms")
        self.failures = meter.create_counter("learning.telemetry.failures", unit="1")
        self.failure_count = 0
        self.provider = TracerProvider(resource=resource)
        guarded = GuardedExporter(exporter, self.failed)
        self.provider.add_span_processor(
            BatchSpanProcessor(
                guarded,
                max_queue_size=256,
                max_export_batch_size=32,
                schedule_delay_millis=200,
                export_timeout_millis=1000,
            )
            if background
            else SimpleSpanProcessor(guarded)
        )
        self.tracer = self.provider.get_tracer("learning.security", "0.1.0")

    def failed(self) -> None:
        self.failure_count += 1
        self.failures.add(1)
        pipeline_log.warning("telemetry_delivery_failed")

    @staticmethod
    def log_event(event: AuditEvent) -> None:
        audit_log.info(event.model_dump_json())

    def reference(self, category: str, value: str) -> str:
        return hmac.new(
            self.reference_key, (category + ":" + value).encode(), hashlib.sha256
        ).hexdigest()[:32]

    @contextmanager
    def span(self, layer: str, action: str) -> Iterator[Span]:
        bounded_layer = layer if layer in LAYERS else "service"
        bounded_action = action if action in ACTIONS else "other"
        started = time.monotonic()
        outcome = "allow"
        with self.tracer.start_as_current_span(
            bounded_layer + "." + bounded_action,
            attributes={"layer": bounded_layer, "action": bounded_action},
            record_exception=False,
            set_status_on_exception=False,
        ) as span:
            try:
                yield span
            except BaseException as error:
                outcome = (
                    "deny"
                    if isinstance(error, ServiceError) and error.status_code < 500
                    else "error"
                )
                span.set_status(StatusCode.ERROR)
                raise
            finally:
                span.set_attribute("outcome", outcome)
                self.duration.record(
                    (time.monotonic() - started) * 1000,
                    {"layer": bounded_layer, "action": bounded_action, "outcome": outcome},
                )

    def decision(
        self,
        principal: str,
        tenant: str,
        resource: str,
        action: CanonicalAction,
        layer: Literal["service", "policy"],
        outcome: Literal["allow", "deny", "error"],
        reason: str,
        version: Literal["1.0.0", "1.1.0"] | None,
        started: float,
    ) -> None:
        context = trace.get_current_span().get_span_context()
        try:
            event = AuditEvent(
                request_id=request_reference.get() or uuid.uuid4().hex,
                trace_id=format(context.trace_id, "032x"),
                span_id=format(context.span_id, "016x"),
                principal_reference=self.reference("principal", principal),
                tenant_reference=self.reference("tenant", tenant),
                resource_reference=self.reference("resource", resource),
                workload="agent-adapter",
                action=action,
                layer=layer,
                decision=outcome,
                reason_code=reason if reason in REASONS else "internal_error",
                policy_version=version,
                duration_ms=(time.monotonic() - started) * 1000,
            )
            self.decisions.add(1, {"action": event.action, "layer": layer, "decision": outcome})
            trace.get_current_span().add_event(
                "authorization.decision", event.model_dump(exclude_none=True)
            )
            self.sink(event)
        except Exception:
            self.failed()

    def close(self) -> None:
        self.provider.shutdown()
        self.metrics.shutdown()
