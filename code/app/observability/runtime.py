import logging
import os
from collections.abc import Callable

from fastapi import FastAPI
from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.metrics.export import (
    MetricExportResult,
    MetricsData,
    PeriodicExportingMetricReader,
)
from requests import Session

from app.observability.gateway import create_app as audited_app
from app.observability.telemetry import Telemetry


class SafeExportLog(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = "telemetry_export_failed"
        record.args = ()
        record.exc_info = None
        record.stack_info = None
        return True


class GuardedMetrics(OTLPMetricExporter):
    failed: Callable[[], None] = lambda: None

    def export(
        self, metrics_data: MetricsData, timeout_millis: float | None = 10000, **kwargs: object
    ) -> MetricExportResult:
        try:
            result = super().export(metrics_data, timeout_millis=timeout_millis)
            if result is MetricExportResult.SUCCESS:
                return result
        except Exception:
            pass
        self.failed()
        return MetricExportResult.FAILURE


def create_telemetry(endpoint: str = "http://collector:4318") -> Telemetry:
    for module in ("trace_exporter", "metric_exporter"):
        logging.getLogger("opentelemetry.exporter.otlp.proto.http." + module).addFilter(
            SafeExportLog()
        )
    traces_session = Session()
    traces_session.trust_env = False
    metrics_session = Session()
    metrics_session.trust_env = False
    exporter = OTLPSpanExporter(
        endpoint=endpoint + "/v1/traces", timeout=0.2, headers={}, session=traces_session
    )
    metrics = GuardedMetrics(
        endpoint=endpoint + "/v1/metrics", timeout=0.2, headers={}, session=metrics_session
    )
    reader = PeriodicExportingMetricReader(
        metrics, export_interval_millis=5000, export_timeout_millis=1000
    )
    telemetry = Telemetry(exporter, [reader], background=True)
    metrics.failed = telemetry.failed
    return telemetry


def create_app() -> FastAPI:
    logging.basicConfig(level=logging.INFO, format="%(name)s %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)
    telemetry = create_telemetry()
    application = audited_app(telemetry, policy_url=os.getenv("OPA_URL", "http://opa:8181"))

    @application.get("/health/telemetry")
    def delivery_status() -> dict[str, int]:
        return {"delivery_failures": telemetry.failure_count}

    application.title = "Privacy-Aware Learning Gateway"
    return application
