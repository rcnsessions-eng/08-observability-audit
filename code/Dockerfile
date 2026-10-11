FROM zero-trust-identity-delegation-gateway:0.1.0 AS runtime
USER root
RUN python -m pip install --no-cache-dir opentelemetry-sdk==1.45.1 opentelemetry-exporter-otlp-proto-http==1.45.1
USER 10001
COPY 08-observability-audit/code/app/observability /app/app/observability
COPY 08-observability-audit/code/scripts /telemetry-scripts
CMD ["uvicorn", "app.observability.runtime:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]

FROM zero-trust-identity-delegation-checks:0.1.0 AS checks
USER root
RUN python -m pip install --no-cache-dir opentelemetry-sdk==1.45.1 opentelemetry-exporter-otlp-proto-http==1.45.1
USER 10001
COPY 08-observability-audit/code/app/observability /app/app/observability
COPY 08-observability-audit/code/tests /telemetry-tests
COPY 08-observability-audit/code/pyproject.toml /telemetry/pyproject.toml
COPY 08-observability-audit/code/scripts /telemetry-scripts
ENV PYTHONPATH=/app/mcp:/app:/identity-tests
ENV MYPY_CACHE_DIR=/dev/null
CMD ["python", "-m", "pytest", "-p", "no:cacheprovider", "/telemetry-tests", "-q"]