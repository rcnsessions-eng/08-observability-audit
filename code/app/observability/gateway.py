import re
import sqlite3
import time
import uuid
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager, contextmanager
from contextvars import ContextVar
from typing import Literal

import httpx
from fastapi import FastAPI
from opentelemetry.context import Context
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.api.routes import learning_service
from app.authz.client import OPAClient
from app.authz.contracts import AuthorizationInput, CanonicalAction, Decision, RequestContext
from app.domain import ContentCollection, Learner, Principal, PublicProgress
from app.errors import ServiceError
from app.identity.main import DelegatedLearningService
from app.identity.main import create_app as identity_app
from app.identity.tokens import TokenVerifier
from app.isolation.service import IsolatedLearningService
from app.observability.telemetry import ACTIONS, Telemetry, request_reference
from learning_tools.contracts import AssessmentArguments, EvidenceArguments, SearchArguments
from learning_tools.repository import ToolRepository
from learning_tools.services import PolicyClient

operation_action: ContextVar[str] = ContextVar("telemetry_action", default="other")
propagator = TraceContextTextMapPropagator()


def propagation_headers() -> dict[str, str]:
    carrier: dict[str, str] = {}
    propagator.inject(carrier)
    carrier.pop("tracestate", None)
    carrier["x-request-id"] = request_reference.get() or uuid.uuid4().hex
    return carrier


async def inject_context(request: httpx.Request) -> None:
    request.headers.update(propagation_headers())


class ObservedAPIClient(OPAClient):
    def __init__(
        self, telemetry: Telemetry, url: str, transport: httpx.BaseTransport | None
    ) -> None:
        super().__init__(url, transport=transport)
        self.telemetry = telemetry
        self.client.event_hooks["request"].append(
            lambda request: request.headers.update(propagation_headers())
        )

    def decide(self, context: AuthorizationInput) -> Decision:
        started = time.monotonic()
        decision: Decision | None = None
        with self.telemetry.span("policy", context.action):
            try:
                decision = super().decide(context)
                return decision
            finally:
                self.telemetry.decision(
                    context.principal.id,
                    context.tenant.id,
                    context.resource.id,
                    context.action,
                    "policy",
                    "error" if decision is None else "allow" if decision.allow else "deny",
                    "policy_unavailable" if decision is None else decision.reason_code,
                    None if decision is None else decision.policy_version,
                    started,
                )


class ObservedRepository(ToolRepository):
    def __init__(self, telemetry: Telemetry) -> None:
        self.telemetry = telemetry
        super().__init__()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        with self.telemetry.span("repository", operation_action.get()):
            with super().transaction() as connection:
                yield connection

    def get_learner_metadata(self, tenant_id: str, learner_id: str) -> Learner | None:
        with self.telemetry.span("repository", operation_action.get()):
            return super().get_learner_metadata(tenant_id, learner_id)


class ObservedPolicy(PolicyClient):
    def __init__(
        self, telemetry: Telemetry, url: str, transport: httpx.AsyncBaseTransport | None = None
    ) -> None:
        super().__init__(url, transport)
        self.telemetry = telemetry
        self.client.event_hooks["request"].append(inject_context)

    async def enforce_context(self, context: AuthorizationInput) -> None:
        context = context.model_copy(
            update={"request": RequestContext(id=request_reference.get() or uuid.uuid4().hex)}
        )
        started = time.monotonic()
        outcome: Literal["allow", "deny", "error"] = "allow"
        reason = (
            "TENANT_APPROVED_CONTENT"
            if context.action == "content.search"
            else "OWNER_AND_TENANT_MATCH"
        )
        version: Literal["1.0.0", "1.1.0"] | None = (
            "1.1.0" if context.action in {"assessment.create", "evidence.record"} else "1.0.0"
        )
        with self.telemetry.span("policy", context.action):
            try:
                await super().enforce_context(context)
            except ServiceError as error:
                outcome = "deny" if error.status_code < 500 else "error"
                reason = "ACCESS_DENIED" if outcome == "deny" else "policy_unavailable"
                if outcome == "error":
                    version = None
                raise
            finally:
                self.telemetry.decision(
                    context.principal.id,
                    context.tenant.id,
                    context.resource.id,
                    context.action,
                    "policy",
                    outcome,
                    reason,
                    version,
                    started,
                )


class TraceMiddleware:
    def __init__(self, app: ASGIApp, telemetry: Telemetry) -> None:
        self.app = app
        self.telemetry = telemetry

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = {
            key.decode("latin1"): value.decode("latin1") for key, value in scope["headers"]
        }
        requested = headers.get("x-request-id", "")
        request_id = requested if re.fullmatch(r"[a-f0-9]{32}", requested) else uuid.uuid4().hex
        request_token = request_reference.set(request_id)
        scope = {
            **scope,
            "headers": [
                (key, value)
                for key, value in scope["headers"]
                if key.lower() != b"x-request-id"
            ]
            + [(b"x-request-id", request_id.encode())],
        }
        path = scope["path"]
        proposed = path.removeprefix("/v1/delegated/tools/")
        action = (
            proposed
            if proposed in ACTIONS
            else "content.search"
            if path == "/v1/content"
            else "progress.read"
            if path.startswith("/v1/learners/")
            else "other"
        )
        action_token = operation_action.set(action)
        parent = propagator.extract(
            {"traceparent": headers.get("traceparent", "")}, context=Context()
        )
        try:
            with self.telemetry.tracer.start_as_current_span(
                "api." + action,
                context=parent,
                record_exception=False,
                set_status_on_exception=False,
            ) as span:

                async def traced_send(message: Message) -> None:
                    if message["type"] == "http.response.start":
                        span.set_attribute("http.response.status_code", message["status"])
                        message = {
                            **message,
                            "headers": [
                                *message.get("headers", []),
                                (
                                    b"x-trace-id",
                                    format(span.get_span_context().trace_id, "032x").encode(),
                                ),
                            ],
                        }
                    await send(message)

                await self.app(scope, receive, traced_send)
        finally:
            operation_action.reset(action_token)
            request_reference.reset(request_token)


def create_app(
    telemetry: Telemetry,
    verifier: TokenVerifier | None = None,
    policy_transport: httpx.AsyncBaseTransport | None = None,
    api_transport: httpx.BaseTransport | None = None,
    policy_url: str = "http://opa:8181",
) -> FastAPI:
    repository = ObservedRepository(telemetry)
    policy = ObservedPolicy(telemetry, policy_url, policy_transport)
    api_policy = ObservedAPIClient(telemetry, policy_url, api_transport)

    class ObservedAPIService(IsolatedLearningService):
        @contextmanager
        def operation(
            self, principal: Principal, action: CanonicalAction, resource: str
        ) -> Iterator[None]:
            started = time.monotonic()
            outcome: Literal["allow", "deny", "error"] = "allow"
            reason = "OWNER_AND_TENANT_MATCH"
            with telemetry.span("service", action):
                try:
                    yield
                except ServiceError as error:
                    outcome = "deny" if error.status_code < 500 else "error"
                    reason = error.code
                    raise
                finally:
                    telemetry.decision(
                        principal.subject,
                        principal.tenant_id,
                        resource,
                        action,
                        "service",
                        outcome,
                        reason,
                        None,
                        started,
                    )

        def read_progress(self, principal: Principal, learner_id: str) -> PublicProgress:
            with self.operation(principal, "progress.read", learner_id):
                return super().read_progress(principal, learner_id)

        def list_content(self, principal: Principal, limit: int) -> ContentCollection:
            with self.operation(principal, "content.search", "approved-" + principal.tenant_id):
                return super().list_content(principal, limit)

    class ObservedService(DelegatedLearningService):
        @contextmanager
        def operation(
            self, principal: Principal, action: CanonicalAction, resource: str
        ) -> Iterator[None]:
            started = time.monotonic()
            outcome: Literal["allow", "deny", "error"] = "allow"
            reason = "OWNER_AND_TENANT_MATCH"
            action_token = operation_action.set(action)
            with telemetry.span("service", action):
                try:
                    yield
                except ServiceError as error:
                    outcome = "deny" if error.status_code < 500 else "error"
                    reason = error.code
                    raise
                finally:
                    telemetry.decision(
                        principal.subject,
                        principal.tenant_id,
                        resource,
                        action,
                        "service",
                        outcome,
                        reason,
                        None,
                        started,
                    )
                    operation_action.reset(action_token)

        async def search(
            self, principal: Principal, args: SearchArguments
        ) -> dict[str, object]:
            with self.operation(principal, "content.search", "approved-" + principal.tenant_id):
                return await super().search(principal, args)

        async def progress(self, principal: Principal, learner_id: str) -> dict[str, object]:
            with self.operation(principal, "progress.read", learner_id):
                return await super().progress(principal, learner_id)

        async def create_assessment(
            self, principal: Principal, args: AssessmentArguments, deadline: float
        ) -> dict[str, object]:
            with self.operation(principal, "assessment.create", args.course_id):
                return await super().create_assessment(principal, args, deadline)

        async def record_evidence(
            self, principal: Principal, args: EvidenceArguments, deadline: float
        ) -> dict[str, object]:
            with self.operation(principal, "evidence.record", args.course_id):
                return await super().record_evidence(principal, args, deadline)

    application = identity_app(
        repository, verifier, policy, api_transport, service_factory=ObservedService
    )
    application.dependency_overrides[learning_service] = lambda: ObservedAPIService(
        repository, api_policy, request_reference.get() or uuid.uuid4().hex
    )
    application.add_middleware(TraceMiddleware, telemetry=telemetry)
    application.state.telemetry_repository = repository
    previous_lifespan = application.router.lifespan_context

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        try:
            async with previous_lifespan(app):
                yield
        finally:
            api_policy.close()
            telemetry.close()

    application.router.lifespan_context = lifespan
    application.title = "Privacy-Aware Learning Gateway"
    return application
