import asyncio
import logging
import os
import uuid

from app.identity.relay import GatewayRelay
from app.observability.gateway import inject_context
from app.observability.runtime import create_telemetry
from app.observability.telemetry import Telemetry, request_reference
from learning_tools.server import create_server


class ObservedRelay(GatewayRelay):
    def __init__(
        self, telemetry: Telemetry, url: str, user_token: str, workload_token: str
    ) -> None:
        super().__init__(url, user_token, workload_token)
        self.telemetry = telemetry
        self.client.event_hooks["request"].append(inject_context)

    async def invoke(self, action: str, args: dict[str, object]) -> dict[str, object]:
        token = request_reference.set(uuid.uuid4().hex)
        try:
            with self.telemetry.span("mcp", action):
                return await super().invoke(action, args)
        finally:
            request_reference.reset(token)


async def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(name)s %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)
    telemetry = create_telemetry()
    relay = ObservedRelay(
        telemetry,
        os.getenv("LEARNING_GATEWAY_URL", "http://gateway:8000"),
        os.getenv("LEARNING_USER_TOKEN", ""),
        os.getenv("LEARNING_WORKLOAD_TOKEN", ""),
    )
    try:
        principal = await relay.principal()
        await create_server(relay, principal).run_stdio_async()
    finally:
        await relay.client.aclose()
        telemetry.close()


if __name__ == "__main__":
    asyncio.run(main())
