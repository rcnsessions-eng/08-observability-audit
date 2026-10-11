import asyncio
import os
import sys
import uuid

import httpx
from mcp import Client, StdioServerParameters

CANARY = "FAKE-SECRET-OBSERVABILITY-DO-NOT-LOG"


async def main() -> None:
    gateway = os.environ["LEARNING_GATEWAY_URL"]
    issuer = os.environ["LEARNING_IDP_URL"]
    async with httpx.AsyncClient(timeout=5, trust_env=False) as http:
        user = await http.post(
            issuer + "/protocol/openid-connect/token",
            data={
                "grant_type": "password",
                "client_id": "learning-client",
                "username": "learner-red-1",
                "password": os.environ["LEARNING_DEMO_PASSWORD"],
            },
        )
        workload = await http.post(
            issuer + "/protocol/openid-connect/token",
            data={
                "grant_type": "client_credentials",
                "client_id": "agent-adapter",
                "client_secret": os.environ["LEARNING_AGENT_SECRET"],
            },
        )
        assert user.status_code == workload.status_code == 200, "Token issuance failed"
        user_token = user.json()["access_token"]
        workload_token = workload.json()["access_token"]
        headers = {
            "Authorization": "Bearer " + user_token,
            "X-Workload-Authorization": "Bearer " + workload_token,
            "X-Request-ID": CANARY,
            "baggage": "secret=" + CANARY,
        }
        for learner, expected in [("learner-red-1", 200), ("learner-blue-1", 404)]:
            response = await http.post(
                gateway + "/v1/delegated/tools/progress.read",
                headers=headers,
                json={"args": {"learner_id": learner}},
            )
            assert response.status_code == expected, "Authorization outcome changed"
            assert len(response.headers["x-trace-id"]) == 32
            assert response.headers["x-request-id"] != CANARY
        params = StdioServerParameters(
            command=sys.executable,
            args=["-m", "app.observability.relay"],
            env={
                "PYTHONPATH": os.environ["PYTHONPATH"],
                "LEARNING_GATEWAY_URL": gateway,
                "LEARNING_USER_TOKEN": user_token,
                "LEARNING_WORKLOAD_TOKEN": workload_token,
            },
        )
        async with Client(params, read_timeout_seconds=5) as client:
            tools = await client.list_tools()
            assert len(tools.tools) == 4
            result = await client.call_tool(
                "evidence.record",
                {
                    "args": {
                        "course_id": "course-red",
                        "kind": "content_read",
                        "idempotency_key": "observability-" + uuid.uuid4().hex,
                    },
                },
            )
            assert not result.is_error, "Real MCP evidence call failed"
        print("Real provider, sanitized correlation, allow/deny and MCP checks passed")


if __name__ == "__main__":
    asyncio.run(main())
