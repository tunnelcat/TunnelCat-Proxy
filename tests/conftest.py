"""Shared test fixtures.

RelayServer instances spawn background tasks (the expiry sweep loop,
serve_forever()) that outlive a single test unless explicitly cancelled --
leaving them dangling can stall pytest-asyncio's event loop teardown after
the test body has already finished and passed. Route all relay creation in
tests through make_relay so cleanup is automatic.
"""

from __future__ import annotations

import asyncio

import pytest

from tunnelcat.relay.server import RelayServer


@pytest.fixture
async def make_relay():
    created = []

    async def _make(token="tok", allow_next=None, default_next=None, session_timeout=300.0):
        relay = RelayServer(
            "127.0.0.1",
            0,
            admin_token=token,
            allow_next=allow_next or set(),
            default_next=default_next,
            session_timeout=session_timeout,
        )
        server = await asyncio.start_server(relay._handle_conn, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        relay.bind_port = port
        relay.self_label = f"127.0.0.1:{port}"
        relay._server = server
        sweep_task = asyncio.create_task(relay._sweep_expired())
        serve_task = asyncio.create_task(server.serve_forever())
        created.append((server, sweep_task, serve_task))
        return relay

    yield _make

    for server, sweep_task, serve_task in created:
        server.close()
        for task in (sweep_task, serve_task):
            task.cancel()
            try:
                await asyncio.wait_for(task, timeout=5)
            except (asyncio.CancelledError, asyncio.TimeoutError):
                pass
