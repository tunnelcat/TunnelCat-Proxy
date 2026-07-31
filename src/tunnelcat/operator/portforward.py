"""-L (local->remote) and -R (remote->local) port forwarding, driven from
the operator side.

-L reuses exactly the SOCKS5 mechanism minus the SOCKS handshake: a fixed
local listener whose every connection opens a channel with a fixed target,
and the agent does the connect()/DNS.

-R asks the agent (over the control channel) to bind a listener. Each
connection accepted there causes the agent to open a channel back to the
operator, and the operator does the connect(). Useful for exposing
something reachable from your side back into the target's network.
"""

from __future__ import annotations

import asyncio
import logging
import secrets

from ..common.netopt import set_nodelay
from ..mux import Session
from ..protocol import messages as M

logger = logging.getLogger(__name__)


class LocalForward:
    """-L listen_host:listen_port -> target_host:target_port (agent connects out)."""

    def __init__(self, session: Session, listen_host: str, listen_port: int, target_host: str, target_port: int):
        self.session = session
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.target_host = target_host
        self.target_port = target_port
        self._server: asyncio.base_events.Server | None = None

    async def start(self):
        self._server = await asyncio.start_server(self._on_conn, self.listen_host, self.listen_port)
        return self._server.sockets[0].getsockname()

    def close(self):
        if self._server:
            self._server.close()

    async def _on_conn(self, reader, writer):
        set_nodelay(writer)
        try:
            ch = await self.session.open_channel(metadata=M.connect_target(self.target_host, self.target_port))
        except Exception:
            logger.exception("local forward: failed to open channel to %s:%s", self.target_host, self.target_port)
            writer.close()
            return
        await ch.pump_duplex(reader, writer)


class RemoteForwardManager:
    """-R: ask the agent to bind a listener; operator connects out per-connection."""

    def __init__(self, session: Session):
        self.session = session
        self._pending: dict[str, asyncio.Future] = {}

    async def start(self, listen_host: str, listen_port: int, target_host: str, target_port: int, timeout: float = 15.0) -> int:
        request_id = secrets.token_hex(8)
        fut: asyncio.Future = asyncio.get_event_loop().create_future()
        self._pending[request_id] = fut
        await self.session.send_control(
            M.start_remote_forward(request_id, listen_host, listen_port, target_host, target_port)
        )
        try:
            return await asyncio.wait_for(fut, timeout)
        finally:
            self._pending.pop(request_id, None)

    def handle_control_message(self, d: dict) -> bool:
        """Returns True if this manager handled the message."""
        t = d.get("type")
        if t == M.MSG_REMOTE_FORWARD_STARTED:
            fut = self._pending.get(d["request_id"])
            if fut and not fut.done():
                fut.set_result(d["bound_port"])
            return True
        if t == M.MSG_REMOTE_FORWARD_FAILED:
            fut = self._pending.get(d["request_id"])
            if fut and not fut.done():
                fut.set_exception(RuntimeError(d.get("reason", "remote forward failed")))
            return True
        return False
