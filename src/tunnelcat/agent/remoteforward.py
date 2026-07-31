from __future__ import annotations

import asyncio
import logging

from ..common.netopt import set_nodelay
from ..mux import Session
from ..protocol import messages as M

logger = logging.getLogger(__name__)


class AgentRemoteForwards:
    """Agent-side half of -R: bind a listener here, open a channel back to
    the operator for each connection so *it* does the connect()."""

    def __init__(self, session: Session):
        self.session = session
        # Keeps each bound Server alive for the life of the forward. Never
        # read back, just holding the reference so it isn't garbage
        # collected out from under the listener.
        self._servers: dict[str, asyncio.base_events.Server] = {}

    async def handle_control_message(self, d: dict) -> bool:
        if d.get("type") != M.MSG_START_REMOTE_FORWARD:
            return False
        request_id = d["request_id"]
        target_host, target_port = d["target_host"], d["target_port"]
        try:
            server = await asyncio.start_server(
                lambda r, w: self._on_conn(r, w, target_host, target_port),
                d["listen_host"],
                d["listen_port"],
            )
        except OSError as exc:
            logger.info("remote forward bind failed: %s", exc)
            await self.session.send_control(M.remote_forward_failed(request_id, str(exc)))
            return True
        bound_port = server.sockets[0].getsockname()[1]
        self._servers[request_id] = server
        await self.session.send_control(M.remote_forward_started(request_id, bound_port))
        return True

    async def _on_conn(self, reader, writer, target_host: str, target_port: int) -> None:
        set_nodelay(writer)
        try:
            ch = await self.session.open_channel(metadata=M.connect_target(target_host, target_port))
        except Exception:
            logger.exception("remote forward: failed to open channel back for %s:%s", target_host, target_port)
            writer.close()
            return
        await ch.pump_duplex(reader, writer)
