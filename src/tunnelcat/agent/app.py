from __future__ import annotations

import asyncio
import logging

from ..common import identity, transport
from ..common.executor import run_channel_acceptor
from ..crypto import pairing
from ..crypto.framing import SecureFramer
from ..crypto.noise import perform_handshake
from ..mux import Session
from ..protocol import messages as M
from ..relay.chain import HopTarget, connect_through_chain
from ..protocol import relaywire as W
from .remoteforward import AgentRemoteForwards

logger = logging.getLogger(__name__)


class AgentApp:
    def __init__(self, on_event=None):
        self.on_event = on_event or (lambda *a, **k: None)
        self.session: Session | None = None
        self._remote_forwards: AgentRemoteForwards | None = None

    async def pair_direct_connect(self, host: str, port: int, code: str) -> None:
        reader, writer = await transport.connect_direct(host, port)
        await self._complete(reader, writer, code)

    async def pair_direct_listen(self, bind_host: str, bind_port: int, code: str) -> None:
        def on_waiting(bound):
            self.on_event("listening", host=bound[0], port=bound[1])

        reader, writer = await transport.listen_once(bind_host, bind_port, on_waiting=on_waiting)
        await self._complete(reader, writer, code)

    async def pair_via_relay(self, chain: list[HopTarget], code: str) -> None:
        sid = pairing.derive_session_id(pairing.code_to_bytes(code)).hex()

        def on_relay_event(ev):
            self.on_event("relay_hop", hop=ev.hop, status=ev.status, detail=ev.detail)

        reader, writer = await connect_through_chain(chain, W.join(sid, "agent"), sid, on_event=on_relay_event)
        await self._complete(reader, writer, code)

    async def _complete(self, reader, writer, code: str) -> None:
        try:
            psk = pairing.derive_psk(pairing.code_to_bytes(code))
            self.on_event("handshaking")
            hs = await perform_handshake(reader, writer, psk, initiator=False)
            framer = SecureFramer(reader, writer, hs)
        except BaseException:
            # A bad code or a failed handshake means the connection is
            # already open with nothing left to do with it. Close it here
            # rather than leaving the caller to notice.
            writer.close()
            raise
        self.session = Session(framer, is_transport_initiator=False)
        self.session.start()
        self._remote_forwards = AgentRemoteForwards(self.session)
        self.on_event("paired")
        await self.session.send_control(M.Hello(**identity.describe_self()).to_bytes())

    async def run(self) -> None:
        """Blocks, servicing incoming connect requests and control commands
        until the session closes."""

        def on_connect(host, port, success):
            self.on_event("connect_out", host=host, port=port, success=success)

        await asyncio.gather(
            run_channel_acceptor(self.session, on_event=on_connect),
            self._control_loop(),
        )

    async def _control_loop(self) -> None:
        while True:
            raw = await self.session.recv_control()
            if raw is None:
                return
            d = M.unpack(raw)
            handled = await self._remote_forwards.handle_control_message(d)
            if not handled:
                logger.debug("unhandled control message: %r", d)
