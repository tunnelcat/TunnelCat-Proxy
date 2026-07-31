from __future__ import annotations

import asyncio
import logging

from ..common import transport
from ..common.executor import run_channel_acceptor
from ..crypto import pairing
from ..crypto.framing import SecureFramer
from ..crypto.noise import perform_handshake
from ..mux import Session
from ..protocol import messages as M
from ..protocol import relaywire as W
from ..relay.chain import HopTarget, connect_through_chain
from .portforward import LocalForward, RemoteForwardManager
from .socks5 import Socks5Server

logger = logging.getLogger(__name__)


class OperatorApp:
    def __init__(self, on_event=None):
        self.on_event = on_event or (lambda *a, **k: None)
        self.session: Session | None = None
        self.agent_identity: dict | None = None
        self.remote_forwards: RemoteForwardManager | None = None
        self._socks_server: Socks5Server | None = None
        self._local_forwards: list[LocalForward] = []  # keep-alive refs, never read back
        self._control_task: asyncio.Task | None = None
        self._acceptor_task: asyncio.Task | None = None

    # -- pairing ----------------------------------------------------------

    async def pair_direct_listen(self, bind_host: str, bind_port: int, code: str | None = None) -> str:
        code = code or pairing.generate_pairing_code()
        self.on_event("pairing_code", code=code)

        def on_waiting(bound):
            self.on_event("listening", host=bound[0], port=bound[1])

        reader, writer = await transport.listen_once(bind_host, bind_port, on_waiting=on_waiting)
        await self._complete(reader, writer, code)
        return code

    async def pair_direct_connect(self, host: str, port: int, code: str) -> None:
        reader, writer = await transport.connect_direct(host, port)
        await self._complete(reader, writer, code)

    async def pair_via_relay(self, chain: list[HopTarget], code: str | None = None) -> str:
        code = code or pairing.generate_pairing_code()
        self.on_event("pairing_code", code=code)
        sid = pairing.derive_session_id(pairing.code_to_bytes(code)).hex()
        token = chain[-1].token

        def on_relay_event(ev):
            self.on_event("relay_hop", hop=ev.hop, status=ev.status, detail=ev.detail)

        reader, writer = await connect_through_chain(chain, W.register(sid, token, "operator"), sid, on_event=on_relay_event)
        await self._complete(reader, writer, code)
        return code

    async def _complete(self, reader, writer, code: str) -> None:
        try:
            psk = pairing.derive_psk(pairing.code_to_bytes(code))
            self.on_event("handshaking")
            hs = await perform_handshake(reader, writer, psk, initiator=True)
            framer = SecureFramer(reader, writer, hs)
        except BaseException:
            # A bad code or a failed handshake means the connection is
            # already open with nothing left to do with it. Close it here
            # rather than leaving the caller to notice.
            writer.close()
            raise
        self.session = Session(framer, is_transport_initiator=True)
        self.session.start()
        self.remote_forwards = RemoteForwardManager(self.session)
        self.on_event("paired")

        # -R connections from the agent land as ordinary channels too, so
        # keep the generic acceptor running in the background even if the
        # operator never calls start_remote_forward.
        self._acceptor_task = asyncio.create_task(
            run_channel_acceptor(self.session, on_event=lambda h, p, ok: self.on_event("remote_forward_connect", host=h, port=p, success=ok))
        )
        self._control_task = asyncio.create_task(self._control_loop())

    async def _control_loop(self) -> None:
        while True:
            raw = await self.session.recv_control()
            if raw is None:
                return
            d = M.unpack(raw)
            if d.get("type") == M.MSG_HELLO:
                self.agent_identity = d
                self.on_event("agent_hello", **d)
                continue
            if self.remote_forwards and self.remote_forwards.handle_control_message(d):
                continue
            logger.debug("unhandled control message: %r", d)

    # -- services -----------------------------------------------------------

    async def start_socks5(self, bind_host: str = "127.0.0.1", bind_port: int = 1080):
        async def open_channel(host, port):
            return await self.session.open_channel(metadata=M.connect_target(host, port))

        def on_conn(host, port, success):
            self.on_event("socks_connect", host=host, port=port, success=success)

        self._socks_server = Socks5Server(bind_host, bind_port, open_channel, on_connection=on_conn)
        addr = await self._socks_server.start()
        self.on_event("socks_started", host=addr[0], port=addr[1])
        return addr

    async def add_local_forward(self, listen_host: str, listen_port: int, target_host: str, target_port: int):
        fwd = LocalForward(self.session, listen_host, listen_port, target_host, target_port)
        addr = await fwd.start()
        self._local_forwards.append(fwd)
        self.on_event("local_forward_started", host=addr[0], port=addr[1], target_host=target_host, target_port=target_port)
        return addr

    async def add_remote_forward(self, listen_host: str, listen_port: int, target_host: str, target_port: int) -> int:
        bound_port = await self.remote_forwards.start(listen_host, listen_port, target_host, target_port)
        self.on_event("remote_forward_started", host=listen_host, port=bound_port, target_host=target_host, target_port=target_port)
        return bound_port
