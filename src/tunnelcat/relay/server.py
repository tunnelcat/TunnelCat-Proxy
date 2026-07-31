"""Blind rendezvous + splice relay.

A relay never parses anything above the relaywire envelope: it matches
connections by session_id (a value that reveals nothing about the psk used
in the Noise handshake) and, once matched, becomes a dumb bidirectional
byte pump. It cannot decrypt tunnel traffic even if compromised.

Two ways a session resolves at a given relay:
  - Terminal: the relay itself holds the REGISTER and pairs it with a
    matching JOIN. Vice versa isn't needed since REGISTER always creates
    the pending slot and JOIN always attaches to an existing one.
  - Forwarding: the relay is told (via a HOP envelope, or its own
    ``default_next`` config) to dial another relay and forward the request
    onward, then transparently splice from that point on. Whatever the
    next hop sends back (hop_ack, matched, error, or eventually raw tunnel
    bytes) flows back through unmodified, which is what lets a chain's
    status messages bubble all the way back to the operator for display.

Every relay announces itself with a hop_ack as soon as it accepts a
connection, whether it ends up terminal or forwarding, so the initiating
side sees each hop light up in order.
"""

from __future__ import annotations

import asyncio
import hmac
import logging
import time

from ..common.netopt import prepare_connection
from ..protocol import relaywire as W

logger = logging.getLogger(__name__)


class PendingEntry:
    __slots__ = ("reader", "writer", "label", "created")

    def __init__(self, reader, writer, label):
        self.reader = reader
        self.writer = writer
        self.label = label
        self.created = time.monotonic()


class RelayServer:
    def __init__(
        self,
        bind_host: str,
        bind_port: int,
        admin_token: str,
        self_label: str | None = None,
        allow_next: set[str] | None = None,
        default_next: str | None = None,
        session_timeout: float = 300.0,
    ):
        self.bind_host = bind_host
        self.bind_port = bind_port
        self.admin_token = admin_token
        self._explicit_label = self_label
        self.self_label = self_label or f"{bind_host}:{bind_port}"
        self.allow_next = allow_next or set()
        self.default_next = default_next
        self.session_timeout = session_timeout
        self._pending: dict[str, PendingEntry] = {}
        self._server: asyncio.base_events.Server | None = None

    async def serve_forever(self) -> None:
        self._server = await asyncio.start_server(self._handle_conn, self.bind_host, self.bind_port)
        self.bind_port = self._server.sockets[0].getsockname()[1]
        if self._explicit_label is None:
            self.self_label = f"{self.bind_host}:{self.bind_port}"
        addrs = ", ".join(str(s.getsockname()) for s in self._server.sockets)
        logger.info("relay listening on %s", addrs)
        asyncio.create_task(self._sweep_expired())
        async with self._server:
            await self._server.serve_forever()

    async def _sweep_expired(self) -> None:
        # Scale the sweep cadence to the configured timeout so a short
        # session_timeout is actually enforced close to that window,
        # rather than lagging behind by up to a fixed 30s regardless.
        interval = min(30.0, max(1.0, self.session_timeout / 10))
        while True:
            await asyncio.sleep(interval)
            now = time.monotonic()
            expired = [sid for sid, e in self._pending.items() if now - e.created > self.session_timeout]
            for sid in expired:
                entry = self._pending.pop(sid, None)
                if entry:
                    logger.info("expiring unmatched session %s (%s)", sid[:12], entry.label)
                    entry.writer.close()

    def _valid_token(self, token: str) -> bool:
        return hmac.compare_digest(token or "", self.admin_token)

    async def _reject(self, writer: asyncio.StreamWriter, reason: str) -> None:
        await W.send_msg(writer, W.error(reason))
        writer.close()

    async def _handle_conn(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        prepare_connection(writer)
        peer = writer.get_extra_info("peername")
        try:
            msg = await W.recv_msg(reader)
        except (asyncio.IncompleteReadError, ConnectionError, ValueError, EOFError):
            writer.close()
            return

        # Announce ourselves immediately, which is what lets a chain's
        # hops appear one by one on the initiating side's display.
        try:
            await W.send_msg(writer, W.hop_ack(self.self_label, "connected", detail=f"peer {peer}"))
        except ConnectionError:
            writer.close()
            return

        msg_type = msg.get("type")

        # A relay with a static default_next transparently forwards
        # anything that wasn't already explicitly routed via HOP. This is
        # what hides a fixed chain topology behind one front-door address.
        if msg_type != W.MSG_HOP and self.default_next:
            await self._do_hop(reader, writer, next_hop=self.default_next, inner=msg)
            return

        if msg_type == W.MSG_REGISTER:
            await self._handle_register(reader, writer, msg)
        elif msg_type == W.MSG_JOIN:
            await self._handle_join(reader, writer, msg)
        elif msg_type == W.MSG_HOP:
            if not self._valid_token(msg.get("token", "")):
                await self._reject(writer, "invalid relay token")
                return
            next_hop = msg.get("next")
            inner = msg.get("inner")
            await self._do_hop(reader, writer, next_hop=next_hop, inner=inner)
        else:
            await self._reject(writer, f"unknown message type {msg_type!r}")

    async def _handle_register(self, reader, writer, msg: dict) -> None:
        session_id = msg.get("session_id", "")
        if not self._valid_token(msg.get("token", "")):
            await self._reject(writer, "invalid relay token")
            return
        if session_id in self._pending:
            await self._reject(writer, "session_id already registered")
            return
        self._pending[session_id] = PendingEntry(reader, writer, msg.get("label", "operator"))
        await W.send_msg(writer, W.hop_ack(self.self_label, "waiting_for_peer"))
        logger.info("session %s registered by %s", session_id[:12], msg.get("label"))

    async def _handle_join(self, reader, writer, msg: dict) -> None:
        session_id = msg.get("session_id", "")
        entry = self._pending.pop(session_id, None)
        if entry is None:
            await self._reject(writer, "no such session (not registered, or expired)")
            return
        logger.info("session %s joined by %s, splicing", session_id[:12], msg.get("label"))
        await W.send_msg(entry.writer, W.matched())
        await W.send_msg(writer, W.matched())
        await asyncio.gather(
            _pump(entry.reader, writer),
            _pump(reader, entry.writer),
        )

    async def _do_hop(self, reader, writer, next_hop: str | None, inner: dict | None) -> None:
        if not next_hop or next_hop not in self.allow_next:
            await self._reject(writer, f"forwarding to {next_hop!r} not permitted by this relay")
            return
        host, _, port_s = next_hop.rpartition(":")
        try:
            next_reader, next_writer = await asyncio.open_connection(host, int(port_s))
            prepare_connection(next_writer)
        except OSError as exc:
            await W.send_msg(writer, W.hop_ack(next_hop, "failed", detail=str(exc)))
            writer.close()
            return

        await W.send_msg(next_writer, inner)
        # From here on this relay is a transparent pipe: everything the
        # next hop (or the chain beyond it) sends back, including its own
        # hop_acks and the eventual encrypted tunnel bytes, flows through
        # unmodified in both directions.
        await asyncio.gather(
            _pump(reader, next_writer),
            _pump(next_reader, writer),
        )


async def _pump(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
    try:
        while True:
            data = await src.read(65536)
            if not data:
                break
            dst.write(data)
            await dst.drain()
    except ConnectionError:
        pass
    finally:
        dst.close()
