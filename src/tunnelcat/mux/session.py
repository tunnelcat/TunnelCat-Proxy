"""Channel multiplexer: many logical streams over one encrypted SecureFramer.

Frame plaintext layout (as handed to/from SecureFramer):
    [1 byte type][4 byte channel_id big-endian][payload...]

Channel 0 is reserved for control-plane messages (msgpack RPC). Either side
may open data channels (e.g. the operator opens one per SOCKS client
connection; the agent opens one per incoming reverse-forward connection),
so channel ids are split by parity to avoid collisions: the initiator of
the transport connection allocates even ids, the responder allocates odd
ids, both starting above 0.
"""

from __future__ import annotations

import asyncio
import logging
import struct

from ..crypto.framing import SecureFramer
from .channel import Channel

logger = logging.getLogger(__name__)

_TYPE_OPEN = 1
_TYPE_OPEN_OK = 2
_TYPE_OPEN_FAIL = 3
_TYPE_DATA = 4
_TYPE_CLOSE = 5

_HEADER = struct.Struct(">BI")


class ChannelOpenFailed(Exception):
    pass


class SessionClosed(Exception):
    pass


class Session:
    def __init__(self, framer: SecureFramer, is_transport_initiator: bool):
        self._framer = framer
        self._channels: dict[int, Channel] = {}
        self._pending_open: dict[int, asyncio.Future] = {}
        self._incoming: asyncio.Queue[Channel | None] = asyncio.Queue()
        self._control_inbound: asyncio.Queue[bytes | None] = asyncio.Queue()
        self._next_id = 2 if is_transport_initiator else 1
        self._id_step = 2
        self._closed = False
        self._reader_task: asyncio.Task | None = None
        self.on_channel_closed = None  # optional callback(channel_id)

    def start(self) -> None:
        self._reader_task = asyncio.create_task(self._read_loop())

    def _alloc_id(self) -> int:
        cid = self._next_id
        self._next_id += self._id_step
        return cid

    async def _write_frame(self, type_: int, channel_id: int, payload: bytes) -> None:
        await self._framer.send(_HEADER.pack(type_, channel_id) + payload)

    async def _read_loop(self) -> None:
        try:
            while True:
                frame = await self._framer.recv()
                type_, channel_id = _HEADER.unpack_from(frame, 0)
                payload = frame[_HEADER.size :]
                await self._dispatch(type_, channel_id, payload)
        except (asyncio.IncompleteReadError, ConnectionError, EOFError):
            pass
        except Exception:
            logger.exception("mux read loop error")
        finally:
            await self._shutdown()

    async def _dispatch(self, type_: int, channel_id: int, payload: bytes) -> None:
        if channel_id == 0:
            if type_ == _TYPE_DATA:
                await self._control_inbound.put(payload)
            return

        if type_ == _TYPE_OPEN:
            ch = Channel(channel_id, self, open_metadata=payload)
            self._channels[channel_id] = ch
            await self._incoming.put(ch)
        elif type_ == _TYPE_OPEN_OK:
            fut = self._pending_open.pop(channel_id, None)
            if fut and not fut.done():
                fut.set_result(self._channels[channel_id])
        elif type_ == _TYPE_OPEN_FAIL:
            fut = self._pending_open.pop(channel_id, None)
            self._channels.pop(channel_id, None)
            if fut and not fut.done():
                fut.set_exception(ChannelOpenFailed(payload.decode(errors="replace")))
        elif type_ == _TYPE_DATA:
            ch = self._channels.get(channel_id)
            if ch and not ch._push(payload):
                # Consumer stalled too far behind, drop the channel rather
                # than let one bad channel block the shared read loop (and
                # therefore every other channel) forever.
                self._channels.pop(channel_id, None)
                await self._write_frame(_TYPE_CLOSE, channel_id, b"stalled consumer")
        elif type_ == _TYPE_CLOSE:
            ch = self._channels.pop(channel_id, None)
            if ch:
                ch._push(None)
            if self.on_channel_closed:
                self.on_channel_closed(channel_id)

    async def _shutdown(self) -> None:
        if self._closed:
            return
        self._closed = True
        for ch in self._channels.values():
            ch._push(None)
        for fut in self._pending_open.values():
            if not fut.done():
                fut.set_exception(SessionClosed())
        await self._incoming.put(None)
        await self._control_inbound.put(None)

    # -- public API -----------------------------------------------------

    async def open_channel(self, metadata: bytes = b"", timeout: float = 30.0) -> Channel:
        if self._closed:
            raise SessionClosed()
        cid = self._alloc_id()
        ch = Channel(cid, self)
        self._channels[cid] = ch
        fut: asyncio.Future = asyncio.get_event_loop().create_future()
        self._pending_open[cid] = fut
        await self._write_frame(_TYPE_OPEN, cid, metadata)
        try:
            return await asyncio.wait_for(fut, timeout=timeout)
        except asyncio.TimeoutError:
            self._channels.pop(cid, None)
            self._pending_open.pop(cid, None)
            raise ChannelOpenFailed("timed out waiting for peer to accept channel")

    async def accept_channel(self) -> Channel | None:
        return await self._incoming.get()

    async def confirm_channel(self, channel: Channel) -> None:
        await self._write_frame(_TYPE_OPEN_OK, channel.channel_id, b"")

    async def reject_channel(self, channel: Channel, reason: bytes = b"") -> None:
        self._channels.pop(channel.channel_id, None)
        await self._write_frame(_TYPE_OPEN_FAIL, channel.channel_id, reason)

    async def send_control(self, payload: bytes) -> None:
        if self._closed:
            raise SessionClosed()
        await self._write_frame(_TYPE_DATA, 0, payload)

    async def recv_control(self) -> bytes | None:
        return await self._control_inbound.get()

    async def _send_data(self, channel_id: int, data: bytes) -> None:
        if self._closed:
            return
        await self._write_frame(_TYPE_DATA, channel_id, data)

    async def _send_close(self, channel_id: int) -> None:
        # This only announces that we are done sending. It must not
        # remove the channel from self._channels, since the peer may
        # still be sending us data the other way (e.g. an upload that
        # finishes before the matching download does). The channel is
        # only fully forgotten once a CLOSE is received from the peer
        # (see _dispatch), which is the point we know nothing more is
        # coming.
        if self._closed:
            return
        await self._write_frame(_TYPE_CLOSE, channel_id, b"")

    async def close(self) -> None:
        if self._reader_task:
            self._reader_task.cancel()
        self._framer.close()
        await self._shutdown()
