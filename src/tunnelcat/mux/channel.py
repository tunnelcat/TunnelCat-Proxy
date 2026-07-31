from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .session import Session

logger = logging.getLogger(__name__)

_INBOUND_MAXSIZE = 64  # real backpressure signal to whoever writes to this channel
_WIRE_INTAKE_MAXSIZE = 512  # slack absorbed before giving up on a stalled consumer (~32MB worst case)


class Channel:
    """One logical stream multiplexed over the encrypted session.

    Looks like a minimal asyncio stream: async read()/write()/close().

    The session has one shared read loop demultiplexing frames for every
    channel. When a channel's consumer is keeping up, a frame goes
    straight into its consumer-facing _inbound queue. Only when _inbound
    is momentarily full does a frame go through a per-channel drain task
    fed by _wire_intake instead. That indirection is what stops the
    shared read loop from ever blocking on one channel's backpressure,
    which would otherwise freeze every other channel sharing the session
    (e.g. one slow SOCKS connection stalling all of Burp's other
    concurrent requests). A channel whose consumer never catches up gets
    abandoned once _wire_intake's own much larger bound is hit, instead
    of blocking siblings forever or growing memory without limit.
    """

    def __init__(self, channel_id: int, session: Session, open_metadata: bytes = b""):
        self.channel_id = channel_id
        self.open_metadata = open_metadata
        self._session = session
        self._inbound: asyncio.Queue[bytes | None] = asyncio.Queue(maxsize=_INBOUND_MAXSIZE)
        self._wire_intake: asyncio.Queue[bytes | None] = asyncio.Queue(maxsize=_WIRE_INTAKE_MAXSIZE)
        # True while the drain task is idle (blocked waiting, nothing in
        # flight). Only then can _push skip _wire_intake safely, since
        # otherwise it could deliver a frame to _inbound ahead of one the
        # drain task already pulled off the queue but hasn't forwarded yet.
        self._drain_idle = True
        self._drain_task = asyncio.create_task(self._drain_wire_intake())
        self._read_eof = False  # peer's CLOSE (or session shutdown) has been received
        self._write_closed = False  # we've sent our own CLOSE (we're done sending)
        self._open_result: asyncio.Future = asyncio.get_event_loop().create_future()

    async def _drain_wire_intake(self) -> None:
        while True:
            item = await self._wire_intake.get()
            self._drain_idle = False
            await self._inbound.put(item)
            self._drain_idle = True
            if item is None:
                return

    def _push(self, data: bytes | None) -> bool:
        """Called by the shared session read loop, must never block.

        Returns False if this channel just got abandoned because its
        consumer is too far behind, so the caller can tear it down and let
        the peer know.
        """
        if self._drain_idle:
            # Fast path: nothing queued behind us, so this frame can go
            # straight to the consumer queue. Skips the extra queue hop
            # and task wakeup the slow path costs, which matters since
            # this runs once per frame for every channel.
            try:
                self._inbound.put_nowait(data)
                if data is None:
                    # EOF delivered without ever touching _wire_intake, so
                    # the drain task's own terminating sentinel will never
                    # arrive there. It's idle (nothing left to drain), so
                    # cancelling it now is safe and prevents it from
                    # leaking as a permanently-pending task.
                    self._drain_task.cancel()
                return True
            except asyncio.QueueFull:
                pass  # inbound is momentarily full, fall through to the slow path
        try:
            self._wire_intake.put_nowait(data)
            return True
        except asyncio.QueueFull:
            logger.warning("channel %d: consumer stalled too far behind, abandoning channel", self.channel_id)
            try:
                self._wire_intake.put_nowait(None)  # best-effort EOF for whatever's reading
            except asyncio.QueueFull:
                pass
            return False

    async def read(self) -> bytes | None:
        """Returns None once the peer has closed its send side (or the
        session shuts down), independent of whether we've closed ours."""
        if self._read_eof:
            return None
        data = await self._inbound.get()
        if data is None:
            self._read_eof = True
        return data

    async def write(self, data: bytes) -> None:
        if not data or self._write_closed:
            return
        await self._session._send_data(self.channel_id, data)

    async def close(self) -> None:
        """Signal that we're done sending.

        This is a half-close: it must not stop us from still receiving
        whatever the peer has in flight the other way. The drain task
        keeps running until a matching EOF actually arrives (the peer's
        CLOSE, an abandon, or session shutdown), all of which push None
        through _wire_intake and let it terminate on its own.
        """
        if not self._write_closed:
            self._write_closed = True
            await self._session._send_close(self.channel_id)

    async def pump_to(self, writer: asyncio.StreamWriter) -> None:
        """Relay everything from this channel into a raw asyncio writer
        until EOF, then half-close (not hard-close) the writer.

        A hard writer.close() here would be wrong whenever pump_from is
        still concurrently reading on the same duplex socket, which is
        the normal case for both directions of one real connection.
        Closing a socket while its receive buffer may still have unread
        data queued can make the OS send a TCP RST instead of a clean
        FIN, discarding that data and aborting the connection out from
        under the still-running read direction. write_eof() sends a FIN
        for our send side only, without touching the read side.
        """
        try:
            while True:
                data = await self.read()
                if data is None:
                    break
                writer.write(data)
                await writer.drain()
        finally:
            if writer.can_write_eof():
                try:
                    writer.write_eof()
                except OSError:
                    pass
            else:
                writer.close()

    async def pump_from(self, reader: asyncio.StreamReader) -> None:
        """Relay everything from a raw asyncio reader into this channel until EOF."""
        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    break
                await self.write(data)
        finally:
            await self.close()

    async def pump_duplex(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Relay both directions between this channel and a raw duplex
        socket, then close the socket. Used everywhere a channel gets
        bridged to a real connection: SOCKS targets, local/remote forwards.
        """
        try:
            await asyncio.gather(self.pump_to(writer), self.pump_from(reader))
        finally:
            writer.close()
