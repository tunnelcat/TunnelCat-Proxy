"""Encrypted, length-prefixed frame transport built on a handshake's CipherStates.

Wire format per frame: 4-byte big-endian length || AEAD ciphertext.
The plaintext inside is an opaque blob handed to us by the mux layer.
"""

from __future__ import annotations

import asyncio
import struct

from .noise import CipherState, HandshakeResult

MAX_FRAME = 1 << 20  # 1 MiB cap against a malicious/corrupt length prefix
_LEN_STRUCT = struct.Struct(">I")


class FramingError(Exception):
    pass


class SecureFramer:
    """Send/receive AEAD-encrypted, length-prefixed frames over an asyncio stream."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, hs: HandshakeResult):
        self._reader = reader
        self._writer = writer
        self._send_cs: CipherState = hs.send
        self._recv_cs: CipherState = hs.recv
        self._send_lock = asyncio.Lock()

    async def send(self, plaintext: bytes) -> None:
        # Nonce assignment (inside encrypt()) and the wire write must be
        # one atomic unit. If a frame were encrypted with nonce N but lost
        # the race to reach the socket, it would land out of nonce order
        # and desync the receiver's monotonic counter, breaking every
        # frame after it. Concurrent callers are the normal case here
        # (many SOCKS channels writing through one session).
        async with self._send_lock:
            ct = self._send_cs.encrypt(plaintext)
            # Two writes instead of concatenating header+ct into a new
            # bytes object: write() just appends to the transport buffer
            # either way, so this skips an allocation on every frame.
            self._writer.write(_LEN_STRUCT.pack(len(ct)))
            self._writer.write(ct)
            await self._writer.drain()

    async def recv(self) -> bytes:
        header = await self._reader.readexactly(4)
        (length,) = _LEN_STRUCT.unpack(header)
        if length > MAX_FRAME or length < 16:
            raise FramingError(f"implausible frame length {length}")
        ct = await self._reader.readexactly(length)
        return self._recv_cs.decrypt(ct)

    def close(self) -> None:
        self._writer.close()

    async def wait_closed(self) -> None:
        try:
            await self._writer.wait_closed()
        except ConnectionError:
            pass
