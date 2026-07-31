"""Minimal SOCKS5 server (RFC 1928): no-auth, CONNECT only.

Domain-name targets (ATYP 0x03) are passed through as hostnames rather
than resolved locally. That's what makes "DNS over SOCKS" in Burp or a
browser result in the agent doing the resolution on the remote network,
which is usually what you want when pivoting.
"""

from __future__ import annotations

import asyncio
import logging
import socket
import struct

from ..common.netopt import set_nodelay

logger = logging.getLogger(__name__)

_VERSION = 0x05
_CMD_CONNECT = 0x01
_ATYP_IPV4 = 0x01
_ATYP_DOMAIN = 0x03
_ATYP_IPV6 = 0x04

REP_OK = 0x00
REP_GENERAL_FAILURE = 0x01
REP_CMD_NOT_SUPPORTED = 0x07
REP_ATYP_NOT_SUPPORTED = 0x08


class Socks5Server:
    def __init__(self, bind_host: str, bind_port: int, open_channel, on_connection=None):
        self.bind_host = bind_host
        self.bind_port = bind_port
        self._open_channel = open_channel  # async fn(host: str, port: int) -> Channel
        self._on_connection = on_connection  # fn(host, port, success: bool)
        self._server: asyncio.base_events.Server | None = None

    async def start(self):
        self._server = await asyncio.start_server(self._handle_client, self.bind_host, self.bind_port)
        return self._server.sockets[0].getsockname()

    def close(self):
        if self._server:
            self._server.close()

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            await self._negotiate_and_relay(reader, writer)
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        except Exception:
            logger.exception("socks5 client session error")
        finally:
            writer.close()

    async def _negotiate_and_relay(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        set_nodelay(writer)
        ver_nmethods = await reader.readexactly(2)
        ver, nmethods = ver_nmethods
        await reader.readexactly(nmethods)  # offered auth methods, we ignore and require none
        if ver != _VERSION:
            return
        writer.write(bytes([_VERSION, 0x00]))
        await writer.drain()

        header = await reader.readexactly(4)
        _ver, cmd, _rsv, atyp = header
        if cmd != _CMD_CONNECT:
            await self._reply(writer, REP_CMD_NOT_SUPPORTED)
            return

        if atyp == _ATYP_IPV4:
            host = socket.inet_ntoa(await reader.readexactly(4))
        elif atyp == _ATYP_DOMAIN:
            length = (await reader.readexactly(1))[0]
            host = (await reader.readexactly(length)).decode("utf-8", errors="replace")
        elif atyp == _ATYP_IPV6:
            host = socket.inet_ntop(socket.AF_INET6, await reader.readexactly(16))
        else:
            await self._reply(writer, REP_ATYP_NOT_SUPPORTED)
            return

        (port,) = struct.unpack(">H", await reader.readexactly(2))

        try:
            channel = await self._open_channel(host, port)
        except Exception as exc:
            logger.info("SOCKS connect %s:%s failed: %s", host, port, exc)
            if self._on_connection:
                self._on_connection(host, port, False)
            await self._reply(writer, REP_GENERAL_FAILURE)
            return

        if self._on_connection:
            self._on_connection(host, port, True)
        await self._reply(writer, REP_OK)

        await asyncio.gather(
            channel.pump_to(writer),
            channel.pump_from(reader),
        )

    async def _reply(self, writer: asyncio.StreamWriter, rep: int) -> None:
        writer.write(bytes([_VERSION, rep, 0x00, _ATYP_IPV4]) + b"\x00\x00\x00\x00" + b"\x00\x00")
        await writer.drain()
