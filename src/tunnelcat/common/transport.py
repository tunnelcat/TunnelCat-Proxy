"""Establishing the raw byte stream that the Noise handshake then runs over,
regardless of whether that stream came from direct listen/connect or from
threading through a relay chain. Everything above this layer (handshake,
mux, control protocol) doesn't care which one was used.
"""

from __future__ import annotations

import asyncio

from .netopt import prepare_connection


async def listen_once(bind_host: str, bind_port: int, on_waiting=None) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Listen for exactly one inbound connection, then stop listening."""
    fut: asyncio.Future = asyncio.get_event_loop().create_future()

    async def on_conn(reader, writer):
        if not fut.done():
            fut.set_result((reader, writer))

    server = await asyncio.start_server(on_conn, bind_host, bind_port)
    bound = server.sockets[0].getsockname()
    if on_waiting:
        on_waiting(bound)
    try:
        reader, writer = await fut
        prepare_connection(writer)
        return reader, writer
    finally:
        server.close()


async def connect_direct(host: str, port: int) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    reader, writer = await asyncio.open_connection(host, port)
    prepare_connection(writer)
    return reader, writer
