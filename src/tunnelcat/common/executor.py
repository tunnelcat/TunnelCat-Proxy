"""Generic "accept a mux channel, connect out locally, relay bytes" loop.

Used by the agent for every SOCKS5/-L connection the operator initiates,
and by the operator for -R (reverse) forwards the agent initiates. The
direction of who does the real connect()/DNS resolution is just "whoever
accepts the channel," which is exactly the property -R pivoting needs.
"""

from __future__ import annotations

import asyncio
import logging

from ..mux import Session
from ..protocol import messages as M
from .netopt import set_nodelay

logger = logging.getLogger(__name__)


async def run_channel_acceptor(session: Session, on_event=None) -> None:
    while True:
        ch = await session.accept_channel()
        if ch is None:
            return
        asyncio.create_task(_handle(session, ch, on_event))


async def _handle(session: Session, ch, on_event) -> None:
    try:
        host, port = M.parse_connect_target(ch.open_metadata)
    except Exception:
        await session.reject_channel(ch, b"malformed open metadata")
        return
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=15)
        set_nodelay(writer)
    except Exception as exc:
        logger.info("connect-out to %s:%s failed: %s", host, port, exc)
        if on_event:
            on_event(host, port, False)
        await session.reject_channel(ch, str(exc)[:200].encode())
        return

    if on_event:
        on_event(host, port, True)
    await session.confirm_channel(ch)
    await ch.pump_duplex(reader, writer)
