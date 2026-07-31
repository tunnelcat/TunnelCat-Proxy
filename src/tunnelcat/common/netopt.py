"""Socket tuning applied at every connection point.

Nagle's algorithm (TCP_NODELAY off, the OS default) delays small writes by
up to ~40ms waiting to coalesce with more data or an ACK. That's mostly
invisible on a single hop, but a relay chain means N independent sockets
each doing this on their own. For interactive traffic (small
request/response chunks, e.g. clicking through a web app via Burp) the
delay can compound roughly linearly with hop count. Disabling it costs
nothing here since chunking is already controlled explicitly at the
application layer (SOCKS/mux framing), so there's no bulk-transfer
efficiency being traded away.
"""

from __future__ import annotations

import asyncio
import socket


def set_nodelay(writer: asyncio.StreamWriter) -> None:
    sock = writer.get_extra_info("socket")
    if sock is not None and sock.family in (socket.AF_INET, socket.AF_INET6):
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass


def tune_write_buffer(writer: asyncio.StreamWriter, high_water: int = 256 * 1024) -> None:
    """Raise the write-buffer high-water mark on connections that carry
    bulk proxied traffic (relay pump legs, the operator<->agent transport).

    The default (64KiB) is fine for a single hop, but on a chain each
    hop's drain() independently suspends and resumes at that threshold.
    With several hops relaying the same bytes, that's several extra
    scheduling round trips per buffer's worth of data. A larger buffer
    means fewer, larger drain() cycles per hop, so the saving compounds
    with chain length instead of the overhead compounding.
    """
    try:
        writer.transport.set_write_buffer_limits(high=high_water)
    except (NotImplementedError, AttributeError, OSError):
        pass


def prepare_connection(writer: asyncio.StreamWriter) -> None:
    """Apply both tunings at once for connections that carry bulk proxied
    traffic: relay legs and the main operator<->agent transport."""
    set_nodelay(writer)
    tune_write_buffer(writer)
