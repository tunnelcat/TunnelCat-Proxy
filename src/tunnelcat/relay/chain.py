"""Client-side helper for connecting through a relay or a chain of relays.

Only the connecting side needs to know the chain. The peer it's trying to
reach only ever talks to whichever relay is reachable to it (usually the
last one). Building the nested HOP envelope once and sending it means every
intermediate relay's own hop_ack, and eventually the terminal MATCHED,
bubbles back through the same connection unmodified. That's what lets us
render live per-hop status without any extra round trips.
"""

from __future__ import annotations

from dataclasses import dataclass
import asyncio

from ..common.netopt import prepare_connection
from ..protocol import relaywire as W


class RelayError(Exception):
    pass


@dataclass
class HopTarget:
    host: str
    port: int
    token: str

    @property
    def addr(self) -> str:
        return f"{self.host}:{self.port}"


@dataclass
class RelayEvent:
    hop: str
    status: str  # connected | waiting_for_peer | matched | failed | error
    detail: str = ""


def parse_chain_spec(spec: str) -> list[HopTarget]:
    """Parse 'host:port:token,host:port:token,...' into HopTargets.

    Raises ValueError naming the specific bad entry, since this is almost
    always typed by hand on a command line.
    """
    hops = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        pieces = part.rsplit(":", 2)
        if len(pieces) != 3:
            raise ValueError(f"invalid relay entry {part!r}, expected host:port:token")
        host, port_s, token = pieces
        if not port_s.isdigit():
            raise ValueError(f"invalid port {port_s!r} in relay entry {part!r}")
        if not host or not token:
            raise ValueError(f"invalid relay entry {part!r}, host and token can't be empty")
        hops.append(HopTarget(host=host, port=int(port_s), token=token))
    if not hops:
        raise ValueError("empty relay chain spec")
    return hops


def _build_envelope(chain: list[HopTarget], idx: int, final_msg: dict, session_id_hex: str) -> dict:
    if idx == len(chain) - 1:
        return final_msg
    next_addr = chain[idx + 1].addr
    inner = _build_envelope(chain, idx + 1, final_msg, session_id_hex)
    return W.hop(session_id_hex, next_addr, chain[idx].token, inner)


async def connect_through_chain(
    chain: list[HopTarget],
    final_msg: dict,
    session_id_hex: str,
    on_event=None,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    if not chain:
        raise ValueError("empty chain")
    first = chain[0]
    reader, writer = await asyncio.open_connection(first.host, first.port)
    prepare_connection(writer)
    try:
        envelope = _build_envelope(chain, 0, final_msg, session_id_hex)
        await W.send_msg(writer, envelope)

        while True:
            try:
                msg = await W.recv_msg(reader)
            except (asyncio.IncompleteReadError, ConnectionError, EOFError) as exc:
                raise RelayError(f"relay connection closed unexpectedly: {exc}") from exc

            t = msg.get("type")
            if t == W.MSG_HOP_ACK:
                if on_event:
                    on_event(RelayEvent(hop=msg.get("hop", "?"), status=msg.get("status", "?"), detail=msg.get("detail", "")))
            elif t == W.MSG_MATCHED:
                if on_event:
                    on_event(RelayEvent(hop="peer", status="matched"))
                return reader, writer
            elif t == W.MSG_ERROR:
                reason = msg.get("reason", "relay error")
                if on_event:
                    on_event(RelayEvent(hop="?", status="failed", detail=reason))
                raise RelayError(reason)
            else:
                raise RelayError(f"unexpected relay message type {t!r}")
    except BaseException:
        # Covers RelayError above and cancellation. asyncio.CancelledError
        # is a BaseException, not an Exception, so a plain except Exception
        # here would miss it: a caller that gives up waiting, e.g. by
        # cancelling a pending register(), must still get this socket
        # closed rather than leaking it.
        writer.close()
        raise
