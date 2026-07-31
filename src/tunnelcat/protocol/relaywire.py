"""Unencrypted relay-leg control protocol.

This is deliberately separate from the E2E control channel in messages.py.
Relays only ever see session_id (a value derived from the pairing code
that reveals nothing about the psk) and hop status, never anything from
the Noise handshake or the encrypted tunnel payload. Wrap the relay leg
in TLS at deployment time (a cert on the relay's domain) to keep this
metadata off the wire in cleartext. The protocol itself doesn't depend on
TLS for its core security property, which is that the relay cannot
decrypt tunnel traffic.
"""

from __future__ import annotations

import asyncio
import struct

import msgpack

_LEN = struct.Struct(">I")
MAX_MSG = 1 << 16

MSG_REGISTER = "register"     # claim a session_id on this relay (needs admin token)
MSG_JOIN = "join"             # attach to an already-registered session_id (code-derived proof only)
MSG_HOP = "hop"                # forward register/join onward to another relay
MSG_HOP_ACK = "hop_ack"        # status update relayed back toward the initiator, for CLI display
MSG_MATCHED = "matched"        # both ends spliced, data will now flow
MSG_ERROR = "error"


async def send_msg(writer: asyncio.StreamWriter, obj: dict) -> None:
    data = msgpack.packb(obj, use_bin_type=True)
    writer.write(_LEN.pack(len(data)) + data)
    await writer.drain()


async def recv_msg(reader: asyncio.StreamReader) -> dict:
    header = await reader.readexactly(4)
    (length,) = _LEN.unpack(header)
    if length > MAX_MSG:
        raise ValueError(f"relay message too large: {length}")
    data = await reader.readexactly(length)
    return msgpack.unpackb(data, raw=False)


def register(session_id_hex: str, token: str, role_label: str) -> dict:
    return {"type": MSG_REGISTER, "session_id": session_id_hex, "token": token, "label": role_label}


def join(session_id_hex: str, role_label: str) -> dict:
    return {"type": MSG_JOIN, "session_id": session_id_hex, "label": role_label}


def hop(session_id_hex: str, next_hop: str, token: str, inner: dict) -> dict:
    return {"type": MSG_HOP, "session_id": session_id_hex, "next": next_hop, "token": token, "inner": inner}


def hop_ack(hop_addr: str, status: str, detail: str = "") -> dict:
    return {"type": MSG_HOP_ACK, "hop": hop_addr, "status": status, "detail": detail}


def matched() -> dict:
    return {"type": MSG_MATCHED}


def error(reason: str) -> dict:
    return {"type": MSG_ERROR, "reason": reason}
