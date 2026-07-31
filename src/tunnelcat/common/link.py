"""tnl:// connection links: one string that bundles everything an agent
needs to pair (transport details plus pairing code) instead of separate
flags.

Not a new secret. It's the same material you'd otherwise pass via
--connect/--relay-chain/--code, just packaged as one thing to copy between
your two machines out of band.
"""

from __future__ import annotations

import base64

import msgpack

PREFIX = "tnl://"


def encode_direct(host: str, port: int, code: str) -> str:
    payload = {"mode": "direct", "host": host, "port": port, "code": code}
    return PREFIX + _b64(payload)


def encode_relay(chain_spec: str, code: str) -> str:
    payload = {"mode": "relay", "chain": chain_spec, "code": code}
    return PREFIX + _b64(payload)


def decode(link: str) -> dict:
    link = link.strip()
    if not link.startswith(PREFIX):
        raise ValueError(f"not a {PREFIX} link, check it was pasted in full")
    try:
        raw = base64.urlsafe_b64decode(_pad(link[len(PREFIX) :]))
        payload = msgpack.unpackb(raw, raw=False)
    except Exception as exc:
        raise ValueError(f"malformed {PREFIX} link, check it was pasted in full: {exc}") from exc
    if not isinstance(payload, dict) or "mode" not in payload or "code" not in payload:
        raise ValueError(f"malformed {PREFIX} link: missing required fields")
    return payload


def _b64(payload: dict) -> str:
    raw = msgpack.packb(payload, use_bin_type=True)
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _pad(s: str) -> str:
    return s + "=" * (-len(s) % 4)
