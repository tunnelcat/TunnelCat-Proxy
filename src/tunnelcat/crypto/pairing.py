"""Pairing code generation and derivation of independent secrets from it.

A single random pairing code is the only thing a user copies between two
machines. Everything the protocol needs is derived from it via HKDF with
distinct context labels, so each derived value is cryptographically
independent even though they share one root secret:

- ``psk``: mixed into the Noise handshake, never leaves the two paired
  endpoints, relays never see it.
- ``session_id``: the only thing a relay learns, used purely for
  rendezvous matching, carries no information about the psk.

Because these are HKDF outputs with different ``info`` strings, learning
session_id gives no advantage in computing psk (HKDF-Expand is one-way per
label), which is exactly the property that lets an untrusted relay broker
a session without being able to decrypt anything that flows through it.
"""

from __future__ import annotations

import base64
import binascii
import secrets

from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives import hashes

CODE_BYTES = 20  # 160 bits of entropy


def generate_pairing_code() -> str:
    """Generate a new random pairing code, base32-encoded, grouped for readability."""
    raw = secrets.token_bytes(CODE_BYTES)
    b32 = base64.b32encode(raw).decode("ascii").rstrip("=")
    groups = [b32[i : i + 4] for i in range(0, len(b32), 4)]
    return "-".join(groups)


def code_to_bytes(code: str) -> bytes:
    b32 = code.replace("-", "").upper()
    padding = "=" * (-len(b32) % 8)
    try:
        return base64.b32decode(b32 + padding)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"invalid pairing code {code!r}, check it was copied in full") from exc


def _hkdf(ikm: bytes, info: bytes, length: int = 32) -> bytes:
    return HKDFExpand(algorithm=hashes.SHA256(), length=length, info=info).derive(ikm)


def derive_psk(code_bytes: bytes) -> bytes:
    return _hkdf(code_bytes, b"tunnel-psk-v1")


def derive_session_id(code_bytes: bytes) -> bytes:
    """The only value a relay ever learns. Knowing it already proves
    possession of the pairing code, since it's a one-way HKDF output over
    160 bits of entropy, so no separate proof of possession is needed at
    the relay layer. The relay couldn't verify anything cryptographic
    anyway without also learning the psk, which would break E2E
    confidentiality.
    """
    return _hkdf(code_bytes, b"tunnel-session-id-v1")
