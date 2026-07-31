"""Minimal implementation of the Noise_NNpsk0_25519_ChaChaPoly_SHA256 handshake.

This follows the Noise Protocol Framework (Perrin, 2018) pattern NNpsk0:

    -> psk, e
    <- e, ee

Properties this gives us:
  - Forward secrecy from the ephemeral-ephemeral X25519 DH ("ee").
  - Mutual implicit authentication from the PSK: both sides only arrive at
    matching transport keys if they mixed in the same psk. An active
    attacker without the pairing code cannot complete a session; frames
    will fail to decrypt rather than being silently accepted.
  - Transcript binding via the running hash `h`, so tampering with any
    handshake message is detected.

This is a from-scratch implementation of a documented, publicly analyzed
pattern, not a novel construction, but it has not been independently
audited. For higher assurance, swap this module for a vetted Noise library.
The rest of the codebase only depends on the HandshakeResult interface below.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes as _hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.exceptions import InvalidTag

PROTOCOL_NAME = b"Noise_NNpsk0_25519_ChaChaPoly_SHA256"
DHLEN = 32
TAGLEN = 16


class HandshakeFailed(Exception):
    """Raised when a peer's handshake message fails to authenticate.

    This is the expected outcome of an active MITM attempt or a mistyped
    pairing code. It fails closed rather than silently proceeding with
    mismatched keys.
    """


def _hmac_hash(key: bytes, data: bytes) -> bytes:
    h = HMAC(key, _hashes.SHA256())
    h.update(data)
    return h.finalize()


def _hkdf(chaining_key: bytes, ikm: bytes, num_outputs: int):
    temp_key = _hmac_hash(chaining_key, ikm)
    output1 = _hmac_hash(temp_key, b"\x01")
    if num_outputs == 1:
        return (output1,)
    output2 = _hmac_hash(temp_key, output1 + b"\x02")
    if num_outputs == 2:
        return (output1, output2)
    output3 = _hmac_hash(temp_key, output2 + b"\x03")
    return (output1, output2, output3)


class CipherState:
    """AEAD encrypt/decrypt with a monotonic nonce counter (never reused)."""

    __slots__ = ("_key", "_n")

    def __init__(self, key: bytes):
        self._key = key
        self._n = 0

    def _nonce(self) -> bytes:
        return b"\x00\x00\x00\x00" + self._n.to_bytes(8, "little")

    def encrypt(self, plaintext: bytes, ad: bytes = b"") -> bytes:
        aead = ChaCha20Poly1305(self._key)
        ct = aead.encrypt(self._nonce(), plaintext, ad)
        self._n += 1
        return ct

    def decrypt(self, ciphertext: bytes, ad: bytes = b"") -> bytes:
        aead = ChaCha20Poly1305(self._key)
        try:
            pt = aead.decrypt(self._nonce(), ciphertext, ad)
        except InvalidTag as exc:
            raise HandshakeFailed("AEAD authentication failed") from exc
        self._n += 1
        return pt


class _SymmetricState:
    def __init__(self):
        if len(PROTOCOL_NAME) <= 32:
            h = PROTOCOL_NAME + b"\x00" * (32 - len(PROTOCOL_NAME))
        else:
            h = _hashes.Hash(_hashes.SHA256())
            h.update(PROTOCOL_NAME)
            h = h.finalize()
        self.h = h
        self.ck = h
        self._cs: CipherState | None = None
        self.mix_hash(b"")  # empty prologue

    def mix_hash(self, data: bytes) -> None:
        d = _hashes.Hash(_hashes.SHA256())
        d.update(self.h + data)
        self.h = d.finalize()

    def mix_key(self, ikm: bytes) -> None:
        ck, temp_k = _hkdf(self.ck, ikm, 2)
        self.ck = ck
        self._cs = CipherState(temp_k)

    def mix_key_and_hash(self, ikm: bytes) -> None:
        ck, temp_h, temp_k = _hkdf(self.ck, ikm, 3)
        self.ck = ck
        self.mix_hash(temp_h)
        self._cs = CipherState(temp_k)

    def encrypt_and_hash(self, plaintext: bytes) -> bytes:
        if self._cs is None:
            ct = plaintext
        else:
            ct = self._cs.encrypt(plaintext, ad=self.h)
        self.mix_hash(ct)
        return ct

    def decrypt_and_hash(self, ciphertext: bytes) -> bytes:
        if self._cs is None:
            pt = ciphertext
        else:
            pt = self._cs.decrypt(ciphertext, ad=self.h)
        self.mix_hash(ciphertext)
        return pt

    def split(self) -> tuple[CipherState, CipherState]:
        k1, k2 = _hkdf(self.ck, b"", 2)
        return CipherState(k1), CipherState(k2)


@dataclass
class HandshakeResult:
    send: CipherState
    recv: CipherState


async def _write_frame(writer: asyncio.StreamWriter, data: bytes) -> None:
    writer.write(data)
    await writer.drain()


async def perform_handshake(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    psk: bytes,
    initiator: bool,
) -> HandshakeResult:
    """Run the NNpsk0 handshake over an already-connected stream.

    Both directions use fixed-size messages (32-byte ephemeral pubkey +
    16-byte AEAD tag), so no extra length framing is needed here.
    """
    ss = _SymmetricState()

    if initiator:
        # -> psk, e
        ss.mix_key_and_hash(psk)
        e_priv = X25519PrivateKey.generate()
        e_pub = e_priv.public_key().public_bytes_raw()
        ss.mix_hash(e_pub)
        payload = ss.encrypt_and_hash(b"")
        await _write_frame(writer, e_pub + payload)

        # <- e, ee
        msg2 = await reader.readexactly(DHLEN + TAGLEN)
        their_e_pub = msg2[:DHLEN]
        payload2 = msg2[DHLEN:]
        ss.mix_hash(their_e_pub)
        dh = e_priv.exchange(X25519PublicKey.from_public_bytes(their_e_pub))
        ss.mix_key(dh)
        ss.decrypt_and_hash(payload2)

        c1, c2 = ss.split()
        return HandshakeResult(send=c1, recv=c2)
    else:
        # -> psk, e   (read from initiator)
        ss.mix_key_and_hash(psk)
        msg1 = await reader.readexactly(DHLEN + TAGLEN)
        their_e_pub = msg1[:DHLEN]
        payload1 = msg1[DHLEN:]
        ss.mix_hash(their_e_pub)
        ss.decrypt_and_hash(payload1)

        # <- e, ee
        e_priv = X25519PrivateKey.generate()
        e_pub = e_priv.public_key().public_bytes_raw()
        ss.mix_hash(e_pub)
        dh = e_priv.exchange(X25519PublicKey.from_public_bytes(their_e_pub))
        ss.mix_key(dh)
        payload2 = ss.encrypt_and_hash(b"")
        await _write_frame(writer, e_pub + payload2)

        c1, c2 = ss.split()
        return HandshakeResult(send=c2, recv=c1)
