import asyncio

import pytest

from tunnelcat.crypto import pairing
from tunnelcat.crypto.noise import perform_handshake, HandshakeFailed
from tunnelcat.crypto.framing import SecureFramer


async def _pipe_pair():
    """Two in-process asyncio streams connected back to back via a loopback socket."""
    server_reader_writer = {}

    async def on_conn(reader, writer):
        server_reader_writer["reader"] = reader
        server_reader_writer["writer"] = writer
        server_reader_writer["ready"].set_result(None)

    server_reader_writer["ready"] = asyncio.get_event_loop().create_future()
    server = await asyncio.start_server(on_conn, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    client_reader, client_writer = await asyncio.open_connection("127.0.0.1", port)
    await server_reader_writer["ready"]
    server.close()
    return (client_reader, client_writer), (server_reader_writer["reader"], server_reader_writer["writer"])


@pytest.mark.asyncio
async def test_handshake_and_framing_roundtrip():
    code = pairing.generate_pairing_code()
    psk = pairing.derive_psk(pairing.code_to_bytes(code))

    (a_r, a_w), (b_r, b_w) = await _pipe_pair()

    hs_a, hs_b = await asyncio.gather(
        perform_handshake(a_r, a_w, psk, initiator=True),
        perform_handshake(b_r, b_w, psk, initiator=False),
    )

    framer_a = SecureFramer(a_r, a_w, hs_a)
    framer_b = SecureFramer(b_r, b_w, hs_b)

    await framer_a.send(b"hello from initiator")
    assert await framer_b.recv() == b"hello from initiator"

    await framer_b.send(b"hello back")
    assert await framer_a.recv() == b"hello back"

    framer_a.close()
    framer_b.close()


@pytest.mark.asyncio
async def test_handshake_fails_with_wrong_psk():
    code1 = pairing.generate_pairing_code()
    code2 = pairing.generate_pairing_code()
    psk1 = pairing.derive_psk(pairing.code_to_bytes(code1))
    psk2 = pairing.derive_psk(pairing.code_to_bytes(code2))

    (a_r, a_w), (b_r, b_w) = await _pipe_pair()

    with pytest.raises(HandshakeFailed):
        await asyncio.gather(
            perform_handshake(a_r, a_w, psk1, initiator=True),
            perform_handshake(b_r, b_w, psk2, initiator=False),
        )


def test_derivations_are_independent():
    code = pairing.generate_pairing_code()
    cb = pairing.code_to_bytes(code)
    psk = pairing.derive_psk(cb)
    sid = pairing.derive_session_id(cb)
    assert psk != sid
    assert len(psk) == 32
    assert len(sid) == 32
