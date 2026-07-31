import asyncio

import pytest

from tunnelcat.crypto import pairing
from tunnelcat.crypto.noise import perform_handshake
from tunnelcat.crypto.framing import SecureFramer
from tunnelcat.mux import Session


async def _make_sessions():
    code = pairing.generate_pairing_code()
    psk = pairing.derive_psk(pairing.code_to_bytes(code))

    fut = asyncio.get_event_loop().create_future()

    async def on_conn(reader, writer):
        fut.set_result((reader, writer))

    server = await asyncio.start_server(on_conn, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    a_r, a_w = await asyncio.open_connection("127.0.0.1", port)
    b_r, b_w = await fut
    server.close()

    hs_a, hs_b = await asyncio.gather(
        perform_handshake(a_r, a_w, psk, initiator=True),
        perform_handshake(b_r, b_w, psk, initiator=False),
    )
    sess_a = Session(SecureFramer(a_r, a_w, hs_a), is_transport_initiator=True)
    sess_b = Session(SecureFramer(b_r, b_w, hs_b), is_transport_initiator=False)
    sess_a.start()
    sess_b.start()
    return sess_a, sess_b


@pytest.mark.asyncio
async def test_control_channel_roundtrip():
    sess_a, sess_b = await _make_sessions()
    await sess_a.send_control(b"ping")
    assert await sess_b.recv_control() == b"ping"
    await sess_b.send_control(b"pong")
    assert await sess_a.recv_control() == b"pong"
    await sess_a.close()
    await sess_b.close()


@pytest.mark.asyncio
async def test_data_channel_open_and_relay():
    sess_a, sess_b = await _make_sessions()

    async def acceptor():
        ch = await sess_b.accept_channel()
        assert ch.open_metadata == b"target-info"
        await sess_b.confirm_channel(ch)
        data = await ch.read()
        await ch.write(data.upper())
        await ch.close()

    accept_task = asyncio.create_task(acceptor())

    ch_a = await sess_a.open_channel(metadata=b"target-info")
    await ch_a.write(b"hello")
    reply = await ch_a.read()
    assert reply == b"HELLO"
    assert await ch_a.read() is None  # EOF after close

    await accept_task
    await sess_a.close()
    await sess_b.close()


@pytest.mark.asyncio
async def test_channel_rejection():
    sess_a, sess_b = await _make_sessions()

    async def rejector():
        ch = await sess_b.accept_channel()
        await sess_b.reject_channel(ch, reason=b"nope")

    reject_task = asyncio.create_task(rejector())

    from tunnelcat.mux import ChannelOpenFailed

    with pytest.raises(ChannelOpenFailed):
        await sess_a.open_channel(metadata=b"x")

    await reject_task
    await sess_a.close()
    await sess_b.close()
