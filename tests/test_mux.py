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
async def test_drain_task_completes_on_fast_path_close():
    """Regression test: a channel whose consumer always keeps up (so every
    frame, including the final EOF, is delivered via the fast path) must
    not leave its per-channel drain task permanently pending. That task
    only self-terminates on a sentinel that the fast path -- by design --
    never routes through it, so _push must cancel it explicitly instead.
    Left unfixed, every such channel (the common case) leaks one task
    forever, logged by asyncio as "Task was destroyed but it is pending"."""
    sess_a, sess_b = await _make_sessions()

    async def acceptor():
        ch = await sess_b.accept_channel()
        await sess_b.confirm_channel(ch)
        assert await ch.read() == b"hi"
        await ch.close()
        return ch

    accept_task = asyncio.create_task(acceptor())

    ch_a = await sess_a.open_channel(metadata=b"x")
    await ch_a.write(b"hi")
    await ch_a.close()  # both directions closed -> both peers see EOF via the fast path
    assert await ch_a.read() is None  # peer's close (EOF), fast path throughout

    ch_b = await accept_task
    for ch in (ch_a, ch_b):
        try:
            await asyncio.wait_for(asyncio.shield(ch._drain_task), timeout=2)
        except asyncio.CancelledError:
            pass
        assert ch._drain_task.cancelled(), "drain task leaked instead of being cancelled"

    await sess_a.close()
    await sess_b.close()


@pytest.mark.asyncio
async def test_session_close_leaves_no_dangling_tasks():
    """Regression test: Session.close() must fully retire its reader task
    and transport, not just request cancellation and move on -- otherwise
    the task (or the transport's StreamWriter, finalized after the loop
    that owned it is gone) can be torn down mid-flight, which is exactly
    the class of bug that produced "Task was destroyed but it is pending"
    / "Event loop is closed" warnings in production."""
    sess_a, sess_b = await _make_sessions()
    reader_task_a, reader_task_b = sess_a._reader_task, sess_b._reader_task

    await sess_a.close()
    await sess_b.close()

    assert reader_task_a.done()
    assert reader_task_b.done()


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
