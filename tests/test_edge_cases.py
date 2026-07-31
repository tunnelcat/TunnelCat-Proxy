from __future__ import annotations

import asyncio
import os

import pytest

from tunnelcat.agent.app import AgentApp
from tunnelcat.crypto import pairing
from tunnelcat.crypto.noise import HandshakeFailed
from tunnelcat.operator.app import OperatorApp
from tunnelcat.relay.chain import HopTarget, RelayError, connect_through_chain
from tunnelcat.protocol import relaywire as W

from test_e2e import _echo_server, _pair_direct, _socks5_roundtrip


# -- SOCKS5 / mux correctness under load -----------------------------------


@pytest.mark.asyncio
async def test_large_payload_roundtrip_through_socks():
    """5MB through a single tunneled connection, byte-perfect, with the
    client reading the (streaming) echo concurrently with writing -- like
    any real client (Burp, curl, a browser) actually behaves."""

    async def streaming_echo(reader, writer):
        while True:
            chunk = await reader.read(65536)
            if not chunk:
                break
            writer.write(chunk)
            await writer.drain()
        writer.close()

    server = await asyncio.start_server(streaming_echo, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]

    operator, agent, _, _ = await _pair_direct()
    socks_addr = await operator.start_socks5("127.0.0.1", 0)

    payload = os.urandom(5 * 1024 * 1024)

    reader, writer = await asyncio.open_connection("127.0.0.1", socks_addr[1])
    writer.write(bytes([0x05, 1, 0x00]))
    await writer.drain()
    await reader.readexactly(2)
    host_bytes = b"localhost"
    req = bytes([0x05, 0x01, 0x00, 0x03, len(host_bytes)]) + host_bytes + port.to_bytes(2, "big")
    writer.write(req)
    await writer.drain()
    reply = await reader.readexactly(4)
    assert reply[1] == 0x00
    await reader.readexactly(4 + 2)  # bnd.addr(ipv4) + bnd.port

    async def sender():
        writer.write(payload)
        await writer.drain()
        writer.write_eof()

    async def receiver():
        got = b""
        while len(got) < len(payload):
            chunk = await reader.read(65536)
            if not chunk:
                break
            got += chunk
        return got

    _, got = await asyncio.wait_for(asyncio.gather(sender(), receiver()), timeout=20)

    assert got == payload, f"corruption: got {len(got)} bytes, expected {len(payload)}"

    server.close()
    await operator.session.close()
    await agent.session.close()


@pytest.mark.asyncio
async def test_stalled_channel_does_not_block_sibling_channels():
    """Regression test for a head-of-line-blocking bug: one SOCKS
    connection whose client never reads its (large) response used to
    freeze the shared session's read loop, hanging every other concurrent
    connection too -- a real problem for Burp-style usage with many
    simultaneous connections."""

    async def slow_target(reader, writer):
        try:
            for _ in range(400):  # far more than the intake bound can absorb
                writer.write(b"x" * 65536)
                await writer.drain()
        except (ConnectionError, asyncio.CancelledError):
            pass
        finally:
            writer.close()

    target_server, target_port = await _echo_server()
    slow_server = await asyncio.start_server(slow_target, "127.0.0.1", 0)
    slow_port = slow_server.sockets[0].getsockname()[1]

    operator, agent, _, _ = await _pair_direct()
    socks_addr = await operator.start_socks5("127.0.0.1", 0)

    async def open_stalled():
        r, w = await asyncio.open_connection("127.0.0.1", socks_addr[1])
        try:
            w.write(bytes([0x05, 1, 0x00]))
            await w.drain()
            await r.readexactly(2)
            hb = b"localhost"
            req = bytes([0x05, 0x01, 0x00, 0x03, len(hb)]) + hb + slow_port.to_bytes(2, "big")
            w.write(req)
            await w.drain()
            await r.readexactly(4)
            await r.readexactly(4 + 2)
            # deliberately never read again -- this consumer is stalled
            await asyncio.sleep(3)
        finally:
            # Reached via cancellation (the test cancels this task well
            # before the sleep above elapses) as much as via normal
            # completion, so this must be a finally, not a trailing line.
            w.close()

    stalled_task = asyncio.create_task(open_stalled())
    await asyncio.sleep(0.5)  # let the stalled channel's intake fill up

    resp = await asyncio.wait_for(
        _socks5_roundtrip("127.0.0.1", socks_addr[1], "localhost", target_port, b"sibling-should-not-hang"),
        timeout=5,
    )
    assert resp == b"ECHO:sibling-should-not-hang"

    stalled_task.cancel()
    target_server.close()
    slow_server.close()
    await operator.session.close()
    await agent.session.close()


@pytest.mark.asyncio
async def test_many_concurrent_socks_connections_no_crosstalk():
    """N simultaneous SOCKS connections through one session -- each must get
    back exactly its own data, never another connection's."""

    async def tagging_echo(reader, writer):
        data = await reader.read(4096)
        writer.write(b"REPLY:" + data)
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(tagging_echo, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]

    operator, agent, _, _ = await _pair_direct()
    socks_addr = await operator.start_socks5("127.0.0.1", 0)

    n = 30

    async def one_client(i):
        tag = f"client-{i}".encode()
        resp = await _socks5_roundtrip("127.0.0.1", socks_addr[1], "localhost", port, tag)
        assert resp == b"REPLY:" + tag, f"crosstalk detected: client {i} got {resp!r}"

    await asyncio.gather(*(one_client(i) for i in range(n)))

    server.close()
    await operator.session.close()
    await agent.session.close()


@pytest.mark.asyncio
async def test_socks_target_connection_refused_returns_clean_error():
    operator, agent, _, _ = await _pair_direct()
    socks_addr = await operator.start_socks5("127.0.0.1", 0)

    # bind then immediately close to get a port nothing is listening on
    probe = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
    dead_port = probe.sockets[0].getsockname()[1]
    probe.close()
    await probe.wait_closed()

    reader, writer = await asyncio.open_connection("127.0.0.1", socks_addr[1])
    writer.write(bytes([0x05, 1, 0x00]))
    await writer.drain()
    await reader.readexactly(2)
    host_bytes = b"localhost"
    req = bytes([0x05, 0x01, 0x00, 0x03, len(host_bytes)]) + host_bytes + dead_port.to_bytes(2, "big")
    writer.write(req)
    await writer.drain()

    reply = await asyncio.wait_for(reader.readexactly(4), timeout=5)
    assert reply[1] != 0x00, "expected SOCKS failure reply for refused connection"

    writer.close()
    await operator.session.close()
    await agent.session.close()


@pytest.mark.asyncio
async def test_one_socks_client_closing_does_not_affect_others():
    target_server, target_port = await _echo_server()
    operator, agent, _, _ = await _pair_direct()
    socks_addr = await operator.start_socks5("127.0.0.1", 0)

    # Open and abruptly close one connection.
    r1, w1 = await asyncio.open_connection("127.0.0.1", socks_addr[1])
    w1.write(bytes([0x05, 1, 0x00]))
    await w1.drain()
    await r1.readexactly(2)
    w1.close()

    await asyncio.sleep(0.1)

    # Session must still be fully usable afterwards.
    resp = await _socks5_roundtrip("127.0.0.1", socks_addr[1], "localhost", target_port, b"still-alive")
    assert resp == b"ECHO:still-alive"

    target_server.close()
    await operator.session.close()
    await agent.session.close()


# -- background task robustness ----------------------------------------------


@pytest.mark.asyncio
async def test_channel_handler_exception_does_not_kill_acceptor_loop(monkeypatch, caplog):
    """Every SOCKS/-L/-R connection is serviced by a detached background
    task (run_channel_acceptor spawns one per accepted channel with nothing
    else referencing it). Regression test for two ways that used to go
    wrong: an exception inside one of those tasks got silently dropped
    (never logged, connection just died with no trace) instead of being
    caught and reported, and there was no guarantee the acceptor loop
    itself kept running for the next connection afterwards."""
    import logging

    from tunnelcat.mux.channel import Channel

    target_server, target_port = await _echo_server()
    operator, agent, _, _ = await _pair_direct()
    socks_addr = await operator.start_socks5("127.0.0.1", 0)

    real_pump_duplex = Channel.pump_duplex
    call_count = {"n": 0}

    async def flaky_pump_duplex(self, reader, writer):
        call_count["n"] += 1
        if call_count["n"] == 1:
            writer.close()  # a real failure mid-relay would still clean up its own socket
            raise RuntimeError("simulated relay failure")
        return await real_pump_duplex(self, reader, writer)

    monkeypatch.setattr(Channel, "pump_duplex", flaky_pump_duplex)

    with caplog.at_level(logging.ERROR):
        r, w = await asyncio.open_connection("127.0.0.1", socks_addr[1])
        w.write(bytes([0x05, 1, 0x00]))
        await w.drain()
        await r.readexactly(2)
        hb = b"localhost"
        req = bytes([0x05, 0x01, 0x00, 0x03, len(hb)]) + hb + target_port.to_bytes(2, "big")
        w.write(req)
        await w.drain()
        await r.readexactly(4)
        await r.readexactly(4 + 2)
        # Give the agent's detached handler task a chance to run and fail.
        await asyncio.sleep(0.2)
        w.close()

    assert any("relay error" in rec.message for rec in caplog.records), (
        "exception in a detached channel-handler task must be logged, not swallowed"
    )

    # The acceptor loop must still be alive: a fresh connection has to
    # succeed cleanly, proving one failed background task didn't take the
    # whole loop (or the session) down with it.
    resp = await _socks5_roundtrip("127.0.0.1", socks_addr[1], "localhost", target_port, b"still-alive")
    assert resp == b"ECHO:still-alive"

    target_server.close()
    await operator.session.close()
    await agent.session.close()


# -- pairing / handshake failure modes --------------------------------------


@pytest.mark.asyncio
async def test_wrong_pairing_code_fails_cleanly_not_hang():
    op_events = []
    listening_fut = asyncio.get_event_loop().create_future()

    def op_on_event(e, **kw):
        op_events.append((e, kw))
        if e == "listening" and not listening_fut.done():
            listening_fut.set_result((kw["host"], kw["port"]))

    operator = OperatorApp(on_event=op_on_event)
    agent = AgentApp(on_event=lambda e, **kw: None)

    real_code = pairing.generate_pairing_code()
    wrong_code = pairing.generate_pairing_code()
    assert real_code != wrong_code

    listen_task = asyncio.create_task(operator.pair_direct_listen("127.0.0.1", 0, code=real_code))
    host, port = await listening_fut

    with pytest.raises(HandshakeFailed):
        await asyncio.wait_for(agent.pair_direct_connect(host, port, wrong_code), timeout=5)

    # operator side should also fail (not hang forever) since its handshake
    # partner sent garbage relative to its psk
    with pytest.raises((HandshakeFailed, asyncio.IncompleteReadError, ConnectionError)):
        await asyncio.wait_for(listen_task, timeout=5)


@pytest.mark.asyncio
async def test_relay_wrong_admin_token_rejected(make_relay):
    relay = await make_relay(token="correct-token")
    code = pairing.generate_pairing_code()
    sid = pairing.derive_session_id(pairing.code_to_bytes(code)).hex()
    chain = [HopTarget("127.0.0.1", relay.bind_port, "WRONG-token")]

    with pytest.raises(RelayError):
        await connect_through_chain(chain, W.register(sid, "WRONG-token", "operator"), sid)


@pytest.mark.asyncio
async def test_relay_double_register_same_session_rejected(make_relay):
    relay = await make_relay(token="tok")
    code = pairing.generate_pairing_code()
    sid = pairing.derive_session_id(pairing.code_to_bytes(code)).hex()
    chain = [HopTarget("127.0.0.1", relay.bind_port, "tok")]

    first_waiting = asyncio.Event()

    def on_first_event(ev):
        if ev.status == "waiting_for_peer":
            first_waiting.set()

    async def first_register():
        try:
            await connect_through_chain(chain, W.register(sid, "tok", "operator-1"), sid, on_event=on_first_event)
        except RelayError:
            pass

    first_task = asyncio.create_task(first_register())
    try:
        await asyncio.wait_for(first_waiting.wait(), timeout=5)

        with pytest.raises(RelayError):
            await asyncio.wait_for(
                connect_through_chain(chain, W.register(sid, "tok", "operator-2"), sid), timeout=5
            )
    finally:
        first_task.cancel()
        await asyncio.gather(first_task, return_exceptions=True)


@pytest.mark.asyncio
async def test_relay_session_expires_after_timeout(make_relay):
    relay = await make_relay(token="tok", session_timeout=0.5)
    code = pairing.generate_pairing_code()
    sid = pairing.derive_session_id(pairing.code_to_bytes(code)).hex()
    chain = [HopTarget("127.0.0.1", relay.bind_port, "tok")]

    reader1, writer1 = await asyncio.open_connection("127.0.0.1", relay.bind_port)
    await W.send_msg(writer1, W.register(sid, "tok", "operator"))
    await W.recv_msg(reader1)
    await W.recv_msg(reader1)

    await asyncio.sleep(2.0)  # sweep interval scales with session_timeout, well within this window

    with pytest.raises(RelayError):
        await connect_through_chain(chain, W.join(sid, "agent"), sid, on_event=None)
