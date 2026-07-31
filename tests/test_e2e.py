"""Full end-to-end tests driving the real OperatorApp/AgentApp (and, for the
relay case, real RelayServer instances) over real loopback sockets -- the
same code path the CLI uses, just without spawning subprocesses.
"""

from __future__ import annotations

import asyncio

import pytest

from tunnelcat.agent.app import AgentApp
from tunnelcat.crypto import pairing
from tunnelcat.operator.app import OperatorApp
from tunnelcat.relay.chain import HopTarget


async def _echo_server():
    async def handler(reader, writer):
        data = await reader.read(4096)
        writer.write(b"ECHO:" + data)
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    return server, port


async def _socks5_roundtrip(proxy_host, proxy_port, target_host, target_port, payload):
    reader, writer = await asyncio.open_connection(proxy_host, proxy_port)
    writer.write(bytes([0x05, 1, 0x00]))
    await writer.drain()
    assert await reader.readexactly(2) == bytes([0x05, 0x00])

    host_bytes = target_host.encode()
    req = bytes([0x05, 0x01, 0x00, 0x03, len(host_bytes)]) + host_bytes + target_port.to_bytes(2, "big")
    writer.write(req)
    await writer.drain()

    reply = await reader.readexactly(4)
    assert reply[1] == 0x00, f"SOCKS connect failed, rep={reply[1]}"
    atyp = reply[3]
    if atyp == 0x01:
        await reader.readexactly(4 + 2)
    elif atyp == 0x03:
        length = (await reader.readexactly(1))[0]
        await reader.readexactly(length + 2)
    elif atyp == 0x04:
        await reader.readexactly(16 + 2)

    writer.write(payload)
    await writer.drain()
    resp = await reader.read(4096)
    writer.close()
    return resp


async def _pair_direct(code=None):
    code = code or pairing.generate_pairing_code()
    op_events, ag_events = [], []
    listening_fut = asyncio.get_event_loop().create_future()
    agent_hello_seen = asyncio.Event()

    def op_on_event(e, **kw):
        op_events.append((e, kw))
        if e == "listening" and not listening_fut.done():
            listening_fut.set_result((kw["host"], kw["port"]))
        if e == "agent_hello":
            agent_hello_seen.set()

    operator = OperatorApp(on_event=op_on_event)
    agent = AgentApp(on_event=lambda e, **kw: ag_events.append((e, kw)))

    listen_task = asyncio.create_task(operator.pair_direct_listen("127.0.0.1", 0, code=code))
    host, port = await listening_fut
    agent_task = asyncio.create_task(agent.pair_direct_connect(host, port, code))
    await asyncio.gather(listen_task, agent_task)
    asyncio.create_task(agent.run())

    # agent_hello arrives asynchronously via the operator's background
    # control loop -- wait for it so callers can rely on
    # operator.agent_identity being populated rather than racing it.
    await asyncio.wait_for(agent_hello_seen.wait(), timeout=5)
    return operator, agent, op_events, ag_events


@pytest.mark.asyncio
async def test_direct_pairing_authenticates_agent_identity():
    operator, agent, op_events, ag_events = await _pair_direct()
    assert operator.agent_identity is not None
    assert operator.agent_identity["hostname"]
    assert any(e == "agent_hello" for e, _ in op_events)
    await operator.session.close()
    await agent.session.close()


@pytest.mark.asyncio
async def test_socks5_through_direct_tunnel_reaches_target_via_agent():
    target_server, target_port = await _echo_server()
    operator, agent, _, _ = await _pair_direct()

    socks_addr = await operator.start_socks5("127.0.0.1", 0)
    resp = await _socks5_roundtrip("127.0.0.1", socks_addr[1], "localhost", target_port, b"hello-through-tunnel")
    assert resp == b"ECHO:hello-through-tunnel"

    target_server.close()
    await operator.session.close()
    await agent.session.close()


@pytest.mark.asyncio
async def test_local_forward_minus_L():
    target_server, target_port = await _echo_server()
    operator, agent, _, _ = await _pair_direct()

    addr = await operator.add_local_forward("127.0.0.1", 0, "localhost", target_port)
    reader, writer = await asyncio.open_connection(addr[0], addr[1])
    writer.write(b"via-L-forward")
    await writer.drain()
    resp = await reader.read(4096)
    assert resp == b"ECHO:via-L-forward"

    target_server.close()
    await operator.session.close()
    await agent.session.close()


@pytest.mark.asyncio
async def test_remote_forward_minus_R():
    # Target reachable from the *operator's* side; agent exposes a port that,
    # when connected to, causes the operator to connect out to the target.
    target_server, target_port = await _echo_server()
    operator, agent, _, _ = await _pair_direct()

    bound_port = await operator.add_remote_forward("127.0.0.1", 0, "localhost", target_port)
    reader, writer = await asyncio.open_connection("127.0.0.1", bound_port)
    writer.write(b"via-R-forward")
    await writer.drain()
    resp = await reader.read(4096)
    assert resp == b"ECHO:via-R-forward"

    target_server.close()
    await operator.session.close()
    await agent.session.close()


@pytest.mark.asyncio
async def test_full_relay_chain_with_socks_and_live_hop_events(make_relay):
    relay2 = await make_relay(token="tok2")
    relay1 = await make_relay(token="tok1", allow_next={f"127.0.0.1:{relay2.bind_port}"})

    target_server, target_port = await _echo_server()

    code = pairing.generate_pairing_code()
    op_events = []
    agent_hello_seen = asyncio.Event()

    def op_on_event(e, **kw):
        op_events.append((e, kw))
        if e == "agent_hello":
            agent_hello_seen.set()

    operator = OperatorApp(on_event=op_on_event)
    agent = AgentApp(on_event=lambda e, **kw: None)

    operator_chain = [
        HopTarget("127.0.0.1", relay1.bind_port, "tok1"),
        HopTarget("127.0.0.1", relay2.bind_port, "tok2"),
    ]
    agent_chain = [HopTarget("127.0.0.1", relay2.bind_port, "tok2")]

    op_task = asyncio.create_task(operator.pair_via_relay(operator_chain, code=code))
    await asyncio.sleep(0.05)
    ag_task = asyncio.create_task(agent.pair_via_relay(agent_chain, code))
    await asyncio.gather(op_task, ag_task)
    asyncio.create_task(agent.run())

    # agent_hello arrives asynchronously via the operator's background
    # control loop, not synchronously by the time pairing itself returns --
    # wait for it explicitly rather than racing it.
    await asyncio.wait_for(agent_hello_seen.wait(), timeout=5)

    # The operator should have seen both relay hops announce themselves,
    # in order, plus the final matched/paired/hello sequence -- this is
    # exactly the visibility the live CLI tree renders.
    relay_hops_seen = [kw["hop"] for e, kw in op_events if e == "relay_hop"]
    assert f"127.0.0.1:{relay1.bind_port}" in relay_hops_seen
    assert f"127.0.0.1:{relay2.bind_port}" in relay_hops_seen
    assert relay_hops_seen.index(f"127.0.0.1:{relay1.bind_port}") < relay_hops_seen.index(f"127.0.0.1:{relay2.bind_port}")
    assert any(e == "paired" for e, _ in op_events)
    assert any(e == "agent_hello" for e, _ in op_events)

    socks_addr = await operator.start_socks5("127.0.0.1", 0)
    resp = await _socks5_roundtrip("127.0.0.1", socks_addr[1], "localhost", target_port, b"through-two-relays")
    assert resp == b"ECHO:through-two-relays"

    target_server.close()
    await operator.session.close()
    await agent.session.close()
