import asyncio

import pytest

from tunnelcat.crypto import pairing
from tunnelcat.relay.chain import HopTarget, connect_through_chain, RelayError
from tunnelcat.protocol import relaywire as W


@pytest.mark.asyncio
async def test_single_relay_register_join_and_splice(make_relay):
    relay = await make_relay(token="secret")
    code = pairing.generate_pairing_code()
    sid = pairing.derive_session_id(pairing.code_to_bytes(code)).hex()

    events_a, events_b = [], []
    chain = [HopTarget("127.0.0.1", relay.bind_port, "secret")]

    async def do_register():
        r, w = await connect_through_chain(chain, W.register(sid, "secret", "operator"), sid, on_event=events_a.append)
        return r, w

    async def do_join():
        await asyncio.sleep(0.05)
        r, w = await connect_through_chain(chain, W.join(sid, "agent"), sid, on_event=events_b.append)
        return r, w

    (r1, w1), (r2, w2) = await asyncio.gather(do_register(), do_join())

    w1.write(b"ping-through-relay")
    await w1.drain()
    got = await r2.readexactly(len(b"ping-through-relay"))
    assert got == b"ping-through-relay"

    assert any(e.status == "matched" for e in events_a)
    assert any(e.status == "matched" for e in events_b)

    w1.close()
    w2.close()


@pytest.mark.asyncio
async def test_join_without_register_fails(make_relay):
    relay = await make_relay(token="secret")
    code = pairing.generate_pairing_code()
    sid = pairing.derive_session_id(pairing.code_to_bytes(code)).hex()
    chain = [HopTarget("127.0.0.1", relay.bind_port, "secret")]

    with pytest.raises(RelayError):
        await connect_through_chain(chain, W.join(sid, "agent"), sid)


@pytest.mark.asyncio
async def test_two_hop_chain_forwards_and_splices(make_relay):
    relay2 = await make_relay(token="tok2")
    relay1 = await make_relay(token="tok1", allow_next={f"127.0.0.1:{relay2.bind_port}"})

    code = pairing.generate_pairing_code()
    sid = pairing.derive_session_id(pairing.code_to_bytes(code)).hex()

    chain_operator = [
        HopTarget("127.0.0.1", relay1.bind_port, "tok1"),
        HopTarget("127.0.0.1", relay2.bind_port, "tok2"),
    ]
    chain_agent = [HopTarget("127.0.0.1", relay2.bind_port, "tok2")]

    events = []

    async def do_register():
        return await connect_through_chain(chain_operator, W.register(sid, "tok2", "operator"), sid, on_event=events.append)

    async def do_join():
        await asyncio.sleep(0.05)
        return await connect_through_chain(chain_agent, W.join(sid, "agent"), sid)

    (r1, w1), (r2, w2) = await asyncio.gather(do_register(), do_join())

    w2.write(b"hello-from-agent")
    await w2.drain()
    got = await r1.readexactly(len(b"hello-from-agent"))
    assert got == b"hello-from-agent"

    # We should have seen relay1's self-announcement, relay2's self-announcement
    # (forwarded transparently through relay1), and the final matched event.
    hops_seen = [e.hop for e in events]
    assert f"127.0.0.1:{relay1.bind_port}" in hops_seen
    assert f"127.0.0.1:{relay2.bind_port}" in hops_seen
    assert events[-1].status == "matched"

    w1.close()
    w2.close()


@pytest.mark.asyncio
async def test_close_pending_sessions_closes_unjoined_registrant(make_relay):
    """A registrant that never gets joined (dropped connection, abandoned
    pairing attempt) otherwise sits in relay._pending holding an open
    socket until _sweep_expired's timeout -- up to five minutes by
    default. close_pending_sessions() is the immediate-shutdown path for
    that; regression test for it actually closing the socket rather than
    just clearing the dict."""
    relay = await make_relay(token="secret")
    code = pairing.generate_pairing_code()
    sid = pairing.derive_session_id(pairing.code_to_bytes(code)).hex()
    chain = [HopTarget("127.0.0.1", relay.bind_port, "secret")]

    waiting = asyncio.Event()

    def on_event(ev):
        if ev.status == "waiting_for_peer":
            waiting.set()

    reg_task = asyncio.create_task(
        connect_through_chain(chain, W.register(sid, "secret", "operator"), sid, on_event=on_event)
    )
    await asyncio.wait_for(waiting.wait(), timeout=5)
    assert sid in relay._pending
    pending_writer = relay._pending[sid].writer

    relay.close_pending_sessions()

    assert sid not in relay._pending
    assert pending_writer.is_closing()

    reg_task.cancel()
    await asyncio.gather(reg_task, return_exceptions=True)


@pytest.mark.asyncio
async def test_hop_denied_when_not_in_allowlist(make_relay):
    relay2 = await make_relay(token="tok2")
    relay1 = await make_relay(token="tok1", allow_next=set())  # nothing allowed

    code = pairing.generate_pairing_code()
    sid = pairing.derive_session_id(pairing.code_to_bytes(code)).hex()
    chain = [
        HopTarget("127.0.0.1", relay1.bind_port, "tok1"),
        HopTarget("127.0.0.1", relay2.bind_port, "tok2"),
    ]

    with pytest.raises(RelayError):
        await connect_through_chain(chain, W.register(sid, "tok2", "operator"), sid)
