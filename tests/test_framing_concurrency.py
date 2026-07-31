"""Concurrent senders sharing one SecureFramer -- this is the real shape of
SOCKS usage (many simultaneous channels all writing through one encrypted
connection), which none of the other tests exercise since they only ever
have one thing in flight at a time.
"""

from __future__ import annotations

import asyncio

import pytest

from tunnelcat.crypto import pairing
from tunnelcat.crypto.framing import SecureFramer
from tunnelcat.crypto.noise import perform_handshake


async def _make_framers():
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
    return SecureFramer(a_r, a_w, hs_a), SecureFramer(b_r, b_w, hs_b)


@pytest.mark.asyncio
async def test_many_concurrent_senders_all_decrypt_correctly():
    """Fire a large number of concurrent .send() calls from many tasks and
    make sure every single one decrypts cleanly on the other end -- if
    encryption and the wire write aren't atomic w.r.t. each other, nonce
    assignment order can diverge from wire order under concurrency and the
    receiver's monotonic nonce counter desyncs, breaking every frame after
    the first reordering.
    """
    framer_a, framer_b = await _make_framers()

    n_senders = 40
    msgs_per_sender = 5
    expected = set()

    async def sender(i):
        for j in range(msgs_per_sender):
            payload = f"sender-{i}-msg-{j}".encode()
            expected.add(payload)
            await framer_a.send(payload)
            await asyncio.sleep(0)  # yield, maximize interleaving

    async def receiver():
        got = set()
        for _ in range(n_senders * msgs_per_sender):
            got.add(await framer_b.recv())
        return got

    recv_task = asyncio.create_task(receiver())
    await asyncio.gather(*(sender(i) for i in range(n_senders)))
    got = await recv_task

    assert got == expected

    framer_a.close()
    framer_b.close()
