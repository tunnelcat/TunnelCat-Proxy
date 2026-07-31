from __future__ import annotations

import asyncio
import logging

import click

from ..common.clierrors import handle_errors
from .server import RelayServer


@click.command(
    "serve",
    epilog=(
        "\b\n"
        "Examples:\n\n"
        "  tunnelcat relay serve --port 8443 --token SECRET\n\n"
        "  tunnelcat relay serve --port 8443 --token SECRET "
        "--allow-next relay2.example.com:8443"
    ),
)
@click.option("--bind", "bind_host", default="0.0.0.0", show_default=True, help="Address to bind the relay to.")
@click.option("--port", "bind_port", type=int, required=True, help="Port to bind the relay to, must be reachable by whoever connects to this hop.")
@click.option("--token", required=True, envvar="TUNNELCAT_RELAY_TOKEN", help="Admin token required to REGISTER or HOP through this relay. Also settable via TUNNELCAT_RELAY_TOKEN.")
@click.option("--allow-next", "allow_next", multiple=True, help="host:port this relay is permitted to forward HOPs to. Repeatable. Required for chaining.")
@click.option("--default-next", default=None, help="Silently forward every request here (hides the rest of the chain from clients).")
@click.option("--label", "self_label", default=None, help="Display name for this relay in hop status (default host:port).")
@click.option("--session-timeout", type=float, default=300.0, show_default=True, help="Seconds an unmatched REGISTER is kept before expiring.")
@click.option("-v", "--verbose", is_flag=True, help="Enable debug logging.")
@handle_errors
def serve(bind_host, bind_port, token, allow_next, default_next, self_label, session_timeout, verbose):
    """Run a relay: rendezvous + blind byte-splice for operator<->agent pairing.

    The relay never sees the pairing code, the psk, or any tunnel payload,
    only a session_id used purely for matching two connections together.
    """
    logging.basicConfig(level=logging.DEBUG if verbose else logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    relay = RelayServer(
        bind_host=bind_host,
        bind_port=bind_port,
        admin_token=token,
        self_label=self_label,
        allow_next=set(allow_next),
        default_next=default_next,
        session_timeout=session_timeout,
    )
    asyncio.run(relay.serve_forever())
