from __future__ import annotations

import asyncio

import click
from rich.console import Console

from ..common import link as linkmod
from ..common.clierrors import handle_errors
from ..crypto import pairing as pairingmod
from ..relay.chain import parse_chain_spec
from .app import OperatorApp
from .display import ChainDisplay
from .repl import run_repl

_GROUP_EPILOG = """\b
Which subcommand to use:
  listen   the agent can reach you (you have a public/routable address)
  connect  you can reach the agent (it's listening and told you its address)
  pair     neither can reach the other directly, go through a relay

Run 'tunnelcat operator <subcommand> --help' for details on each.
"""


@click.group("operator", epilog=_GROUP_EPILOG)
def operator_group():
    """Operator side: pairs with an agent and exposes local SOCKS5 + forwards."""


def _socks_options(f):
    f = click.option("--socks-port", type=int, default=1080, show_default=True, help="Local port for the SOCKS5 proxy (point Burp/browser at this).")(f)
    f = click.option("--socks-host", default="127.0.0.1", show_default=True, help="Local address to bind the SOCKS5 proxy to.")(f)
    return f


def _optional_code_option(f):
    return click.option("--code", default=None, help="Reuse an existing pairing code instead of generating one.")(f)


async def _after_pair(app: OperatorApp, display: ChainDisplay, socks_host: str, socks_port: int) -> None:
    await app.start_socks5(socks_host, socks_port)
    await run_repl(app, display.console)
    if app.session:
        await app.session.close()


def _run_operator(console: Console, title: str, socks_host: str, socks_port: int, pair_fn) -> None:
    """Build the display and app, print the live chain tree, and drive one
    pairing session through to the interactive REPL.

    pair_fn is a coroutine function that takes the OperatorApp and performs
    whichever pairing mode the calling command uses.
    """
    display = ChainDisplay(console)
    display.start(title)
    app = OperatorApp(on_event=display.on_event)

    async def main():
        await pair_fn(app)
        await _after_pair(app, display, socks_host, socks_port)

    asyncio.run(main())


@operator_group.command(
    "listen",
    epilog="Example:\n\n  tunnelcat operator listen --port 8443",
)
@click.option("--bind", "bind_host", default="0.0.0.0", show_default=True, help="Address to bind the listener to.")
@click.option("--port", "bind_port", type=int, required=True, help="Port to bind the listener to, must be reachable by the agent.")
@click.option("--advertise-host", default=None, help="Address to embed in the printed agent link (default: --bind, or 127.0.0.1 if bind is 0.0.0.0).")
@_optional_code_option
@_socks_options
@handle_errors
def listen_cmd(bind_host, bind_port, advertise_host, code, socks_host, socks_port):
    """Listen directly for an agent (use when the agent can reach you)."""
    console = Console()
    code = code or pairingmod.generate_pairing_code()
    advertised = advertise_host or (bind_host if bind_host != "0.0.0.0" else "127.0.0.1")
    agent_link = linkmod.encode_direct(advertised, bind_port, code)
    console.print(f"[cyan]Agent one-liner:[/cyan]  tunnelcat agent join {agent_link}")

    _run_operator(
        console,
        f"operator (listening on {bind_host}:{bind_port})",
        socks_host,
        socks_port,
        pair_fn=lambda app: app.pair_direct_listen(bind_host, bind_port, code=code),
    )


@operator_group.command(
    "connect",
    epilog="Example:\n\n  tunnelcat operator connect 203.0.113.5 8443 --code CODE",
)
@click.argument("host")
@click.argument("port", type=int)
@click.option("--code", required=True, help="Pairing code printed by the agent when it started listening.")
@_socks_options
@handle_errors
def connect_cmd(host, port, code, socks_host, socks_port):
    """Connect directly to an agent that is listening (you have its reachable address)."""
    _run_operator(
        Console(),
        f"operator -> {host}:{port} (direct connect)",
        socks_host,
        socks_port,
        pair_fn=lambda app: app.pair_direct_connect(host, port, code),
    )


@operator_group.command(
    "pair",
    epilog=(
        "\b\n"
        "Examples:\n\n"
        "  tunnelcat operator pair --relay-chain relay.example.com:8443:TOKEN\n\n"
        "  tunnelcat operator pair --relay-chain "
        "relay1.example.com:8443:tokA,relay2.example.com:8443:tokB"
    ),
)
@click.option("--relay-chain", "relay_chain", required=True, help="host:port:token,host:port:token,... (order matters)")
@click.option("--agent-hop", default=None, help="host:port:token the agent should join through (default: last hop of --relay-chain)")
@_optional_code_option
@_socks_options
@handle_errors
def pair_cmd(relay_chain, agent_hop, code, socks_host, socks_port):
    """Pair with an agent through one relay or a chain of relays."""
    chain = parse_chain_spec(relay_chain)
    console = Console()
    code = code or pairingmod.generate_pairing_code()

    agent_hop_spec = agent_hop or f"{chain[-1].host}:{chain[-1].port}:{chain[-1].token}"
    agent_link = linkmod.encode_relay(agent_hop_spec, code)
    console.print(f"[cyan]Agent one-liner:[/cyan]  tunnelcat agent join {agent_link}")

    path = " -> ".join(h.addr for h in chain) + " -> agent"
    _run_operator(
        console,
        f"operator -> {path}",
        socks_host,
        socks_port,
        pair_fn=lambda app: app.pair_via_relay(chain, code=code),
    )
