from __future__ import annotations

import asyncio

import click
from rich.console import Console

from ..common import link as linkmod
from ..common.clierrors import handle_errors
from ..relay.chain import parse_chain_spec
from .app import AgentApp
from .display import simple_on_event

_GROUP_EPILOG = """\b
Which subcommand to use:
  connect  the operator is listening and told you its address
  listen   the operator can reach you (you have a routable address)
  relay    neither can reach the other directly, go through a relay
  join     paste the one-liner link the operator printed, picks the
           right mode automatically

Run 'tunnelcat agent <subcommand> --help' for details on each.
"""


@click.group("agent", epilog=_GROUP_EPILOG)
def agent_group():
    """Agent side: run this on the machine you want to pivot through."""


def _run_agent(pair_fn) -> None:
    """Build the agent app and drive one pairing session to completion.

    pair_fn is a coroutine function that takes the AgentApp and performs
    whichever pairing mode the calling command uses.
    """
    console = Console()
    app = AgentApp(on_event=simple_on_event(console))

    async def main():
        await pair_fn(app)
        await app.run()

    asyncio.run(main())


@agent_group.command(
    "connect",
    epilog="Example:\n\n  tunnelcat agent connect 10.0.4.12 8443 --code CODE",
)
@click.argument("host")
@click.argument("port", type=int)
@click.option("--code", required=True, help="Pairing code printed by the operator when it started listening.")
@handle_errors
def connect_cmd(host, port, code):
    """Connect directly out to a listening operator."""
    _run_agent(lambda app: app.pair_direct_connect(host, port, code))


@agent_group.command(
    "listen",
    epilog="Example:\n\n  tunnelcat agent listen --port 8443",
)
@click.option("--bind", "bind_host", default="0.0.0.0", show_default=True, help="Address to bind the listener to.")
@click.option("--port", "bind_port", type=int, required=True, help="Port to bind the listener to, must be reachable by the operator.")
@click.option("--code", required=True, help="Pairing code printed by the operator.")
@handle_errors
def listen_cmd(bind_host, bind_port, code):
    """Listen directly for the operator to connect in."""
    _run_agent(lambda app: app.pair_direct_listen(bind_host, bind_port, code))


@agent_group.command(
    "relay",
    epilog="Example:\n\n  tunnelcat agent relay --chain relay.example.com:8443:TOKEN --code CODE",
)
@click.option("--chain", "chain_spec", required=True, help="host:port:token,... (usually just the one relay you can reach)")
@click.option("--code", required=True, help="Pairing code printed by the operator.")
@handle_errors
def relay_cmd(chain_spec, code):
    """Pair with the operator through a relay (or relay chain)."""
    chain = parse_chain_spec(chain_spec)
    _run_agent(lambda app: app.pair_via_relay(chain, code))


@agent_group.command(
    "join",
    epilog="Example:\n\n  tunnelcat agent join tnl://...",
)
@click.argument("link_str", metavar="LINK")
@handle_errors
def join_cmd(link_str):
    """Pair using a tnl:// link printed by 'tunnelcat operator listen/pair'."""
    payload = linkmod.decode(link_str)

    async def do_pair(app: AgentApp) -> None:
        if payload["mode"] == "direct":
            await app.pair_direct_connect(payload["host"], payload["port"], payload["code"])
        elif payload["mode"] == "relay":
            chain = parse_chain_spec(payload["chain"])
            await app.pair_via_relay(chain, payload["code"])
        else:
            raise click.ClickException(f"unknown link mode {payload['mode']!r}")

    _run_agent(do_pair)
