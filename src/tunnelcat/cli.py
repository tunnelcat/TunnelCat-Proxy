from __future__ import annotations

import click

from .agent.cli import agent_group
from .operator.cli import operator_group
from .relay.cli import serve as relay_serve_cmd

_MAIN_EPILOG = """\
\b
Quickstart (direct, agent reachable from operator):
  operator$  tunnelcat operator listen --port 8443
  agent$     tunnelcat agent join <link printed above>

\b
Quickstart (through a relay, neither side reachable to the other):
  relay-vps$    tunnelcat relay serve --port 8443 --token SECRET
  workstation$  tunnelcat operator pair --relay-chain relay.example.com:8443:SECRET
  target$       tunnelcat agent join <link printed above>

Run 'tunnelcat <group> --help' (operator, agent, relay) for the
subcommands in each, or 'tunnelcat <group> <subcommand> --help' for a
specific one.
"""


@click.group("relay")
def relay_group():
    """Run a relay: rendezvous + blind splice for operator<->agent pairing."""


relay_group.add_command(relay_serve_cmd)


@click.group(epilog=_MAIN_EPILOG)
@click.version_option()
def main():
    """TunnelCat: E2E-encrypted, paired SOCKS5/port-forward tunneling for authorized pentest pivoting."""


main.add_command(operator_group)
main.add_command(agent_group)
main.add_command(relay_group)


if __name__ == "__main__":
    main()
