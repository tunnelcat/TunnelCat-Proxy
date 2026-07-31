from __future__ import annotations

import asyncio
import sys

from rich.console import Console

from .app import OperatorApp

_HELP = (
    "[dim]Commands:\n"
    "  forward -L <local_port>:<target_host>:<target_port>   (SOCKS-style, via agent)\n"
    "  forward -R <remote_port>:<target_host>:<target_port>  (agent listens, you connect out)\n"
    "  status\n"
    "  quit[/dim]"
)


def _parse_spec(arg: str) -> tuple[int, str, int]:
    port_s, host, target_port_s = arg.split(":", 2)
    return int(port_s), host, int(target_port_s)


async def run_repl(app: OperatorApp, console: Console) -> None:
    console.print(_HELP)
    loop = asyncio.get_event_loop()
    while True:
        try:
            line = await loop.run_in_executor(None, sys.stdin.readline)
        except (EOFError, KeyboardInterrupt):
            break
        if not line:
            break
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        cmd = parts[0]
        try:
            if cmd in ("quit", "exit"):
                break
            elif cmd == "status":
                identity = app.agent_identity or {}
                console.print(f"agent: {identity.get('hostname', '?')} ({identity.get('platform', '?')})")
            elif cmd == "forward" and len(parts) >= 3 and parts[1] == "-L":
                lport, thost, tport = _parse_spec(parts[2])
                await app.add_local_forward("127.0.0.1", lport, thost, tport)
            elif cmd == "forward" and len(parts) >= 3 and parts[1] == "-R":
                rport, thost, tport = _parse_spec(parts[2])
                await app.add_remote_forward("0.0.0.0", rport, thost, tport)
            else:
                console.print(f"[red]unknown command: {line!r}[/red]")
        except Exception as exc:
            console.print(f"[red]error: {exc}[/red]")
