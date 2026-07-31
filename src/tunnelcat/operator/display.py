"""Live CLI view of the connection path as it forms: operator -> relay1 ->
relay2 -> ... -> agent, one line per hop, updated in place as each one
connects. Always clear exactly what's in the path and whether it's still
connecting, waiting, or fully matched end-to-end.
"""

from __future__ import annotations

from rich.console import Console
from rich.live import Live
from rich.tree import Tree

_STYLE_BY_STATUS = {
    "connected": "yellow",
    "waiting_for_peer": "yellow",
    "matched": "green",
    "failed": "red",
    "error": "red",
}


class ChainDisplay:
    def __init__(self, console: Console | None = None):
        self.console = console or Console()
        self._root: Tree | None = None
        self._live: Live | None = None
        self._nodes: dict[str, "Tree"] = {}

    def start(self, title: str) -> None:
        self._root = Tree(f"[bold]{title}[/bold]")
        self._live = Live(self._root, console=self.console, refresh_per_second=8)
        self._live.start()

    def stop(self) -> None:
        if self._live:
            self._live.stop()
            self._live = None

    def _set(self, key: str, label: str) -> None:
        if self._root is None:
            return
        if key in self._nodes:
            self._nodes[key].label = label
        else:
            node = self._root.add(label)
            self._nodes[key] = node

    def on_event(self, event: str, **kw) -> None:
        if event == "pairing_code":
            self.console.print(f"[cyan]Pairing code:[/cyan]  {kw['code']}")
        elif event == "listening":
            self.console.print(f"[cyan]Listening on {kw['host']}:{kw['port']}, waiting for peer...[/cyan]")
        elif event == "handshaking":
            self._set("_handshake", "[yellow]transport connected — running E2E handshake...[/yellow]")
        elif event == "relay_hop":
            hop, status, detail = kw["hop"], kw["status"], kw.get("detail", "")
            style = _STYLE_BY_STATUS.get(status, "white")
            label = f"[{style}]{hop} — {status}[/{style}]"
            if detail:
                label += f" [dim]({detail})[/dim]"
            self._set(hop, label)
        elif event == "paired":
            self._set("_e2e", "[green]end-to-end encrypted session established (Noise handshake verified)[/green]")
        elif event == "agent_hello":
            label = f"[bold green]agent: {kw.get('hostname')} — {kw.get('platform')}[/bold green]"
            ips = kw.get("local_ips") or []
            if ips:
                label += f"  [dim]({', '.join(ips)})[/dim]"
            self._set("_agent", label)
            self.stop()
        elif event == "socks_started":
            self.console.print(f"[green]SOCKS5 proxy listening on {kw['host']}:{kw['port']}[/green]")
        elif event == "socks_connect":
            ok = kw["success"]
            color = "green" if ok else "red"
            verb = "connected" if ok else "FAILED"
            self.console.print(f"[{color}]SOCKS  {kw['host']}:{kw['port']} — {verb}[/{color}]")
        elif event == "local_forward_started":
            self.console.print(
                f"[green]-L {kw['host']}:{kw['port']} -> {kw['target_host']}:{kw['target_port']} (via agent)[/green]"
            )
        elif event == "remote_forward_started":
            self.console.print(
                f"[green]-R agent:{kw['port']} -> {kw['target_host']}:{kw['target_port']} (via operator)[/green]"
            )
        elif event == "remote_forward_connect":
            ok = kw["success"]
            color = "green" if ok else "red"
            self.console.print(f"[{color}]-R connect {kw['host']}:{kw['port']}[/{color}]")
