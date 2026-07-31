from __future__ import annotations

from rich.console import Console

_STYLE_BY_STATUS = {
    "connected": "yellow",
    "waiting_for_peer": "yellow",
    "matched": "green",
    "failed": "red",
    "error": "red",
}


def simple_on_event(console: Console):
    def handler(event: str, **kw):
        if event == "listening":
            console.print(f"[cyan]Listening on {kw['host']}:{kw['port']}, waiting for operator...[/cyan]")
        elif event == "handshaking":
            console.print("[yellow]Transport connected — running E2E handshake...[/yellow]")
        elif event == "relay_hop":
            style = _STYLE_BY_STATUS.get(kw["status"], "white")
            line = f"[{style}]{kw['hop']} — {kw['status']}[/{style}]"
            if kw.get("detail"):
                line += f" [dim]({kw['detail']})[/dim]"
            console.print(line)
        elif event == "paired":
            console.print("[green]Paired — end-to-end encrypted session established.[/green]")
        elif event == "connect_out":
            ok = kw["success"]
            color = "green" if ok else "red"
            console.print(f"[{color}]connect-out {kw['host']}:{kw['port']} — {'ok' if ok else 'failed'}[/{color}]")

    return handler
