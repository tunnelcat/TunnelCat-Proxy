from __future__ import annotations

import platform
import socket


def local_ips() -> list[str]:
    """Best-effort primary outbound IP.

    Deliberately skips resolving the machine's own hostname via DNS/mDNS.
    On many hosts (notably macOS without reverse DNS configured) that
    blocks for several seconds, which is unacceptable to eat on every
    pairing. UDP "connect" here never actually sends a packet since UDP is
    connectionless. It just asks the kernel's routing table which local
    interface would be used, so this is a fast, local-only operation with
    no network dependency.
    """
    ips = set()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ips.add(s.getsockname()[0])
        s.close()
    except OSError:
        pass
    return sorted(ips)


def describe_self() -> dict:
    return {
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "python_version": platform.python_version(),
        "local_ips": local_ips(),
    }
