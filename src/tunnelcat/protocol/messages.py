"""Wire schemas for the E2E-encrypted control channel (mux channel 0) and
for the metadata carried on OPEN frames when a data channel is opened.

Everything here travels only after the Noise handshake has succeeded, so
it is authenticated and confidential between operator and agent. Relays
never see any of it.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import msgpack


def pack(obj) -> bytes:
    return msgpack.packb(obj, use_bin_type=True)


def unpack(data: bytes):
    return msgpack.unpackb(data, raw=False)


# -- data-channel OPEN metadata -----------------------------------------
# Used both for SOCKS5 CONNECT targets and for -L local port forwards:
# the opener (usually the operator) says "connect me to host:port"; the
# acceptor (usually the agent) does the real connect()/DNS resolution.


def connect_target(host: str, port: int) -> bytes:
    return pack({"host": host, "port": port})


def parse_connect_target(metadata: bytes) -> tuple[str, int]:
    d = unpack(metadata)
    return d["host"], d["port"]


# -- control-channel messages --------------------------------------------

MSG_HELLO = "hello"
MSG_START_REMOTE_FORWARD = "start_remote_forward"
MSG_REMOTE_FORWARD_STARTED = "remote_forward_started"
MSG_REMOTE_FORWARD_FAILED = "remote_forward_failed"


@dataclass
class Hello:
    hostname: str
    platform: str
    python_version: str
    local_ips: list[str] = field(default_factory=list)

    def to_bytes(self) -> bytes:
        return pack(
            {
                "type": MSG_HELLO,
                "hostname": self.hostname,
                "platform": self.platform,
                "python_version": self.python_version,
                "local_ips": self.local_ips,
            }
        )


def start_remote_forward(request_id: str, listen_host: str, listen_port: int, target_host: str, target_port: int) -> bytes:
    return pack(
        {
            "type": MSG_START_REMOTE_FORWARD,
            "request_id": request_id,
            "listen_host": listen_host,
            "listen_port": listen_port,
            "target_host": target_host,
            "target_port": target_port,
        }
    )


def remote_forward_started(request_id: str, bound_port: int) -> bytes:
    return pack({"type": MSG_REMOTE_FORWARD_STARTED, "request_id": request_id, "bound_port": bound_port})


def remote_forward_failed(request_id: str, reason: str) -> bytes:
    return pack({"type": MSG_REMOTE_FORWARD_FAILED, "request_id": request_id, "reason": reason})
