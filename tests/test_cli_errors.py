"""Regression tests for the friendly-error-message layer: parsing
functions should raise ValueError with a message naming the actual
problem, and CLI commands should turn those (and other expected runtime
failures) into a clean one-line message and exit code 1 instead of a raw
traceback.
"""

from __future__ import annotations

import pytest
from click.testing import CliRunner

from tunnelcat.cli import main as cli_main
from tunnelcat.common import link as linkmod
from tunnelcat.crypto import pairing
from tunnelcat.relay.chain import parse_chain_spec


# -- parse_chain_spec ---------------------------------------------------


def test_parse_chain_spec_rejects_missing_parts():
    with pytest.raises(ValueError, match="expected host:port:token"):
        parse_chain_spec("not-a-valid-spec")


def test_parse_chain_spec_rejects_non_numeric_port():
    with pytest.raises(ValueError, match="invalid port"):
        parse_chain_spec("host:notaport:token")


def test_parse_chain_spec_rejects_empty_chain():
    with pytest.raises(ValueError, match="empty relay chain"):
        parse_chain_spec("")


def test_parse_chain_spec_accepts_valid_multi_hop():
    hops = parse_chain_spec("relay1.example.com:8443:tokA,relay2.example.com:8443:tokB")
    assert len(hops) == 2
    assert hops[0].host == "relay1.example.com" and hops[0].port == 8443 and hops[0].token == "tokA"
    assert hops[1].host == "relay2.example.com" and hops[1].port == 8443 and hops[1].token == "tokB"


# -- tnl:// link decoding -------------------------------------------------


def test_link_decode_rejects_missing_prefix():
    with pytest.raises(ValueError, match="not a tnl://"):
        linkmod.decode("not-a-link-at-all")


def test_link_decode_rejects_garbage_payload():
    with pytest.raises(ValueError, match="malformed tnl://"):
        linkmod.decode("tnl://garbage!!!")


def test_link_decode_roundtrip_still_works():
    link = linkmod.encode_direct("10.0.0.5", 8443, "SOME-CODE")
    payload = linkmod.decode(link)
    assert payload == {"mode": "direct", "host": "10.0.0.5", "port": 8443, "code": "SOME-CODE"}


# -- pairing code parsing -------------------------------------------------


def test_code_to_bytes_rejects_malformed_code():
    with pytest.raises(ValueError, match="invalid pairing code"):
        pairing.code_to_bytes("!!!not-base32!!!")


def test_code_to_bytes_accepts_generated_code():
    code = pairing.generate_pairing_code()
    assert len(pairing.code_to_bytes(code)) == pairing.CODE_BYTES


# -- CLI-level: errors surface as clean messages, not tracebacks --------


def test_cli_rejects_bad_relay_chain_cleanly():
    runner = CliRunner()
    result = runner.invoke(cli_main, ["agent", "relay", "--chain", "garbage", "--code", "AAAA-BBBB"])
    assert result.exit_code != 0
    assert "Traceback" not in result.output
    assert "Error:" in result.output


def test_cli_rejects_bad_link_cleanly():
    runner = CliRunner()
    result = runner.invoke(cli_main, ["agent", "join", "tnl://garbage!!!"])
    assert result.exit_code != 0
    assert "Traceback" not in result.output
    assert "Error:" in result.output


def test_cli_connection_refused_is_clean():
    runner = CliRunner()
    # Port 1 is a privileged port nothing will be listening on as this user.
    result = runner.invoke(cli_main, ["agent", "connect", "127.0.0.1", "1", "--code", "AAAA-BBBB"])
    assert result.exit_code != 0
    assert "Traceback" not in result.output
    assert "Error:" in result.output


@pytest.mark.parametrize(
    "args",
    [
        ["--help"],
        ["operator", "--help"],
        ["operator", "listen", "--help"],
        ["operator", "connect", "--help"],
        ["operator", "pair", "--help"],
        ["agent", "--help"],
        ["agent", "connect", "--help"],
        ["agent", "listen", "--help"],
        ["agent", "relay", "--help"],
        ["agent", "join", "--help"],
        ["relay", "--help"],
        ["relay", "serve", "--help"],
    ],
)
def test_cli_help_does_not_crash(args):
    runner = CliRunner()
    result = runner.invoke(cli_main, args)
    assert result.exit_code == 0, f"{args} failed: {result.output}"
    assert "Traceback" not in result.output
    assert "Usage:" in result.output
