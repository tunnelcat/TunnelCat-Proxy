"""Turns expected runtime failures into a short, actionable message
instead of a raw traceback. Anything not explicitly listed here still
surfaces as a full traceback, since a misleading catch-all is worse than
an ugly one.

Apply @handle_errors directly above `def` on a click command callback, as
the innermost decorator, so click's own @click.option/@click.argument
decorators still see a plain function to attach their parameters to.
"""

from __future__ import annotations

import asyncio
import functools

import click

from ..crypto.noise import HandshakeFailed
from ..relay.chain import RelayError


def handle_errors(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except click.ClickException:
            raise
        except KeyboardInterrupt:
            click.echo("\nInterrupted.")
            raise SystemExit(130) from None
        except ValueError as exc:
            # Covers malformed --relay-chain/--chain specs, malformed
            # tnl:// links, and malformed pairing codes (binascii.Error,
            # raised on bad base32 input, is itself a ValueError subclass).
            raise click.ClickException(str(exc)) from exc
        except HandshakeFailed as exc:
            raise click.ClickException(
                "handshake failed, check that the pairing code matches on both sides"
            ) from exc
        except RelayError as exc:
            raise click.ClickException(f"relay rejected the connection: {exc}") from exc
        except ConnectionRefusedError as exc:
            raise click.ClickException(f"connection refused: {exc}") from exc
        except asyncio.TimeoutError:
            raise click.ClickException("timed out waiting for the peer") from None
        except OSError as exc:
            raise click.ClickException(f"network error: {exc}") from exc

    return wrapper
