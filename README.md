# TunnelCat

E2E-encrypted, paired SOCKS5 / port-forward tunneling for authorized pentest
pivoting. Pair an **agent** (runs on a machine with network access you need,
e.g. a foothold or an AWS WorkSpace with egress-only internet) with an
**operator** (your machine, e.g. running Burp), and get a local SOCKS5 proxy
that pivots traffic through the agent, including remote DNS resolution.

Everything between operator and agent is encrypted end-to-end with a
Noise-based handshake authenticated by a one-time pairing code. Optional
**relays** let you bridge two machines that can't reach each other directly
(the common case: neither your laptop nor the target box has a public IP).
Relays are blind rendezvous/splice points and can never decrypt tunnel
traffic, even chained across multiple hops.

## Install

```
python3 -m venv .venv && .venv/bin/pip install -e .
```

Requires Python 3.11+.

### Deploying the agent to a target (no pip/venv on the target)

For the machine you're pivoting through, you usually don't want to (or
can't) `pip install` anything. `scripts/build-agent-bundle.sh` packs
`tunnelcat` and all its dependencies into a single self-contained
`tunnelcat.pyz` file using [shiv](https://github.com/linkedin/shiv):

```
pip install shiv                      # build machine only
scripts/build-agent-bundle.sh         # -> dist/tunnelcat.pyz (linux x86_64, py3.11 by default)
scp dist/tunnelcat.pyz target-host:/tmp/tc
ssh target-host '/tmp/tc agent join <link-from-operator>'
```

The target needs nothing but a matching `python3` already on it — no pip,
no venv, no internet access, no build tooling. First invocation
self-extracts to `~/.shiv/` and caches there; later runs skip that step.

The bundle is built for a specific platform/Python ABI (`cryptography` and
`msgpack` ship compiled extensions, so this isn't purely cross-platform).
Check the target first with `python3 --version; uname -m`, then pass the
matching platform/version if it's not linux x86_64 / Python 3.11, e.g.:

```
scripts/build-agent-bundle.sh manylinux2014_aarch64 311   # linux arm64, py3.11
scripts/build-agent-bundle.sh manylinux2014_x86_64  312   # linux x86_64, py3.12
```

## Architecture

- **crypto/**: Noise_NNpsk0-inspired handshake (X25519 + ChaCha20-Poly1305
  + HKDF-SHA256) and the AEAD frame transport built on it. Pairing code ->
  independent `psk` (handshake) and `session_id` (relay matching) via HKDF,
  so a relay never learns anything that helps decrypt tunnel traffic.
- **mux/**: channel multiplexer over the encrypted stream. Channel 0 is a
  control RPC channel, every proxied connection gets its own channel.
- **relay/**: rendezvous + blind byte-splice server, with support for
  chaining relays (each hop announces itself back up the chain, which is
  what powers the live CLI visualization).
- **operator/** / **agent/**: the two ends. SOCKS5 server + port forwards
  on the operator side, connect-out execution on the agent side.

See inline module docstrings for the protocol details.

## Usage

Every group and subcommand has its own `--help` with worked examples:
`tunnelcat --help`, `tunnelcat operator --help`, `tunnelcat operator pair
--help`, and so on. That's the source of truth for exact flags; this table
is a quick-reference summary.

Common mistakes (a malformed `--relay-chain`/`--chain` spec, a bad
`tnl://` link, a mistyped pairing code, a connection that gets refused, a
relay rejecting the token) print a one-line `Error: ...` message instead
of a Python traceback.

**`tunnelcat operator ...`**, run on your machine:

| Command | When to use | Notable options |
|---|---|---|
| `listen --port PORT` | the agent can reach you | `--bind`, `--advertise-host`, `--code`, `--socks-host`, `--socks-port` |
| `connect HOST PORT --code CODE` | you can reach the agent | `--socks-host`, `--socks-port` |
| `pair --relay-chain SPEC` | neither can reach the other | `--agent-hop`, `--code`, `--socks-host`, `--socks-port` |

`--socks-host`/`--socks-port` default to `127.0.0.1:1080`. `--code` is
optional on `listen`/`pair` (a new one is generated and printed if you
don't pass one) and required on `connect`, since there you're supplying
the code the agent already printed.

**`tunnelcat agent ...`**, run on the machine you're pivoting through:

| Command | When to use | Notable options |
|---|---|---|
| `connect HOST PORT --code CODE` | the operator is listening | |
| `listen --port PORT --code CODE` | the operator can reach you | `--bind` |
| `relay --chain SPEC --code CODE` | through a relay | |
| `join LINK` | paste the operator's printed one-liner | picks the right mode automatically |

**`tunnelcat relay serve --port PORT --token TOKEN`** runs a
rendezvous/splice relay. `--allow-next HOST:PORT` (repeatable) is required
before this relay will forward anywhere; `--default-next HOST:PORT` hides
a fixed chain behind this relay as the front door; `--label`,
`--session-timeout`, and `-v/--verbose` round out the rest.

Once paired, the operator drops into an interactive REPL:
```
forward -L <local_port>:<target_host>:<target_port>   # local port -> agent connects out
forward -R <remote_port>:<target_host>:<target_port>  # agent's port -> operator connects out
status
quit
```

## Quickstart: direct pairing (same network / reachable IP)

Operator (your machine, e.g. reachable from the target):
```
tunnelcat operator listen --port 8443
```
Prints a pairing code and a ready `tunnelcat agent join <link>` one-liner.

Agent (target machine):
```
tunnelcat agent join tnl://...
```

Once paired, the operator has a SOCKS5 proxy on `127.0.0.1:1080` (point
Burp at it) and a REPL for forwards:
```
forward -L 3389:internal-host:3389     # local port -> agent connects out
forward -R 9000:my-internal-service:80 # agent's port -> operator connects out
status
quit
```

If the agent has the reachable address instead, flip it:
```
agent$   tunnelcat agent listen --port 8443
operator$ tunnelcat operator connect <agent-ip> 8443 --code <code>
```

## Through a relay (neither side reachable to the other)

```
relay-vps$ tunnelcat relay serve --port 8443 --token $TOKEN

workstation$ tunnelcat operator pair --relay-chain relay.example.com:8443:$TOKEN
# prints pairing code + agent one-liner

target$ tunnelcat agent join tnl://...
```

## Chained relays

```
relay1$ tunnelcat relay serve --port 8443 --token tokA --allow-next relay2.example.com:8443
relay2$ tunnelcat relay serve --port 8443 --token tokB

workstation$ tunnelcat operator pair \
  --relay-chain relay1.example.com:8443:tokA,relay2.example.com:8443:tokB
```
The agent only needs to reach whichever relay is the terminal hop (usually
the last one). It doesn't need to know the rest of the chain exists.

A relay configured with `--default-next` silently forwards everything to a
fixed next hop, hiding the chain topology from clients entirely: they only
ever address the front door. Use the same `--token` across a hidden static
chain, since clients won't know the hidden hops' individual tokens.

While pairing, the operator's terminal shows every hop lighting up live as
the chain forms, ending with the agent's authenticated identity (hostname,
platform, IP) once the E2E handshake completes:
```
operator -> relay1:8443 -> relay2:8443 -> agent
├── relay1:8443 — connected
├── relay2:8443 — waiting_for_peer
├── peer — matched
├── transport connected — running E2E handshake...
├── end-to-end encrypted session established (Noise handshake verified)
└── agent: workspace-01 — Linux ... (10.0.4.12)
```

## Security notes / known limitations

- The Noise implementation here is hand-rolled (following the published
  Noise_NNpsk0 pattern) rather than a vetted library. Get it reviewed
  before relying on it for a real engagement.
- Relays require their own token to REGISTER or HOP through them, and a
  `--allow-next` allowlist to forward anywhere. Without it, forwarding is
  refused, so a leaked token can't turn a relay into an open proxy to the
  internet.
- Intermediate relays in an explicit chain don't currently rate-limit
  distinct sessions from a single caller. Fine for infra you control for
  an engagement, worth hardening before exposing a relay more broadly.
- SOCKS5 server is no-auth; bind it to `127.0.0.1` (the default) unless you
  add your own access control in front of it.
- A channel whose consumer stalls badly (e.g. a client that stops reading
  entirely) is abandoned after ~32MB of unconsumed backlog rather than
  blocking every other concurrent connection sharing the session. This is
  by design, so one bad connection can't freeze the rest of a Burp session.

## Tests

```
.venv/bin/pytest tests/ -q
```
Covers the crypto handshake (including its concurrency safety: nonce
assignment and wire order can't diverge under many simultaneous channels
writing at once), the multiplexer (including head-of-line-blocking and
half-close/backpressure regressions), relay session matching and chaining
(including the abuse-prevention allowlist and duplicate-registration
rejection), and full end-to-end flows over real sockets: SOCKS5 through a
direct pairing and through a two-hop relay chain, `-L`/`-R` forwards,
large/streaming transfers, and many concurrent SOCKS connections sharing
one session without cross-talk. `pytest-timeout` caps every test at 25s so
a regression shows up as a fast failure, not a hang.
