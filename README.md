# lend

A small CLI for temporarily sharing local TCP and UDP services over encrypted peer-to-peer tunnels.

`lend` is for when you want to share something running on your machine with another machine or network without setting up port-forwarding, standing up a reverse proxy, or signing up for a managed tunnel service.

Good fits include:

- game servers
- local dev servers
- demos
- admin panels
- other private TCP or UDP services you want to be reachable from another machine or network

## Why lend?

- No port-forwarding required.
- No account, server setup, dashboard, or public URL. Just two CLI commands.
- End-to-end encrypted transport over QUIC.
- Copy-paste token workflow.
- Built for short-lived sharing, not permanent exposure.

## Quick Start

Install `lend`:

```bash
cargo install lend
```

On the machine that already has access to the service:

```bash
lend share tcp 127.0.0.1:3000
```

This prints a token like:

```text
lend_...
```

On the other machine:

```bash
lend use tcp 127.0.0.1:8000 lend_...
```

Traffic sent to `127.0.0.1:8000` on the second machine is then forwarded to `127.0.0.1:3000` on the first.

## CLI

```text
lend share <PROTOCOL> <SERVICE>
lend use <PROTOCOL> <BIND> <TOKEN>
```

## How It Works

- `share` creates an `iroh` endpoint and prints a connection token.
- `use` connects to the sharing peer using that token.
- `iroh` handles direct peer-to-peer connectivity with hole punching when possible and relay fallback when needed.
- `use` authenticates once per peer connection using a random secret embedded in the token.
- In `tcp` mode, each inbound TCP connection on `use` opens a QUIC bidirectional stream over `iroh`.
- In `udp` mode, `lend` forwards best-effort QUIC datagrams and keeps UDP routing isolated per peer connection on the sharing side.

## Tokens

- Tokens are shell-safe ASCII strings prefixed with `lend_`.
- Tokens encode peer address information, protocol information, and a random secret in a compact binary format.
- Tokens are temporary. If the sharing side stops or restarts, old tokens will be treated as invalid.
- Possession of the token is enough to connect, so treat it as sensitive.

## Security Model

- Traffic is end-to-end encrypted over QUIC via `iroh`.
- Access is controlled by possession of the token, which includes a random secret verified once per peer connection in constant-time.
- `lend` does not add user identity, policy enforcement, or fine-grained authorization on top of that bearer-token model.

## Logging

Runtime output uses `tracing` and respects `RUST_LOG`.

- The token is printed by itself on `stdout`, which makes it easy to pipe, capture, or script.
- Human-facing logs go to `stderr`.

Examples:

```bash
RUST_LOG=info lend share tcp 127.0.0.1:3000
RUST_LOG=debug lend use tcp 127.0.0.1:8000 lend_...
```

## Limitations

- Designed for temporary sharing, not long-lived managed tunnels.
- UDP forwarding is best-effort; oversized datagrams may be dropped.
- If the sharing peer exits or restarts, existing and future forwarded connections fail until a new token is generated. This is by design.
- Access is controlled entirely by possession of the token.
- Not intended to be a hardened public exposure layer.

## Testing

Run the full test suite with:

```bash
cargo test
```

Current coverage includes:

- half-close and EOF propagation
- end-to-end UDP datagram forwarding through the real `lend` binary
- token round-tripping
- tampered token rejection
- end-to-end HTTP forwarding through the real `lend` binary
- peer shutdown causing `use` to exit on the next attempted use

The integration tests start local TCP and UDP services, run `lend share` and `lend use` as child processes, capture the emitted token, and verify that traffic crosses the full tunnel correctly.

## Roadmap

- Additional integration coverage for failure modes and protocol-specific behavior
- UDP fragmentation and reassembly for oversized datagrams if real-world use shows a need

## Licensing

This project is available under either the MIT License or Apache 2.0, at your option.
