# ipstack 1.0.1 TCP flow-control fix

Vendored from the crates.io `ipstack` 1.0.1 source archive, SHA-256
`e889a45c1ce3e97268ad2249951528563ec1d02a120fecbd4db690beac34f7fd`.
Upstream: https://github.com/narrowlink/ipstack (Apache-2.0; LICENSE retained).
The parent Cargo.toml uses this relative path so every Windows build includes
the fix without modifying a developer's Cargo registry cache.

Functional changes are confined to `src/stream/tcb.rs` and `src/stream/tcp.rs`.
The upstream README heading and trailing whitespace in documentation comments
are normalized for Git whitespace checks.

- New data fits the remaining advertised receive window and unacknowledged-byte
  limit, including when TCP sequence numbers wrap.
- Retransmissions reuse their original sequence space and respect the current
  receive-window right edge; a full window does not suppress them.
- The session loop checks retransmission deadlines independently of incoming
  packets. It retains exponential backoff and stops its timer with the session.
- A zero receive window sends periodic empty ACK probes without consuming the
  packet-loss retry budget. A lost window update must not deadlock a flow.
- Exhausted retransmissions reset and terminate the session, wake pending I/O,
  and retain unacknowledged data until termination instead of silently dropping
  bytes from the TCP stream.
- Empty writes return zero without creating an empty in-flight packet.

Validation from the tun2proxy directory:

```text
cargo test --offline --manifest-path vendor/ipstack/Cargo.toml --lib
cargo test --offline --locked --lib
cargo build --offline --locked --release --lib
```

The receiver-window and idle-retransmission regression tests both fail on a
separate copy of unmodified ipstack 1.0.1. The live Windows VM reproduction and
before/after download measurements are documented in the application repository
at `docs/windows-http-vpn-verification-20261107.md`.
