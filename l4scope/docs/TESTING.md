# Testing L4Scope

## TL;DR

```bash
# Everything (unit + integration + black-box smoke + optional native build):
./scripts/run-tests.sh

# Or just the Rust tests:
cargo test --workspace
```

`run-tests.sh` gates on build + `cargo test` + the demo/pcap smoke tests, and
treats native (eBPF) builds and lint/format as informational.

## What's covered

### Unit tests (in-crate, `cargo test`)

- **l4scope-core**
  - `config`: TOML-subset parsing, type coercion, unknown-key rejection, defaults.
  - `types`: canonical flow-key direction independence, TCP flag decoding, event
    JSON serialization + escaping.
- **l4scope-capture**
  - `synthetic`: the generator yields a SYN-first, multi-flow, zero-window stream.
- **l4scope-detect**
  - `engine`: retransmission, zero-window, handshake timeout (sweep), handshake
    failure (RST), duplicate ACKs, RST storm.
- **l4scope-export**
  - `attribution`: IPv4/IPv6 CIDR matching, pod-IP selection, invalid specs.
  - `metrics`: record/render Prometheus, pod-level series, snapshot.
  - `otlp`: OTLP/JSON body is well-formed (balanced), contains the expected
    metrics/attributes/temporality; `https://` endpoints are rejected.

### Integration tests (`crates/*/tests/`)

- **`l4scope-capture/tests/pcap_replay.rs`** — replays `testdata/sample.pcap`
  through the `pcap_file` backend and asserts packet count and decoded fields
  (SYN first, TCP only, a zero-window packet, a 200-byte segment, port 443).
- **`l4scope-detect/tests/synthetic_e2e.rs`** — the golden pipeline test: drives
  the synthetic traffic through the engine and asserts every major detector fires
  (high RTT, retransmission, duplicate ACK, zero window, RST storm, handshake
  failure, SYN backlog, handshake timeout).

### Black-box smoke tests (`run-tests.sh`)

- `--demo` emits the expected event kinds on stderr.
- `--pcap testdata/sample.pcap` emits retransmission / zero_window / high_rtt.
- **OTLP push**: a one-shot Python HTTP receiver on `:4318` confirms the agent
  POSTs an OTLP/JSON body containing `resourceMetrics` and pod-level series. (The
  agent flushes once on exit, so this is deterministic even for short runs.)

### Native backends

- `run-tests.sh` attempts `cargo build --features ebpf` only on Linux with `clang`
  and `bpf/vmlinux.h` present (see `docs/BUILD_NATIVE.md`); otherwise it's skipped.
  The eBPF/ETW capture paths need a kernel/OS to exercise end-to-end and are not
  part of the portable CI gate.

## Manual / targeted runs

```bash
cargo test -p l4scope-detect                       # one crate
cargo test -p l4scope-detect --test synthetic_e2e  # one integration test
cargo test canonical_key                            # by test name
cargo test -- --nocapture                           # show println! output
```

## Regenerating the pcap fixture

`testdata/sample.pcap` is a tiny hand-built capture (high-RTT handshake →
retransmits → zero window). If you change it, keep the integration-test
assertions in `pcap_replay.rs` in sync.

## CI

`.github/workflows/ci.yml` runs `cargo test --workspace` and `run-tests.sh` on
Linux and macOS for every push/PR, plus an informational fmt/clippy job and a
Docker build check. `.github/workflows/release.yml` builds release binaries
and a GHCR image and publishes a GitHub Release on `vX.Y.Z` tags — see
`.claude/agents/release.md` for the release flow that creates those tags.
