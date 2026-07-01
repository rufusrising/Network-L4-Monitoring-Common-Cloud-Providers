# L4Scope

A cross-platform **Layer‑4 (TCP/UDP) network health agent**. L4Scope watches live
traffic — via `tcpdump`/`tshark`, native **eBPF** (Linux), or **ETW/pktmon**
(Windows) — reconstructs per‑flow TCP state, and flags the L4 problems that
actually page you: retransmissions, RST storms, SYN‑backlog exhaustion,
zero‑window stalls, handshake failures/timeouts, high RTT, out‑of‑order delivery,
and connection churn.

It is written in Rust, ships as a single static binary, and has **zero external
crate dependencies** (std only) so it builds offline and drops cleanly into a
distroless container or a locked‑down host.

```
capture backend ──▶ normalized PacketMeta ──▶ detection engine ──▶ events + metrics
 (pcap/eBPF/ETW)      (parity contract)         (flow state machine)   (NDJSON + Prometheus)
```

## Why it exists

L3 ping/latency tells you a path is up; it does not tell you *why* an application
is slow or failing. The interesting failures live at L4: a load balancer sending
RSTs, an accept queue overflowing, a receiver that stopped draining its socket,
lossy paths driving retransmits. L4Scope turns raw packets into **named,
actionable signals** with thresholds, severities, and remediation hints — the
same output regardless of OS or capture technology.

## Quickstart

No privileges, no setup — run the built‑in synthetic traffic that trips every
detector:

```bash
cargo run -p l4scope-agent -- --demo
```

Replay a pcap file:

```bash
cargo run -p l4scope-agent -- --pcap testdata/sample.pcap
```

Live capture (needs capture privileges and `tcpdump`/`tshark` on PATH):

```bash
sudo cargo run -p l4scope-agent -- --backend live --iface eth0
# then scrape metrics:
curl -s localhost:9560/metrics
```

Full config file:

```bash
cargo run -p l4scope-agent -- --config config/l4scope.toml
```

## Build & test

```bash
cargo build --release          # default build: all platforms, std only
cargo test                     # engine unit tests
cargo build --features ebpf    # opt-in native eBPF backend (Linux) — see docs/BUILD_NATIVE.md
```

The release binary is `target/release/l4scope`. For the production eBPF path
(no tcpdump/libpcap) and the Windows options, see **`docs/BUILD_NATIVE.md`**.

## Capture backends (pluggable, parity)

| Backend      | Platform        | Privilege                | Notes |
|--------------|-----------------|--------------------------|-------|
| `synthetic`  | all             | none                     | Deterministic demo/CI input |
| `pcap_file`  | all             | file read                | Replays classic `.pcap` |
| `live`       | Linux/macOS/Win | capture cap / admin      | Spawns `tcpdump`/`tshark`, no FFI |
| `ebpf`       | Linux           | `CAP_BPF`+`CAP_NET_ADMIN`| CO‑RE, lowest overhead (feature `ebpf`) |
| `etw`        | Windows         | admin                    | ETW `Microsoft‑Windows‑TCPIP`/pktmon (feature `etw`) |

Every backend emits the same `PacketMeta`, so **all detectors work identically**
on all backends. Adding a backend gives you the whole detector suite for free.

## Outputs

- **OpenTelemetry (OTLP/HTTP + JSON)** push to any OTel Collector — node- and
  pod-level metrics for AKS/GKE/EKS and VMs. Dependency-free exporter; the
  Collector handles cloud export/TLS. See **`docs/OTEL.md`** and
  `deploy/otel/`.
- **Prometheus** `/metrics` and `/healthz` on `127.0.0.1:9560` (configurable):
  `l4scope_events{kind,severity}`, `l4scope_pod_events{pod_ip,kind,severity}`,
  `l4scope_active_flows`, `l4scope_half_open_max`, `l4scope_rst_per_second`,
  `l4scope_new_flows_per_second`, `l4scope_packets_total`.
- **NDJSON events** to stdout/stderr/file: one JSON object per anomaly, ready for
  Loki/Elasticsearch.

## Layout

```
crates/
  l4scope-core      # data model, config, errors  (no I/O)
  l4scope-capture   # Capture trait + backends (pcap/live/ebpf/etw)
  l4scope-detect    # flow state machine + detector chain + engine
  l4scope-export    # Prometheus endpoint + NDJSON sink
  l4scope-agent     # the `l4scope` daemon binary
docs/               # architecture, agent model, detector reference
config/             # sample TOML
testdata/           # sample.pcap
```

See `docs/ARCHITECTURE.md` for the full design, `docs/AGENTS.md` for the
agent/fleet model, and `docs/DETECTORS.md` for what each signal means and how to
act on it.
