# L4Scope — Architecture & Design

Status: reference implementation (v0.1). Audience: engineers deploying or
extending the agent. This document explains the problem framing, the component
model, the cross‑platform strategy, the data path, and the operational and
scaling considerations for running L4Scope across common cloud providers.

## 1. Problem framing (the PM view)

**Who hurts and when.** On‑call engineers and SREs lose hours to failures that
present as "the app is slow / flaky" but are really L4 pathologies: a NAT or LB
resetting connections, a service whose accept queue overflows under load, a
receiver that stops draining its socket (zero window), or a lossy path silently
driving retransmits. Existing tools force a choice: heavyweight packet captures
you analyze *after* the incident (Wireshark), or high‑level metrics that miss the
transport story (RED/latency dashboards).

**What "good" looks like.** A lightweight always‑on agent that (1) runs on every
host/node regardless of OS, (2) needs no application changes, (3) emits a small
set of *named* L4 signals with severity and remediation guidance, and (4) plugs
into existing Prometheus/log pipelines. It must be cheap enough to leave running
in production and safe enough to run in regulated environments (no payload
capture by default, no third‑party network calls).

**Explicit non‑goals.** Not a full IDS/DPI engine, not an APM tracer, not a
pcap archiver. L4Scope is a focused transport‑health sensor. It complements,
rather than replaces, flow logs and tracing.

**Success metrics.** Time‑to‑detect for the covered failure classes; agent CPU
< ~1 core and memory bounded by the flow table at target pps; false‑positive rate
low enough that events are trusted on‑call.

## 2. Component model

L4Scope is four cooperating components wired by the agent process. Each is a
separate crate with a narrow contract, which keeps the detection logic identical
across capture technologies and makes each piece independently testable.

```
        ┌──────────────┐   PacketMeta   ┌───────────────┐   L4Event   ┌──────────────┐
 wire ─▶│  Capture     │ ─────────────▶ │  Detection    │ ──────────▶ │  Export      │─▶ Prometheus
        │  backend     │  (parity ABI)  │  engine       │  (+stats)   │  sinks       │─▶ NDJSON
        └──────────────┘                └───────────────┘             └──────────────┘
              ▲                                 ▲
        l4scope-capture                   l4scope-detect                l4scope-export
                          all orchestrated by  l4scope-agent
```

### 2.1 `l4scope-core` — the contract
Pure types, no I/O. Defines `PacketMeta` (the normalized packet record every
backend must produce), `FlowKey` (direction‑independent flow identity),
`L4Event`, `Severity`, and `Config`. Because it is std‑only and side‑effect free,
it compiles identically on every target and is the single source of truth for the
data model.

### 2.2 `l4scope-capture` — pluggable, parity backends
The `CaptureSource` trait is a pull interface: `next_packet() -> Option<PacketMeta>`.
Backends: `synthetic` (deterministic demo/CI), `pcap_file` (classic pcap replay),
`live` (spawns `tcpdump`/`tshark`/`pktmon` and parses its pcap stream — **zero
FFI**), `ebpf` (Linux CO‑RE, feature‑gated), `etw` (Windows realtime, feature‑
gated). A `parse` module decodes Ethernet/VLAN/SLL/raw → IPv4/IPv6 (incl. a
bounded extension‑header walk) → TCP/UDP into `PacketMeta`. The **parity
contract** is the design's keystone: detectors never see a backend; they see
`PacketMeta`, so any backend gets the full detector suite for free.

### 2.3 `l4scope-detect` — flow state + detector chain
Owns the flow table (`HashMap<FlowKey, FlowState>`) and host‑wide rolling
counters. For each packet the engine runs the state machine **once**, computes a
`PacketDelta` (is‑retransmit, dup‑ack count, zero‑window edge, RTT sample,
handshake transition, new‑flow), then passes an immutable `DetectCtx` to every
`Detector`. Detectors are therefore thin, stateless‑ish rules that translate
deltas + thresholds into events; adding a signal is one `impl Detector`. A
periodic `sweep(now)` handles time‑based conditions (handshake timeouts) and
garbage‑collects idle flows so memory stays bounded.

### 2.4 `l4scope-export` — sinks
A dependency‑free Prometheus text endpoint (`/metrics`, `/healthz`) served from a
tiny std HTTP loop, plus an NDJSON event sink (stdout/stderr/file). The registry
is an `Arc<Mutex<_>>` shared with the pipeline; scrape reads are infrequent and
cheap.

### 2.5 `l4scope-agent` — orchestration
Parses args/config, selects the backend, builds the engine and sinks, and runs
the capture→detect→export loop on the ingest thread while the metrics server runs
on its own thread. Config layering is defaults → file → CLI flags.

## 3. Data path & threading

The hot path is deliberately simple and allocation‑light:

1. **Ingest thread** pulls `PacketMeta` from the backend. For the `live`/`ebpf`
   backends this is where kernel→user handoff happens (a pipe for `live`, a BPF
   ring buffer for `ebpf`).
2. `engine.process(&pkt)` updates flow state and returns `Vec<L4Event>`.
3. Each event is counted in the Prometheus registry and written to the NDJSON
   sink; gauges refresh periodically.
4. **Metrics thread** serves scrapes from the shared registry.

This single‑ingest‑thread model comfortably handles typical host pps. The scaling
path (§6) is RSS/queue fan‑out to N engine shards keyed by `FlowKey` hash, which
preserves per‑flow ordering — the one invariant the state machine needs.

## 4. Cross‑platform strategy

The guiding principle is **one detection engine, many capture backends**, chosen
by config + build features + platform:

- **Linux, production:** `ebpf` (CO‑RE) is the target backend — attach to
  tracepoints / TC / socket hooks, push fixed‑size records into a `BPF_RINGBUF`,
  and decode in userspace. No full‑payload copy, kernel‑side filtering, works on
  any modern kernel via CO‑RE without per‑kernel builds. The compiled BPF object
  is loaded with `aya` in a production build; the userspace record ABI
  (`BpfL4Event`) is defined in `ebpf.rs`.
- **Linux/macOS, no eBPF (older kernels, dev):** `live` spawns `tcpdump -w -` and
  parses its pcap stream. FFI‑free and universally available.
- **Windows:** `etw` consumes `Microsoft‑Windows‑TCPIP` (or drives `pktmon`
  realtime) for a native, Npcap‑free path; interim, `live` drives `tshark`/
  `pktmon`. Same `PacketMeta`, same detectors.
- **Anywhere, offline/forensics/CI:** `pcap_file` and `synthetic`.

Only the backend differs per OS; everything downstream is portable Rust std, so
behavior — and therefore alert semantics — is identical everywhere.

## 5. Deploying across common cloud providers

Packet visibility differs by environment; L4Scope's backend abstraction is what
makes it portable across them.

- **Host / VM (EC2, GCE, Azure VM):** run as a systemd unit (or Windows service)
  with `ebpf`/`etw`, or `live` on the primary ENA/virtio/Hyper‑V NIC. This sees
  the guest's own TCP traffic — the common case for app‑host health.
- **Kubernetes (EKS/GKE/AKS):** run as a **DaemonSet** with `CAP_BPF` +
  `CAP_NET_ADMIN` (or privileged for `live`), `hostNetwork: true` to observe node
  and pod traffic. eBPF at the node level sees all pod flows without a sidecar per
  pod.
- **Out‑of‑band mirroring** (when you cannot run an agent on the workload, e.g.
  managed endpoints or appliances): point a collector VM's `live`/`ebpf` backend
  at a mirror session — **AWS VPC Traffic Mirroring**, **GCP Packet Mirroring**,
  or **Azure Virtual Network TAP**. L4Scope treats the mirrored NIC like any
  other interface.
- **Serverless / managed data stores:** no packet access; use provider flow logs
  as a complementary source (out of scope for the agent, a future ingest adapter).

Operational guardrails for cloud: capture header bytes only (`-s 256`), keep a
tight BPF filter to bound pps, and never emit payloads — L4Scope needs only L4
headers, which also keeps it clear of PII/regulated‑data concerns.

## 6. Scaling & performance

- **Bounded memory:** flow table size is governed by new‑flow rate × `flow_ttl`;
  the sweep evicts idle/closed flows. For hostile SYN‑flood conditions the
  half‑open counters are O(services), not O(flows), and the backlog detector fires
  before the table can be pushed unbounded (pair with a max‑flows cap in a
  hardened build).
- **CPU:** the per‑packet path is a hashmap lookup + a handful of integer ops;
  detectors are branch‑cheap. eBPF pushes filtering into the kernel so userspace
  only sees flows of interest.
- **Horizontal within a host:** shard the engine by `hash(FlowKey) % N` across
  worker threads; each shard owns disjoint flows so there is no lock on the hot
  path. Global signals (RST rate, churn) aggregate shard counters.
- **Fleet scale:** agents are stateless emitters; Prometheus/OTLP and the log
  pipeline do aggregation. No agent‑to‑agent coordination.

## 7. Reliability, security, privacy

- **Least privilege:** `live` needs capture capability; `ebpf` needs `CAP_BPF` +
  `CAP_NET_ADMIN`; drop everything else. No inbound control channel beyond the
  local metrics port (bind to loopback by default).
- **No payloads:** only L4 headers are parsed; the default snap length and the
  header‑only decode mean application data never enters the process.
- **Fail safe:** capture errors end the stream cleanly and the agent exits
  non‑zero (supervisor restarts it); a malformed frame is skipped, never fatal.
- **Supply chain:** zero third‑party crates in the default build shrinks the
  audit surface to std + your BPF/ETW objects when those features are enabled.

## 8. Extensibility

- **New detector:** implement `Detector` and register it in `default_detectors`.
  It receives the precomputed `PacketDelta`, so most rules are a few lines.
- **New backend:** implement `CaptureSource` and add a `Backend` arm — you inherit
  every detector and exporter unchanged.
- **New sink:** OTLP/Kafka/syslog sinks slot in next to the Prometheus and NDJSON
  exporters without touching capture or detection.

## 9. Roadmap

1. Wire the `aya` loader + CO‑RE BPF object (`bpf/l4scope.bpf.c`) for the native
   Linux backend; realtime ETW consumer for Windows.
2. Per‑flow RTT/SRTT from data/ACK timing (beyond the handshake sample);
   RTT/jitter histograms.
3. Max‑flows cap + adaptive sampling under overload; engine sharding.
4. OTLP exporter and a control‑plane heartbeat for fleet inventory (see
   `AGENTS.md`).
5. eBPF‑side aggregation (per‑flow counters in maps) to cut userspace pps.
```
