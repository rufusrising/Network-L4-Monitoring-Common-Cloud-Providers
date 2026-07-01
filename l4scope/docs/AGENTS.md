# L4Scope — Agent & Fleet Model

L4Scope is an *agent*: an autonomous, always‑on sensor that runs where the packets
are and emits signals. This document describes the single‑agent internals as a set
of cooperating roles, and how agents compose into a fleet.

## The agent as cooperating roles

Within one `l4scope` process there are four logical roles. They map 1:1 to the
crates and communicate through the normalized `PacketMeta`/`L4Event` contracts, so
each can evolve or be replaced without touching the others.

**1. Collector.** Owns the wire. Selects and drives a capture backend
(`ebpf`/`etw`/`live`/`pcap_file`/`synthetic`), does kernel→user handoff, and
normalizes frames into `PacketMeta`. It is the only role that is platform‑aware.
Failure policy: a broken stream is fatal‑to‑the‑stream (agent exits, supervisor
restarts); a broken frame is skipped.

**2. Analyzer.** The stateful brain. Maintains the per‑flow TCP state machine and
host‑wide rolling counters, derives a `PacketDelta` per packet, and runs the
detector chain plus the periodic time‑sweep. This role holds all the memory and
all the domain logic, and is 100% portable.

**3. Reporter.** Fans events and metrics out to the world: NDJSON for logs,
Prometheus for scrapes, `/healthz` for liveness. Stateless apart from counters.

**4. Supervisor (the `agent` binary).** Wires the other three, applies config
(defaults → file → CLI), owns threads and lifecycle, and prints the run summary.

Concurrency: the Collector→Analyzer→Reporter chain runs on one ingest thread; the
Reporter's HTTP endpoint runs on its own thread sharing an `Arc<Mutex<Registry>>`.
The scale‑out design shards the Analyzer by `hash(FlowKey)` so per‑flow ordering
is preserved without hot‑path locks.

## Why an agent (vs. central capture)

Transport pathologies are local — the RST, the full accept queue, the stalled
receiver happen at an endpoint. Running the sensor *on the endpoint* (or on a
node observing its pods) gives ground truth with no mirroring cost, keeps payload
data on the host, and scales linearly: N hosts = N independent emitters, zero
inter‑agent coordination. Central/mirrored capture remains supported via the
`live`/`ebpf` backend pointed at a mirror NIC for cases where you cannot place an
agent on the workload.

## Fleet model

Agents are **stateless emitters**; all aggregation happens in the platforms you
already run.

```
  host/node agents (DaemonSet / systemd / Windows service)
        │  Prometheus scrape          │  NDJSON → log pipeline
        ▼                             ▼
   Prometheus / Thanos          Loki / Elasticsearch
        │                             │
        └────────────► Grafana / alerting ◄───────┘
```

- **Identity & inventory:** each agent is identified by host/node labels applied
  at scrape time (Prometheus `relabel`) or injected into NDJSON by the log
  shipper — no bespoke registry required for v1. A future control‑plane heartbeat
  (roadmap) adds active inventory and config push.
- **Configuration:** ship `config/l4scope.toml` via your existing config
  management (ConfigMap, cloud‑init, GPO). Thresholds are per‑environment; the
  defaults are deliberately conservative.
- **Rollout:** because the binary is a single static file with no runtime deps,
  canary by node pool / availability zone and roll forward on the event‑rate and
  agent‑CPU SLOs.
- **Alerting:** alert on the Prometheus series (e.g. `l4scope_events{severity=
  "critical"}` rate, `l4scope_half_open_max` over threshold) and enrich with the
  NDJSON detail line for the on‑call context.

## Deployment recipes (summary)

- **Linux host:** systemd unit, `ebpf` backend, `CAP_BPF`+`CAP_NET_ADMIN`, metrics
  on loopback scraped by the node exporter sidecar.
- **Kubernetes:** DaemonSet, `hostNetwork: true`, one agent per node observing all
  pod flows; Prometheus `ServiceMonitor` on port 9560.
- **Windows host:** Windows service, `etw` backend, admin token.
- **Out‑of‑band:** collector VM with `live`/`ebpf` on a mirror interface (AWS VPC
  Traffic Mirroring / GCP Packet Mirroring / Azure vTAP).

See `ARCHITECTURE.md` §5–§6 for the cloud and scaling detail.
