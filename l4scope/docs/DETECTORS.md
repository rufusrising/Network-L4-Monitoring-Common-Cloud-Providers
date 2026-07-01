# L4Scope — Detector Reference

Each detector turns per‑packet/flow/host state into a named `L4Event` with a
severity, a numeric value, and a one‑line detail. Thresholds are configurable in
`[detect]` (see `config/l4scope.toml`). This reference explains what each signal
means, what typically causes it, and how to act.

Detection primitives the engine computes once per packet (`PacketDelta`):
retransmit / out‑of‑order (from per‑direction next‑expected sequence),
duplicate‑ACK run length, zero‑window edge, handshake transitions, handshake RTT
sample, RST, and new‑flow — plus host‑wide rolling rates and per‑service
half‑open counts.

| Event | Severity | Trigger (default) | Meaning & likely cause | First actions |
|-------|----------|-------------------|------------------------|---------------|
| `retransmission` | warning | retransmit ratio ≥ `retransmit_ratio_warn` (5%) | Segment sent again → loss or timeout on the path | Check link loss/congestion, NIC drops, path MTU, overloaded next hop |
| `duplicate_ack` | warning | `dup_ack_threshold` (3) dup ACKs in a run | Receiver missing a segment; fast‑retransmit signal | Correlate with `retransmission`; inspect the lossy direction |
| `out_of_order` | info | segment seq ahead of expected (gap) | Reordering or a missing earlier segment | Usually benign in small doses; sustained → multipath/ECMP or loss |
| `zero_window` | warning | window drops to 0 on an established flow | Receiver stopped draining its socket buffer | Slow/blocked application, CPU starvation, GC pause on the receiver |
| `high_rtt` | info/warn | handshake RTT ≥ `rtt_warn_ms` (250 ms); warn ≥ 4× | Slow path or distant/overloaded peer | Check region/AZ placement, path latency, peer load |
| `handshake_failure` | warning | RST during SYN/SYN‑ACK | Connection actively refused | Port closed, LB/target‑group unhealthy, security group/firewall reset |
| `handshake_timeout` | warning | SYN unanswered > `handshake_timeout_secs` (3 s) | SYN dropped, no response | Blackhole route, dropped by NACL/firewall, backend down |
| `syn_backlog` | warning | half‑open to one service ≥ `syn_backlog_threshold` (64) | Accept queue filling → SYN flood or slow accept | Raise `somaxconn`/backlog, scale backend, enable SYN cookies |
| `rst_storm` | critical | host‑wide RST rate ≥ `rst_storm_per_sec` (20/s) | Mass connection resets | Bad LB/NAT, deploy gone wrong, port‑scan/abuse, conntrack exhaustion |
| `connection_churn` | info | new‑flow rate ≥ `churn_per_sec` (200/s) | Connection storm / no pooling | Client not reusing connections, retry storm, thundering herd |

## Notes on semantics

- **Flow identity** is direction‑independent (`FlowKey`), so both halves of a
  conversation update one `FlowState`; retransmit and dup‑ACK are tracked
  per‑direction.
- **Sequence math** uses wrapping (`seq_diff`) so u32 wraparound is handled: a
  segment whose sequence is behind the expected next byte is counted as a
  retransmit; ahead is out‑of‑order.
- **Handshake RTT** is measured SYN→SYN‑ACK. Per‑flow SRTT from data/ACK timing is
  on the roadmap.
- **Host‑wide detectors** (`rst_storm`, `syn_backlog`, `connection_churn`) are
  debounced by `alert_debounce_secs` so a sustained condition emits once per
  window instead of per packet.
- **Half‑open accounting** is O(number of services), not O(flows): each service
  endpoint carries a counter incremented on SYN and decremented on
  establish/reset/close/timeout, which is what makes SYN‑flood detection cheap.

## Tuning guidance

Start from the defaults and adjust per environment. High‑latency inter‑region
links warrant a higher `rtt_warn_ms`; busy front ends legitimately churn
connections, so raise `churn_per_sec` there; latency‑sensitive services may want a
lower `retransmit_ratio_warn`. Keep `alert_debounce_secs` high enough that storms
don't spam on‑call but low enough to reflect recovery.

## Adding a detector

Implement `Detector` (`inspect(&mut self, ctx, pkt) -> Option<L4Event>`), read the
precomputed `ctx.delta` / `ctx.flow()` / `ctx.globals()`, and register it in
`default_detectors`. Because the engine does the stateful work, most detectors are
a threshold check plus an event construction.
