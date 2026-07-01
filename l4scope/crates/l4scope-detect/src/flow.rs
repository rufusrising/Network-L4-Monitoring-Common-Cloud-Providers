//! Per-flow state machine and the packet-level "delta" the engine derives once
//! per packet and hands to every detector. Keeping the stateful bookkeeping here
//! makes the detectors themselves thin and side-effect free.

use std::collections::HashMap;

use l4scope_core::config::DetectConfig;
use l4scope_core::types::{Direction, Endpoint, FlowKey, PacketMeta, Protocol, TcpFlags};

use crate::window::RollingRate;

const NS_PER_SEC: u64 = 1_000_000_000;

/// Coarse TCP connection state (enough to attribute L4 anomalies).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    New,
    SynSent,
    SynAckSeen,
    Established,
    Closing,
    Reset,
}

/// Everything we remember about a single conversation.
#[derive(Debug)]
pub struct FlowState {
    pub proto: Protocol,
    pub state: TcpState,
    pub first_seen_ns: u64,
    pub last_seen_ns: u64,
    pub syn_time_ns: Option<u64>,
    pub synack_time_ns: Option<u64>,
    pub rtt_ns: Option<u64>,
    pub established: bool,
    pub handshake_timeout_flagged: bool,
    pub half_open_counted: bool,
    /// The server endpoint (SYN destination), used for backlog attribution.
    pub service: Endpoint,
    /// Next expected sequence number per direction.
    pub next_seq: [Option<u32>; 2],
    /// Last ACK value seen per direction (for duplicate-ACK detection).
    pub last_ack: [Option<u32>; 2],
    pub dup_ack_count: [u32; 2],
    pub zero_window: [bool; 2],
    pub retransmits: u64,
    pub data_segments: u64,
}

impl FlowState {
    fn new(proto: Protocol, now: u64, service: Endpoint) -> Self {
        FlowState {
            proto,
            state: TcpState::New,
            first_seen_ns: now,
            last_seen_ns: now,
            syn_time_ns: None,
            synack_time_ns: None,
            rtt_ns: None,
            established: false,
            handshake_timeout_flagged: false,
            half_open_counted: false,
            service,
            next_seq: [None, None],
            last_ack: [None, None],
            dup_ack_count: [0, 0],
            zero_window: [false, false],
            retransmits: 0,
            data_segments: 0,
        }
    }

    pub fn retransmit_ratio(&self) -> f64 {
        if self.data_segments == 0 {
            0.0
        } else {
            self.retransmits as f64 / self.data_segments as f64
        }
    }
}

/// What changed on this packet. Detectors read this instead of re-deriving state.
#[derive(Debug, Clone, Copy, Default)]
pub struct PacketDelta {
    pub new_flow: bool,
    pub is_retransmit: bool,
    pub is_out_of_order: bool,
    pub is_dup_ack: bool,
    pub dup_ack_count: u32,
    pub zero_window_edge: bool,
    pub rtt_sample_ns: Option<u64>,
    pub handshake_refused: bool,
    pub established_now: bool,
    pub rst: bool,
    pub service: Option<Endpoint>,
}

/// Host-wide, cross-flow signals.
pub struct Globals {
    pub rst_rate: RollingRate,
    pub new_flow_rate: RollingRate,
    /// Concurrent half-open connections per server endpoint.
    pub half_open: HashMap<Endpoint, u32>,
}

impl Globals {
    fn new() -> Self {
        Globals {
            rst_rate: RollingRate::new(1),
            new_flow_rate: RollingRate::new(1),
            half_open: HashMap::new(),
        }
    }

    pub fn half_open_for(&self, ep: &Endpoint) -> u32 {
        self.half_open.get(ep).copied().unwrap_or(0)
    }

    pub fn half_open_max(&self) -> u32 {
        self.half_open.values().copied().max().unwrap_or(0)
    }
}

/// Owns the flow table, host-wide counters, and thresholds.
pub struct EngineState {
    pub cfg: DetectConfig,
    pub flows: HashMap<FlowKey, FlowState>,
    pub globals: Globals,
}

impl EngineState {
    pub fn new(cfg: DetectConfig) -> Self {
        EngineState { cfg, flows: HashMap::new(), globals: Globals::new() }
    }

    /// Reconstruct the observed (src, dst) endpoints from a canonical packet.
    fn endpoints(pkt: &PacketMeta) -> (Endpoint, Endpoint) {
        match pkt.dir {
            Direction::Forward => (pkt.key.low, pkt.key.high),
            Direction::Reverse => (pkt.key.high, pkt.key.low),
        }
    }

    fn guess_service(pkt: &PacketMeta) -> Endpoint {
        let (src, dst) = Self::endpoints(pkt);
        if pkt.proto == Protocol::Tcp && pkt.flags.is_syn_only() {
            return dst; // definitive: destination of a bare SYN is the server
        }
        if dst.port <= src.port {
            dst
        } else {
            src
        }
    }

    /// Ingest one packet, update state, and return `(flow key, delta)`.
    pub fn update(&mut self, pkt: &PacketMeta) -> (FlowKey, PacketDelta) {
        let key = pkt.key;
        let now = pkt.ts_nanos;
        let mut d = PacketDelta::default();

        if !self.flows.contains_key(&key) {
            let service = Self::guess_service(pkt);
            self.flows.insert(key, FlowState::new(pkt.proto, now, service));
            d.new_flow = true;
            self.globals.new_flow_rate.record(now);
        }

        // `flow` borrows self.flows; below we also touch self.globals — these are
        // disjoint fields, so simultaneous mutable access is allowed.
        let flow = self.flows.get_mut(&key).unwrap();
        flow.last_seen_ns = now;

        if pkt.proto == Protocol::Tcp {
            let di = pkt.dir.index();
            let f: &TcpFlags = &pkt.flags;

            if f.is_syn_only() {
                if flow.syn_time_ns.is_none() {
                    flow.syn_time_ns = Some(now);
                    flow.state = TcpState::SynSent;
                    if !flow.half_open_counted {
                        *self.globals.half_open.entry(flow.service).or_insert(0) += 1;
                        flow.half_open_counted = true;
                    }
                }
                flow.next_seq[di] = Some(pkt.seq.wrapping_add(1));
            } else if f.is_syn_ack() {
                flow.synack_time_ns = Some(now);
                flow.state = TcpState::SynAckSeen;
                if let Some(syn) = flow.syn_time_ns {
                    let rtt = now.saturating_sub(syn);
                    flow.rtt_ns = Some(rtt);
                    d.rtt_sample_ns = Some(rtt);
                }
                flow.next_seq[di] = Some(pkt.seq.wrapping_add(1));
            } else if f.rst() {
                d.rst = true;
                self.globals.rst_rate.record(now);
                if matches!(flow.state, TcpState::SynSent | TcpState::SynAckSeen) {
                    d.handshake_refused = true;
                }
                flow.state = TcpState::Reset;
                clear_half_open(flow, &mut self.globals);
            } else {
                // Established / data / pure-ACK / FIN.
                if matches!(flow.state, TcpState::SynAckSeen) && f.ack() {
                    flow.state = TcpState::Established;
                    flow.established = true;
                    d.established_now = true;
                    clear_half_open(flow, &mut self.globals);
                }
                if f.fin() {
                    flow.state = TcpState::Closing;
                    clear_half_open(flow, &mut self.globals);
                }

                // Zero-window edge (receiver stall) on an active connection.
                if flow.established || matches!(flow.state, TcpState::Closing) {
                    let was_zero = flow.zero_window[di];
                    let now_zero = pkt.window == 0;
                    if now_zero && !was_zero {
                        d.zero_window_edge = true;
                    }
                    flow.zero_window[di] = now_zero;
                }

                // Retransmission / out-of-order for data-bearing segments.
                if pkt.payload_len > 0 {
                    flow.data_segments += 1;
                    let end = pkt.seq.wrapping_add(pkt.payload_len);
                    match flow.next_seq[di] {
                        Some(exp) => {
                            let diff = seq_diff(pkt.seq, exp);
                            if diff < 0 {
                                d.is_retransmit = true;
                                flow.retransmits += 1;
                            } else if diff > 0 {
                                d.is_out_of_order = true;
                            }
                            if seq_diff(end, exp) > 0 {
                                flow.next_seq[di] = Some(end);
                            }
                        }
                        None => flow.next_seq[di] = Some(end),
                    }
                }

                // Duplicate-ACK detection (bare ACK, no new data).
                if f.ack() && pkt.payload_len == 0 && !f.syn() && !f.fin() {
                    match flow.last_ack[di] {
                        Some(prev) if prev == pkt.ack => {
                            flow.dup_ack_count[di] += 1;
                            d.is_dup_ack = true;
                            d.dup_ack_count = flow.dup_ack_count[di];
                        }
                        _ => {
                            flow.last_ack[di] = Some(pkt.ack);
                            flow.dup_ack_count[di] = 0;
                        }
                    }
                }
            }
        }

        d.service = Some(flow.service);
        (key, d)
    }
}

/// Signed distance `a - expected` under u32 sequence-number wraparound.
#[inline]
pub fn seq_diff(a: u32, expected: u32) -> i32 {
    a.wrapping_sub(expected) as i32
}

fn clear_half_open(flow: &mut FlowState, globals: &mut Globals) {
    if flow.half_open_counted {
        flow.half_open_counted = false;
        if let Some(c) = globals.half_open.get_mut(&flow.service) {
            *c = c.saturating_sub(1);
        }
    }
}

/// Convenience: nanoseconds -> seconds as f64.
pub fn ns_to_secs_f64(ns: u64) -> f64 {
    ns as f64 / NS_PER_SEC as f64
}
