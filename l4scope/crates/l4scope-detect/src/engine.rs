//! The detection engine: owns flow state + the detector chain, ingests packets,
//! and periodically sweeps for time-based conditions (handshake timeouts) and
//! garbage-collects idle flows.

use l4scope_core::config::DetectConfig;
use l4scope_core::types::{EventKind, L4Event, PacketMeta, Severity};

use crate::detectors::{default_detectors, DetectCtx, Detector};
use crate::flow::{EngineState, TcpState};

const NS_PER_SEC: u64 = 1_000_000_000;

/// Point-in-time gauges for export.
#[derive(Debug, Clone, Copy)]
pub struct EngineStats {
    pub active_flows: usize,
    pub half_open_max: u32,
    pub rst_per_sec: f64,
    pub new_flow_per_sec: f64,
}

pub struct Engine {
    state: EngineState,
    detectors: Vec<Box<dyn Detector>>,
    last_sweep_ns: u64,
    sweep_interval_ns: u64,
}

impl Engine {
    pub fn new(cfg: DetectConfig) -> Self {
        let detectors = default_detectors(&cfg);
        Engine {
            state: EngineState::new(cfg),
            detectors,
            last_sweep_ns: 0,
            sweep_interval_ns: NS_PER_SEC,
        }
    }

    /// Replace the detector chain (custom rule sets, tests).
    pub fn set_detectors(&mut self, detectors: Vec<Box<dyn Detector>>) {
        self.detectors = detectors;
    }

    /// Ingest one packet and return any events it (and any due sweep) produced.
    pub fn process(&mut self, pkt: &PacketMeta) -> Vec<L4Event> {
        let (key, delta) = self.state.update(pkt);

        let mut out = Vec::new();
        {
            let ctx = DetectCtx { state: &self.state, key, delta, now_ns: pkt.ts_nanos };
            for d in &mut self.detectors {
                if let Some(ev) = d.inspect(&ctx, pkt) {
                    out.push(ev);
                }
            }
        }

        if pkt.ts_nanos.saturating_sub(self.last_sweep_ns) >= self.sweep_interval_ns {
            self.last_sweep_ns = pkt.ts_nanos;
            out.extend(self.sweep(pkt.ts_nanos));
        }
        out
    }

    /// Time-driven checks: flag unanswered SYNs and evict idle flows. Safe to
    /// call as often as desired; call it on a timer for live captures with gaps.
    pub fn sweep(&mut self, now_ns: u64) -> Vec<L4Event> {
        let mut out = Vec::new();
        let ttl = self.state.cfg.flow_ttl_secs * NS_PER_SEC;
        let hto = self.state.cfg.handshake_timeout_secs * NS_PER_SEC;

        let mut timeouts = Vec::new();
        let mut to_remove = Vec::new();
        for (k, f) in self.state.flows.iter() {
            if matches!(f.state, TcpState::SynSent) && !f.handshake_timeout_flagged {
                if let Some(t) = f.syn_time_ns {
                    if now_ns.saturating_sub(t) > hto {
                        timeouts.push(*k);
                    }
                }
            }
            if now_ns.saturating_sub(f.last_seen_ns) > ttl {
                to_remove.push(*k);
            }
        }

        for k in timeouts {
            if let Some(f) = self.state.flows.get_mut(&k) {
                f.handshake_timeout_flagged = true;
                if f.half_open_counted {
                    f.half_open_counted = false;
                    if let Some(c) = self.state.globals.half_open.get_mut(&f.service) {
                        *c = c.saturating_sub(1);
                    }
                }
                let waited = (now_ns.saturating_sub(f.syn_time_ns.unwrap_or(now_ns))) as f64
                    / NS_PER_SEC as f64;
                out.push(L4Event::new(
                    now_ns,
                    EventKind::HandshakeTimeout,
                    Severity::Warning,
                    k,
                    waited,
                    format!("SYN to {} unanswered for {:.1}s (handshake timeout)", f.service, waited),
                ));
            }
        }

        for k in to_remove {
            if let Some(f) = self.state.flows.remove(&k) {
                if f.half_open_counted {
                    if let Some(c) = self.state.globals.half_open.get_mut(&f.service) {
                        *c = c.saturating_sub(1);
                    }
                }
            }
        }
        out
    }

    pub fn stats(&self, now_ns: u64) -> EngineStats {
        EngineStats {
            active_flows: self.state.flows.len(),
            half_open_max: self.state.globals.half_open_max(),
            rst_per_sec: self.state.globals.rst_rate.per_sec(now_ns),
            new_flow_per_sec: self.state.globals.new_flow_rate.per_sec(now_ns),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use l4scope_core::types::{Direction, Endpoint, FlowKey, PacketMeta, Protocol, TcpFlags};
    use std::net::{IpAddr, Ipv4Addr};

    fn ep(a: u8, p: u16) -> Endpoint {
        Endpoint::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, a)), p)
    }

    fn tcp(ts: u64, s: Endpoint, d: Endpoint, flags: u8, seq: u32, ack: u32, win: u32, plen: u32) -> PacketMeta {
        let (key, dir): (FlowKey, Direction) = FlowKey::canonical(s, d, Protocol::Tcp);
        PacketMeta {
            ts_nanos: ts,
            key,
            dir,
            proto: Protocol::Tcp,
            flags: TcpFlags(flags),
            seq,
            ack,
            window: win,
            payload_len: plen,
            ttl: 64,
            iface: 0,
        }
    }

    #[test]
    fn detects_retransmissions() {
        let mut eng = Engine::new(DetectConfig {
            retransmit_ratio_warn: 0.1,
            ..l4scope_core::config::Config::default().detect
        });
        let c = ep(1, 5000);
        let s = ep(2, 80);
        eng.process(&tcp(0, c, s, TcpFlags::SYN, 100, 0, 64240, 0));
        eng.process(&tcp(1, s, c, TcpFlags::SYN | TcpFlags::ACK, 900, 101, 65160, 0));
        eng.process(&tcp(2, c, s, TcpFlags::ACK, 101, 901, 64240, 0));
        // first data segment (not a retransmit)
        let _ = eng.process(&tcp(3, c, s, TcpFlags::ACK | TcpFlags::PSH, 101, 901, 64240, 100));
        // retransmit same segment
        let events = eng.process(&tcp(4, c, s, TcpFlags::ACK | TcpFlags::PSH, 101, 901, 64240, 100));
        assert!(events.iter().any(|e| e.kind == EventKind::Retransmission));
    }

    #[test]
    fn detects_zero_window() {
        let mut eng = Engine::new(l4scope_core::config::Config::default().detect);
        let c = ep(1, 5001);
        let s = ep(2, 5432);
        eng.process(&tcp(0, c, s, TcpFlags::SYN, 100, 0, 64240, 0));
        eng.process(&tcp(1, s, c, TcpFlags::SYN | TcpFlags::ACK, 900, 101, 65160, 0));
        eng.process(&tcp(2, c, s, TcpFlags::ACK, 101, 901, 64240, 0));
        let events = eng.process(&tcp(3, c, s, TcpFlags::ACK, 101, 901, 0, 0));
        assert!(events.iter().any(|e| e.kind == EventKind::ZeroWindow));
    }

    #[test]
    fn detects_handshake_timeout_via_sweep() {
        let mut eng = Engine::new(l4scope_core::config::Config::default().detect);
        let c = ep(1, 5002);
        let s = ep(2, 3306);
        eng.process(&tcp(0, c, s, TcpFlags::SYN, 100, 0, 64240, 0));
        let events = eng.sweep(10 * NS_PER_SEC);
        assert!(events.iter().any(|e| e.kind == EventKind::HandshakeTimeout));
    }

    #[test]
    fn detects_handshake_failure_on_rst() {
        let mut eng = Engine::new(l4scope_core::config::Config::default().detect);
        let c = ep(1, 5003);
        let s = ep(2, 8080);
        eng.process(&tcp(0, c, s, TcpFlags::SYN, 100, 0, 64240, 0));
        let events = eng.process(&tcp(1, s, c, TcpFlags::RST | TcpFlags::ACK, 0, 101, 0, 0));
        assert!(events.iter().any(|e| e.kind == EventKind::HandshakeFailure));
    }

    #[test]
    fn detects_duplicate_acks() {
        let mut eng = Engine::new(l4scope_core::config::Config::default().detect);
        let c = ep(1, 5004);
        let s = ep(2, 80);
        eng.process(&tcp(0, c, s, TcpFlags::SYN, 100, 0, 64240, 0));
        eng.process(&tcp(1, s, c, TcpFlags::SYN | TcpFlags::ACK, 900, 101, 65160, 0));
        eng.process(&tcp(2, c, s, TcpFlags::ACK, 101, 901, 64240, 0));
        // 1 baseline ack + 3 duplicates from the server (same ack, no payload).
        eng.process(&tcp(3, s, c, TcpFlags::ACK, 901, 200, 65160, 0));
        eng.process(&tcp(4, s, c, TcpFlags::ACK, 901, 200, 65160, 0));
        eng.process(&tcp(5, s, c, TcpFlags::ACK, 901, 200, 65160, 0));
        let events = eng.process(&tcp(6, s, c, TcpFlags::ACK, 901, 200, 65160, 0));
        assert!(events.iter().any(|e| e.kind == EventKind::DuplicateAck));
    }

    #[test]
    fn detects_rst_storm() {
        let mut eng = Engine::new(l4scope_core::config::Config::default().detect);
        let s = ep(9, 8080);
        // 25 resets within the same second exceeds the default 20/s threshold.
        let mut fired = false;
        for i in 0..25u32 {
            let c = ep((i % 200) as u8 + 20, 40000 + i as u16);
            let evs = eng.process(&tcp(i as u64 * 1_000_000, s, c, TcpFlags::RST, 0, 0, 0, 0));
            if evs.iter().any(|e| e.kind == EventKind::RstStorm) {
                fired = true;
            }
        }
        assert!(fired, "rst storm should trigger");
    }
}
