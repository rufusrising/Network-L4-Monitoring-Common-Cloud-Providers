//! The detector set. Each detector is a small, pluggable rule that turns the
//! engine's per-packet [`PacketDelta`] plus flow/host state into zero or one
//! [`L4Event`]. Add a detector by implementing [`Detector`] and registering it
//! in `default_detectors`.

use l4scope_core::config::DetectConfig;
use l4scope_core::types::{EventKind, FlowKey, L4Event, Severity};

use crate::flow::{ns_to_secs_f64, EngineState, FlowState, Globals, PacketDelta};

/// Read-only view handed to every detector for one packet.
pub struct DetectCtx<'a> {
    pub state: &'a EngineState,
    pub key: FlowKey,
    pub delta: PacketDelta,
    pub now_ns: u64,
}

impl<'a> DetectCtx<'a> {
    pub fn flow(&self) -> Option<&FlowState> {
        self.state.flows.get(&self.key)
    }
    pub fn cfg(&self) -> &DetectConfig {
        &self.state.cfg
    }
    pub fn globals(&self) -> &Globals {
        &self.state.globals
    }
}

/// A pluggable L4 anomaly rule.
pub trait Detector: Send {
    fn name(&self) -> &'static str;
    fn inspect(&mut self, ctx: &DetectCtx, pkt: &l4scope_core::types::PacketMeta) -> Option<L4Event>;
}

/// Simple time-based debounce so host-wide alerts don't spam.
struct Debounce {
    last_ns: u64,
    gap_ns: u64,
}
impl Debounce {
    fn new(gap_secs: u64) -> Self {
        Debounce { last_ns: 0, gap_ns: gap_secs * 1_000_000_000 }
    }
    fn ready(&mut self, now: u64) -> bool {
        if now.saturating_sub(self.last_ns) >= self.gap_ns || self.last_ns == 0 {
            self.last_ns = now;
            true
        } else {
            false
        }
    }
}

// ---------------------------------------------------------------------------

pub struct RetransmissionDetector;
impl Detector for RetransmissionDetector {
    fn name(&self) -> &'static str {
        "retransmission"
    }
    fn inspect(&mut self, ctx: &DetectCtx, _pkt: &l4scope_core::types::PacketMeta) -> Option<L4Event> {
        if !ctx.delta.is_retransmit {
            return None;
        }
        let flow = ctx.flow()?;
        let ratio = flow.retransmit_ratio();
        if ratio < ctx.cfg().retransmit_ratio_warn {
            return None;
        }
        Some(L4Event::new(
            ctx.now_ns,
            EventKind::Retransmission,
            Severity::Warning,
            ctx.key,
            ratio,
            format!(
                "TCP retransmissions on {}: {}/{} segments ({:.1}% loss/retx)",
                ctx.key, flow.retransmits, flow.data_segments, ratio * 100.0
            ),
        ))
    }
}

pub struct OutOfOrderDetector;
impl Detector for OutOfOrderDetector {
    fn name(&self) -> &'static str {
        "out_of_order"
    }
    fn inspect(&mut self, ctx: &DetectCtx, _pkt: &l4scope_core::types::PacketMeta) -> Option<L4Event> {
        if !ctx.delta.is_out_of_order {
            return None;
        }
        Some(L4Event::new(
            ctx.now_ns,
            EventKind::OutOfOrder,
            Severity::Info,
            ctx.key,
            1.0,
            format!("Out-of-order / gap in segment stream on {}", ctx.key),
        ))
    }
}

pub struct DupAckDetector;
impl Detector for DupAckDetector {
    fn name(&self) -> &'static str {
        "duplicate_ack"
    }
    fn inspect(&mut self, ctx: &DetectCtx, _pkt: &l4scope_core::types::PacketMeta) -> Option<L4Event> {
        // Emit exactly once, when the burst reaches the configured threshold.
        if ctx.delta.is_dup_ack && ctx.delta.dup_ack_count == ctx.cfg().dup_ack_threshold {
            return Some(L4Event::new(
                ctx.now_ns,
                EventKind::DuplicateAck,
                Severity::Warning,
                ctx.key,
                ctx.delta.dup_ack_count as f64,
                format!(
                    "{} duplicate ACKs on {} (fast-retransmit / loss signal)",
                    ctx.delta.dup_ack_count, ctx.key
                ),
            ));
        }
        None
    }
}

pub struct ZeroWindowDetector;
impl Detector for ZeroWindowDetector {
    fn name(&self) -> &'static str {
        "zero_window"
    }
    fn inspect(&mut self, ctx: &DetectCtx, _pkt: &l4scope_core::types::PacketMeta) -> Option<L4Event> {
        if !ctx.delta.zero_window_edge {
            return None;
        }
        Some(L4Event::new(
            ctx.now_ns,
            EventKind::ZeroWindow,
            Severity::Warning,
            ctx.key,
            0.0,
            format!("Zero receive window on {} — receiver stalled / app not draining", ctx.key),
        ))
    }
}

pub struct HighRttDetector;
impl Detector for HighRttDetector {
    fn name(&self) -> &'static str {
        "high_rtt"
    }
    fn inspect(&mut self, ctx: &DetectCtx, _pkt: &l4scope_core::types::PacketMeta) -> Option<L4Event> {
        let rtt_ns = ctx.delta.rtt_sample_ns?;
        let rtt_ms = ns_to_secs_f64(rtt_ns) * 1000.0;
        if rtt_ms < ctx.cfg().rtt_warn_ms {
            return None;
        }
        let sev = if rtt_ms >= ctx.cfg().rtt_warn_ms * 4.0 {
            Severity::Warning
        } else {
            Severity::Info
        };
        Some(L4Event::new(
            ctx.now_ns,
            EventKind::HighRtt,
            sev,
            ctx.key,
            rtt_ms,
            format!("High handshake RTT on {}: {:.0} ms", ctx.key, rtt_ms),
        ))
    }
}

pub struct HandshakeFailureDetector;
impl Detector for HandshakeFailureDetector {
    fn name(&self) -> &'static str {
        "handshake_failure"
    }
    fn inspect(&mut self, ctx: &DetectCtx, _pkt: &l4scope_core::types::PacketMeta) -> Option<L4Event> {
        if !ctx.delta.handshake_refused {
            return None;
        }
        Some(L4Event::new(
            ctx.now_ns,
            EventKind::HandshakeFailure,
            Severity::Warning,
            ctx.key,
            1.0,
            format!("Connection refused (RST during handshake) on {}", ctx.key),
        ))
    }
}

pub struct RstStormDetector {
    debounce: Debounce,
}
impl RstStormDetector {
    fn new(gap_secs: u64) -> Self {
        RstStormDetector { debounce: Debounce::new(gap_secs) }
    }
}
impl Detector for RstStormDetector {
    fn name(&self) -> &'static str {
        "rst_storm"
    }
    fn inspect(&mut self, ctx: &DetectCtx, _pkt: &l4scope_core::types::PacketMeta) -> Option<L4Event> {
        if !ctx.delta.rst {
            return None;
        }
        let rate = ctx.globals().rst_rate.per_sec(ctx.now_ns);
        if rate < ctx.cfg().rst_storm_per_sec || !self.debounce.ready(ctx.now_ns) {
            return None;
        }
        Some(L4Event::new(
            ctx.now_ns,
            EventKind::RstStorm,
            Severity::Critical,
            ctx.key,
            rate,
            format!("RST storm: {:.0} resets/s host-wide (near {})", rate, ctx.key),
        ))
    }
}

pub struct SynBacklogDetector {
    debounce: Debounce,
}
impl SynBacklogDetector {
    fn new(gap_secs: u64) -> Self {
        SynBacklogDetector { debounce: Debounce::new(gap_secs) }
    }
}
impl Detector for SynBacklogDetector {
    fn name(&self) -> &'static str {
        "syn_backlog"
    }
    fn inspect(&mut self, ctx: &DetectCtx, _pkt: &l4scope_core::types::PacketMeta) -> Option<L4Event> {
        let flow = ctx.flow()?;
        let count = ctx.globals().half_open_for(&flow.service);
        if count < ctx.cfg().syn_backlog_threshold || !self.debounce.ready(ctx.now_ns) {
            return None;
        }
        Some(L4Event::new(
            ctx.now_ns,
            EventKind::SynBacklog,
            Severity::Warning,
            ctx.key,
            count as f64,
            format!(
                "SYN backlog to {}: {} half-open connections (possible SYN flood / accept-queue exhaustion)",
                flow.service, count
            ),
        ))
    }
}

pub struct ChurnDetector {
    debounce: Debounce,
}
impl ChurnDetector {
    fn new(gap_secs: u64) -> Self {
        ChurnDetector { debounce: Debounce::new(gap_secs) }
    }
}
impl Detector for ChurnDetector {
    fn name(&self) -> &'static str {
        "connection_churn"
    }
    fn inspect(&mut self, ctx: &DetectCtx, _pkt: &l4scope_core::types::PacketMeta) -> Option<L4Event> {
        if !ctx.delta.new_flow {
            return None;
        }
        let rate = ctx.globals().new_flow_rate.per_sec(ctx.now_ns);
        if rate < ctx.cfg().churn_per_sec || !self.debounce.ready(ctx.now_ns) {
            return None;
        }
        Some(L4Event::new(
            ctx.now_ns,
            EventKind::ConnectionChurn,
            Severity::Info,
            ctx.key,
            rate,
            format!("Connection churn: {:.0} new flows/s host-wide", rate),
        ))
    }
}

/// The default detector chain, in evaluation order.
pub fn default_detectors(cfg: &DetectConfig) -> Vec<Box<dyn Detector>> {
    let gap = cfg.alert_debounce_secs;
    vec![
        Box::new(RetransmissionDetector),
        Box::new(OutOfOrderDetector),
        Box::new(DupAckDetector),
        Box::new(ZeroWindowDetector),
        Box::new(HighRttDetector),
        Box::new(HandshakeFailureDetector),
        Box::new(RstStormDetector::new(gap)),
        Box::new(SynBacklogDetector::new(gap)),
        Box::new(ChurnDetector::new(gap)),
    ]
}
