//! Normalized, backend-independent data model.
//!
//! Every capture backend (pcap file, live tcpdump/pktmon, eBPF, Windows ETW)
//! MUST emit [`PacketMeta`]. This is the parity contract that lets the detection
//! engine stay identical across platforms and capture technologies.

use std::net::IpAddr;

/// Transport-layer protocol we track.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    Tcp,
    Udp,
}

impl Protocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
        }
    }
}

/// One endpoint of a flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Endpoint {
    pub ip: IpAddr,
    pub port: u16,
}

impl Endpoint {
    pub fn new(ip: IpAddr, port: u16) -> Self {
        Endpoint { ip, port }
    }
}

impl std::fmt::Display for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.ip {
            IpAddr::V4(v4) => write!(f, "{v4}:{}", self.port),
            IpAddr::V6(v6) => write!(f, "[{v6}]:{}", self.port),
        }
    }
}

/// Which side of the canonical flow a packet travelled on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// From the canonical "low" endpoint to the "high" endpoint.
    Forward,
    /// From "high" back to "low".
    Reverse,
}

impl Direction {
    #[inline]
    pub fn index(&self) -> usize {
        match self {
            Direction::Forward => 0,
            Direction::Reverse => 1,
        }
    }
}

/// Direction-independent flow identity. Both packets of a conversation map to the
/// same key so the engine keeps a single [`FlowState`] per conversation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub low: Endpoint,
    pub high: Endpoint,
    pub proto: Protocol,
}

impl FlowKey {
    /// Build a canonical key from an observed (src, dst) pair and return the
    /// direction the observed packet travelled.
    pub fn canonical(src: Endpoint, dst: Endpoint, proto: Protocol) -> (FlowKey, Direction) {
        if src <= dst {
            (FlowKey { low: src, high: dst, proto }, Direction::Forward)
        } else {
            (FlowKey { low: dst, high: src, proto }, Direction::Reverse)
        }
    }
}

impl std::fmt::Display for FlowKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {} <-> {}", self.proto.as_str(), self.low, self.high)
    }
}

/// TCP control flags, packed. Newtype over the raw flags byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TcpFlags(pub u8);

impl TcpFlags {
    pub const FIN: u8 = 0x01;
    pub const SYN: u8 = 0x02;
    pub const RST: u8 = 0x04;
    pub const PSH: u8 = 0x08;
    pub const ACK: u8 = 0x10;
    pub const URG: u8 = 0x20;

    #[inline] pub fn has(&self, bit: u8) -> bool { self.0 & bit != 0 }
    #[inline] pub fn syn(&self) -> bool { self.has(Self::SYN) }
    #[inline] pub fn ack(&self) -> bool { self.has(Self::ACK) }
    #[inline] pub fn fin(&self) -> bool { self.has(Self::FIN) }
    #[inline] pub fn rst(&self) -> bool { self.has(Self::RST) }
    #[inline] pub fn psh(&self) -> bool { self.has(Self::PSH) }

    /// True for a bare SYN (connection request, not SYN-ACK).
    #[inline] pub fn is_syn_only(&self) -> bool { self.syn() && !self.ack() }
    /// True for a SYN-ACK (connection acceptance).
    #[inline] pub fn is_syn_ack(&self) -> bool { self.syn() && self.ack() }
}

/// A normalized packet record. This is the single unit of currency flowing from
/// capture backends into the detection engine.
#[derive(Debug, Clone)]
pub struct PacketMeta {
    /// Capture timestamp, nanoseconds since UNIX epoch.
    pub ts_nanos: u64,
    /// Canonical flow key.
    pub key: FlowKey,
    /// Direction this packet travelled relative to the canonical key.
    pub dir: Direction,
    pub proto: Protocol,
    /// TCP flags (zeroed for UDP).
    pub flags: TcpFlags,
    /// TCP sequence number (0 for UDP).
    pub seq: u32,
    /// TCP acknowledgement number (0 for UDP).
    pub ack: u32,
    /// Advertised receive window. Raw value; scaling is best-effort.
    pub window: u32,
    /// L4 payload length in bytes (excludes headers).
    pub payload_len: u32,
    /// IP TTL / hop-limit, useful for path-change and spoofing heuristics.
    pub ttl: u8,
    /// Capture interface identifier (backend-defined; 0 when unknown).
    pub iface: u32,
}

/// Anomaly categories the engine can report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventKind {
    Retransmission,
    DuplicateAck,
    OutOfOrder,
    ZeroWindow,
    RstStorm,
    HandshakeFailure,
    HandshakeTimeout,
    SynBacklog,
    HighRtt,
    ConnectionChurn,
}

impl EventKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            EventKind::Retransmission => "retransmission",
            EventKind::DuplicateAck => "duplicate_ack",
            EventKind::OutOfOrder => "out_of_order",
            EventKind::ZeroWindow => "zero_window",
            EventKind::RstStorm => "rst_storm",
            EventKind::HandshakeFailure => "handshake_failure",
            EventKind::HandshakeTimeout => "handshake_timeout",
            EventKind::SynBacklog => "syn_backlog",
            EventKind::HighRtt => "high_rtt",
            EventKind::ConnectionChurn => "connection_churn",
        }
    }
}

/// Severity ranking for events and alert routing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Warning => "warning",
            Severity::Critical => "critical",
        }
    }
}

/// An emitted L4 health event.
#[derive(Debug, Clone)]
pub struct L4Event {
    pub ts_nanos: u64,
    pub kind: EventKind,
    pub severity: Severity,
    /// The flow this event concerns (may be a representative flow for global
    /// events like RST storms).
    pub key: FlowKey,
    /// The primary metric value that triggered the event (e.g. retransmit rate,
    /// RTT in ms, half-open count).
    pub value: f64,
    /// Human-readable one-line explanation.
    pub detail: String,
}

impl L4Event {
    pub fn new(
        ts_nanos: u64,
        kind: EventKind,
        severity: Severity,
        key: FlowKey,
        value: f64,
        detail: impl Into<String>,
    ) -> Self {
        L4Event { ts_nanos, kind, severity, key, value, detail: detail.into() }
    }

    /// Render as a single NDJSON line (hand-rolled; no serde dependency).
    pub fn to_json(&self) -> String {
        format!(
            "{{\"ts_ns\":{},\"kind\":\"{}\",\"severity\":\"{}\",\"proto\":\"{}\",\"low\":\"{}\",\"high\":\"{}\",\"value\":{:.3},\"detail\":\"{}\"}}",
            self.ts_nanos,
            self.kind.as_str(),
            self.severity.as_str(),
            self.key.proto.as_str(),
            self.key.low,
            self.key.high,
            self.value,
            json_escape(&self.detail),
        )
    }
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn ep(a: u8, p: u16) -> Endpoint {
        Endpoint::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, a)), p)
    }

    #[test]
    fn canonical_key_is_direction_independent() {
        let a = ep(1, 5000);
        let b = ep(2, 80);
        let (k1, d1) = FlowKey::canonical(a, b, Protocol::Tcp);
        let (k2, d2) = FlowKey::canonical(b, a, Protocol::Tcp);
        assert_eq!(k1, k2, "both directions map to one key");
        assert_ne!(d1, d2, "directions differ");
    }

    #[test]
    fn tcp_flags_decode() {
        let f = TcpFlags(TcpFlags::SYN);
        assert!(f.is_syn_only());
        assert!(!f.is_syn_ack());
        let sa = TcpFlags(TcpFlags::SYN | TcpFlags::ACK);
        assert!(sa.is_syn_ack());
        assert!(TcpFlags(TcpFlags::RST).rst());
    }

    #[test]
    fn event_json_has_fields() {
        let (k, _) = FlowKey::canonical(ep(1, 5000), ep(2, 80), Protocol::Tcp);
        let ev = L4Event::new(42, EventKind::ZeroWindow, Severity::Warning, k, 0.0, "stall\"x");
        let j = ev.to_json();
        assert!(j.contains("\"kind\":\"zero_window\""));
        assert!(j.contains("\"severity\":\"warning\""));
        assert!(j.contains("stall\\\"x"), "detail is escaped");
    }
}
