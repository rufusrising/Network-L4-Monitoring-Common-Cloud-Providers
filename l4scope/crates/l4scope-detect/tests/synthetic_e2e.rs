//! End-to-end: drive the built-in synthetic traffic through the detection engine
//! and assert every major detector fires. This is the golden pipeline test.

use std::collections::HashSet;

use l4scope_capture::{CaptureSource, SyntheticSource};
use l4scope_core::config::Config;
use l4scope_core::types::EventKind;
use l4scope_detect::Engine;

#[test]
fn synthetic_traffic_trips_every_major_detector() {
    let mut src = SyntheticSource::new();
    let mut engine = Engine::new(Config::default().detect);

    let mut kinds: HashSet<EventKind> = HashSet::new();
    let mut last_ts = 0u64;
    while let Some(pkt) = src.next_packet().expect("synthetic never errors") {
        last_ts = pkt.ts_nanos;
        for ev in engine.process(&pkt) {
            kinds.insert(ev.kind);
        }
    }
    // Final sweep flushes handshake timeouts.
    for ev in engine.sweep(last_ts) {
        kinds.insert(ev.kind);
    }

    for expected in [
        EventKind::HighRtt,
        EventKind::Retransmission,
        EventKind::DuplicateAck,
        EventKind::ZeroWindow,
        EventKind::RstStorm,
        EventKind::HandshakeFailure,
        EventKind::SynBacklog,
        EventKind::HandshakeTimeout,
    ] {
        assert!(kinds.contains(&expected), "expected {expected:?} to fire; got {kinds:?}");
    }
}
