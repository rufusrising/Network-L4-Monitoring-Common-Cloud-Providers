//! Integration test: replay testdata/sample.pcap through the pcap_file backend
//! and assert the parser produces the expected packets/fields.

use std::path::PathBuf;

use l4scope_capture::CaptureSource;
use l4scope_core::config::{Backend, Config};
use l4scope_core::types::Protocol;

fn sample_path() -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/sample.pcap")
        .to_string_lossy()
        .into_owned()
}

#[test]
fn replays_sample_pcap() {
    let mut cap = Config::default().capture;
    cap.backend = Backend::PcapFile;
    cap.pcap_path = sample_path();

    let mut src = l4scope_capture::open(&cap).expect("open pcap");
    let mut pkts = Vec::new();
    while let Some(p) = src.next_packet().expect("read packet") {
        pkts.push(p);
    }

    assert_eq!(pkts.len(), 8, "sample.pcap has 8 packets");
    assert!(pkts[0].flags.is_syn_only(), "first packet is a SYN");
    assert!(pkts.iter().all(|p| p.proto == Protocol::Tcp));
    assert!(pkts.iter().any(|p| p.window == 0), "includes a zero-window packet");
    // Endpoint 443 (server) appears on the canonical key.
    assert!(pkts.iter().any(|p| p.key.low.port == 443 || p.key.high.port == 443));
    // At least one 200-byte data segment (the retransmitted payload).
    assert!(pkts.iter().any(|p| p.payload_len == 200));
}
