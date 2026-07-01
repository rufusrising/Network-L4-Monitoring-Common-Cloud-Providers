//! Native Windows capture backend via ETW / pktmon. Compiled only with
//! `--features etw` on Windows.
//!
//! Design: start a realtime ETW session subscribing to the
//! `Microsoft-Windows-TCPIP` and `Microsoft-Windows-Kernel-Network` providers
//! (or drive `pktmon` in realtime mode), decode each event into [`PacketMeta`],
//! and feed the shared engine. This gives parity with the Linux eBPF path
//! without requiring Npcap.
//!
//! The realtime ETW consumer uses the `windows`/`ferrisetw` crates in a
//! production build. This reference file documents the contract and errors out
//! until the consumer is wired in; the FFI-free `live` backend (driving `tshark`
//! or `pktmon pcapng`) is the recommended interim path on Windows.

use l4scope_core::config::CaptureConfig;
use l4scope_core::error::{Error, Result};

use crate::CaptureSource;

pub fn open(_cfg: &CaptureConfig) -> Result<Box<dyn CaptureSource>> {
    Err(Error::UnsupportedBackend(
        "etw backend requires a realtime ETW consumer (Microsoft-Windows-TCPIP) \
         or pktmon session; use the `live` backend with tshark/pktmon until wired in."
            .into(),
    ))
}
