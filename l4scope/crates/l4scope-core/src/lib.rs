//! `l4scope-core` — shared, dependency-free data model, config, and helpers for
//! the L4Scope agent. No I/O policy lives here; this crate is pure types so it
//! compiles identically on every target.

pub mod config;
pub mod error;
pub mod types;

pub use config::{Backend, CaptureConfig, Config, DetectConfig, ExportConfig, OtlpConfig};
pub use error::{Error, Result};
pub use types::{
    Direction, Endpoint, EventKind, FlowKey, L4Event, PacketMeta, Protocol, Severity, TcpFlags,
};

use std::time::{SystemTime, UNIX_EPOCH};

/// Wall-clock time in nanoseconds since the UNIX epoch. Used to stamp live
/// packets and to drive time-window detectors.
pub fn now_nanos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

/// Convert nanoseconds to whole seconds (floor).
#[inline]
pub fn nanos_to_secs(ns: u64) -> u64 {
    ns / 1_000_000_000
}
