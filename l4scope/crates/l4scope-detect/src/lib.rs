//! `l4scope-detect` — the platform-independent L4 detection engine.
//!
//! Input: a stream of normalized [`l4scope_core::PacketMeta`] from any capture
//! backend. Output: [`l4scope_core::L4Event`] anomalies. All state and thresholds
//! live here; capture and export are separate crates.

pub mod detectors;
pub mod engine;
pub mod flow;
pub mod window;

pub use detectors::{DetectCtx, Detector};
pub use engine::{Engine, EngineStats};
pub use flow::{EngineState, FlowState, Globals, PacketDelta, TcpState};
