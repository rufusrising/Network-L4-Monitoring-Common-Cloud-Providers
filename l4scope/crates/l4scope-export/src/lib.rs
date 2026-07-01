//! `l4scope-export` — sinks and endpoints for events and metrics:
//! a Prometheus `/metrics` + `/healthz` HTTP endpoint, an NDJSON event sink, and
//! an OTLP/HTTP (JSON) metrics push exporter with node/pod attribution.
//! Dependency-free (std only).

pub mod attribution;
pub mod http;
pub mod json;
pub mod metrics;
pub mod otlp;

pub use attribution::PodMatcher;
pub use http::serve;
pub use json::JsonSink;
pub use metrics::{MetricsSnapshot, Registry};
pub use otlp::start as start_otlp;
