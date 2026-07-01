//! Configuration model and a tiny, dependency-free TOML-subset parser.
//!
//! Supported syntax (enough for this agent, no external crate needed):
//!   `# comment`
//!   `[section]`
//!   `key = value`   where value is: bare int, `true`/`false`, or "quoted string"
//!
//! Unknown keys are rejected so typos surface immediately (fail-fast config).

use crate::error::{Error, Result};

/// Which capture backend to use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Backend {
    /// Replay a classic `.pcap` file (always available, all platforms).
    PcapFile,
    /// Deterministic synthetic traffic that exercises every detector (demo/CI).
    Synthetic,
    /// Live capture by spawning `tcpdump`/`tshark`/`pktmon` and parsing its pcap
    /// stream. Zero FFI; works wherever the tool is installed.
    Live,
    /// Native eBPF/CO-RE capture (Linux only, `--features ebpf`).
    Ebpf,
    /// Native Windows ETW/pktmon capture (`--features etw`).
    Etw,
}

impl Backend {
    fn parse(s: &str) -> Result<Backend> {
        match s {
            "pcap_file" | "pcap" => Ok(Backend::PcapFile),
            "synthetic" | "demo" => Ok(Backend::Synthetic),
            "live" | "tcpdump" => Ok(Backend::Live),
            "ebpf" => Ok(Backend::Ebpf),
            "etw" => Ok(Backend::Etw),
            other => Err(Error::Config(format!("unknown backend '{other}'"))),
        }
    }
}

/// Top-level agent configuration.
#[derive(Debug, Clone)]
pub struct Config {
    pub capture: CaptureConfig,
    pub detect: DetectConfig,
    pub export: ExportConfig,
    pub otlp: OtlpConfig,
}

#[derive(Debug, Clone)]
pub struct CaptureConfig {
    pub backend: Backend,
    /// Interface name for live/eBPF/ETW backends (e.g. `eth0`, `en0`, `Ethernet`).
    pub interface: String,
    /// BPF filter expression for the live backend.
    pub filter: String,
    /// Path for the pcap_file backend.
    pub pcap_path: String,
    /// Override the live capture command (else auto-selected per OS).
    pub live_command: String,
}

#[derive(Debug, Clone)]
pub struct DetectConfig {
    /// Idle flows older than this (seconds) are garbage-collected.
    pub flow_ttl_secs: u64,
    /// Retransmit ratio (retransmits / data-segments) above which we warn.
    pub retransmit_ratio_warn: f64,
    /// Number of duplicate ACKs that signals fast-retransmit / loss.
    pub dup_ack_threshold: u32,
    /// RST events per second across the host above which we raise an RST storm.
    pub rst_storm_per_sec: f64,
    /// Concurrent half-open (SYN_SENT/SYN_RCVD) flows to one service above which
    /// we flag possible SYN backlog exhaustion / SYN flood.
    pub syn_backlog_threshold: u32,
    /// Handshake RTT (ms) above which we flag high latency.
    pub rtt_warn_ms: f64,
    /// Seconds a SYN may go unanswered before we call it a handshake timeout.
    pub handshake_timeout_secs: u64,
    /// New-flow rate (flows/sec) above which we flag connection churn.
    pub churn_per_sec: f64,
    /// Minimum seconds between repeated emissions of the same global event.
    pub alert_debounce_secs: u64,
}

#[derive(Debug, Clone)]
pub struct ExportConfig {
    /// `host:port` to serve Prometheus `/metrics` and `/healthz`. Empty = off.
    pub prometheus_addr: String,
    /// Where to write NDJSON events: `stdout`, `stderr`, empty (off), or a path.
    pub json_events: String,
}

/// OpenTelemetry (OTLP/HTTP + JSON) metrics push. Consumable by any OTel
/// Collector; see docs/OTEL.md for AKS/GKE/EKS/VM setups.
#[derive(Debug, Clone)]
pub struct OtlpConfig {
    /// Enable the OTLP push exporter.
    pub enabled: bool,
    /// Collector base endpoint, e.g. `http://localhost:4318` (a node-local
    /// Collector/agent). HTTP only from the agent; use a Collector for TLS/cloud.
    pub endpoint: String,
    /// Metrics path appended to `endpoint` (OTLP/HTTP default).
    pub path: String,
    /// Push interval in seconds.
    pub interval_secs: u64,
    /// Extra HTTP headers as `k=v,k=v` (e.g. auth for a gateway Collector).
    pub headers: String,
    /// Resource attributes as `k=v,k=v` (merged with env `OTEL_RESOURCE_ATTRIBUTES`).
    pub resource_attributes: String,
    /// `service.name` resource attribute.
    pub service_name: String,
    /// Emit pod-level series: attribute datapoints with `k8s.pod.ip` when a flow
    /// endpoint falls inside one of these CIDRs (comma-separated). Empty = off.
    pub pod_cidrs: String,
    /// Master switch for pod-level attribution (requires `pod_cidrs`).
    pub pod_attribution: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            capture: CaptureConfig {
                backend: Backend::Synthetic,
                interface: String::new(),
                filter: "tcp or udp".to_string(),
                pcap_path: String::new(),
                live_command: String::new(),
            },
            detect: DetectConfig {
                flow_ttl_secs: 120,
                retransmit_ratio_warn: 0.05,
                dup_ack_threshold: 3,
                rst_storm_per_sec: 20.0,
                syn_backlog_threshold: 64,
                rtt_warn_ms: 250.0,
                handshake_timeout_secs: 3,
                churn_per_sec: 200.0,
                alert_debounce_secs: 10,
            },
            export: ExportConfig {
                prometheus_addr: "127.0.0.1:9560".to_string(),
                json_events: "stdout".to_string(),
            },
            otlp: OtlpConfig {
                enabled: false,
                endpoint: "http://localhost:4318".to_string(),
                path: "/v1/metrics".to_string(),
                interval_secs: 15,
                headers: String::new(),
                resource_attributes: String::new(),
                service_name: "l4scope".to_string(),
                pod_cidrs: String::new(),
                pod_attribution: false,
            },
        }
    }
}

impl Config {
    /// Load and parse from a file path.
    pub fn load(path: &str) -> Result<Config> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| Error::Config(format!("cannot read {path}: {e}")))?;
        Config::from_str(&text)
    }

    /// Parse from an in-memory string, layering over defaults.
    pub fn from_str(text: &str) -> Result<Config> {
        let mut cfg = Config::default();
        let mut section = String::new();

        for (lineno, raw) in text.lines().enumerate() {
            let line = strip_comment(raw).trim();
            if line.is_empty() {
                continue;
            }
            if let Some(sec) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
                section = sec.trim().to_string();
                continue;
            }
            let (k, v) = line
                .split_once('=')
                .ok_or_else(|| Error::Config(format!("line {}: expected key = value", lineno + 1)))?;
            let key = k.trim();
            let val = v.trim();
            apply(&mut cfg, &section, key, val)
                .map_err(|e| Error::Config(format!("line {}: {e}", lineno + 1)))?;
        }
        Ok(cfg)
    }
}

fn strip_comment(line: &str) -> &str {
    // Comments start with '#' unless inside quotes. Values here never contain '#'
    // in practice, so a simple split is sufficient and predictable.
    match line.find('#') {
        Some(i) => &line[..i],
        None => line,
    }
}

fn unquote(v: &str) -> String {
    let v = v.trim();
    if v.len() >= 2 && v.starts_with('"') && v.ends_with('"') {
        v[1..v.len() - 1].to_string()
    } else {
        v.to_string()
    }
}

fn parse_bool(v: &str) -> Result<bool> {
    match v {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(Error::Config(format!("expected true/false, got '{v}'"))),
    }
}

fn parse_u64(v: &str) -> Result<u64> {
    v.parse::<u64>()
        .map_err(|_| Error::Config(format!("expected integer, got '{v}'")))
}

fn parse_u32(v: &str) -> Result<u32> {
    v.parse::<u32>()
        .map_err(|_| Error::Config(format!("expected integer, got '{v}'")))
}

fn parse_f64(v: &str) -> Result<f64> {
    v.parse::<f64>()
        .map_err(|_| Error::Config(format!("expected number, got '{v}'")))
}

fn apply(cfg: &mut Config, section: &str, key: &str, val: &str) -> Result<()> {
    match (section, key) {
        ("capture", "backend") => cfg.capture.backend = Backend::parse(&unquote(val))?,
        ("capture", "interface") => cfg.capture.interface = unquote(val),
        ("capture", "filter") => cfg.capture.filter = unquote(val),
        ("capture", "pcap_path") => cfg.capture.pcap_path = unquote(val),
        ("capture", "live_command") => cfg.capture.live_command = unquote(val),

        ("detect", "flow_ttl_secs") => cfg.detect.flow_ttl_secs = parse_u64(val)?,
        ("detect", "retransmit_ratio_warn") => cfg.detect.retransmit_ratio_warn = parse_f64(val)?,
        ("detect", "dup_ack_threshold") => cfg.detect.dup_ack_threshold = parse_u32(val)?,
        ("detect", "rst_storm_per_sec") => cfg.detect.rst_storm_per_sec = parse_f64(val)?,
        ("detect", "syn_backlog_threshold") => cfg.detect.syn_backlog_threshold = parse_u32(val)?,
        ("detect", "rtt_warn_ms") => cfg.detect.rtt_warn_ms = parse_f64(val)?,
        ("detect", "handshake_timeout_secs") => cfg.detect.handshake_timeout_secs = parse_u64(val)?,
        ("detect", "churn_per_sec") => cfg.detect.churn_per_sec = parse_f64(val)?,
        ("detect", "alert_debounce_secs") => cfg.detect.alert_debounce_secs = parse_u64(val)?,

        ("export", "prometheus_addr") => cfg.export.prometheus_addr = unquote(val),
        ("export", "json_events") => cfg.export.json_events = unquote(val),

        ("otlp", "enabled") => cfg.otlp.enabled = parse_bool(&unquote(val))?,
        ("otlp", "endpoint") => cfg.otlp.endpoint = unquote(val),
        ("otlp", "path") => cfg.otlp.path = unquote(val),
        ("otlp", "interval_secs") => cfg.otlp.interval_secs = parse_u64(val)?,
        ("otlp", "headers") => cfg.otlp.headers = unquote(val),
        ("otlp", "resource_attributes") => cfg.otlp.resource_attributes = unquote(val),
        ("otlp", "service_name") => cfg.otlp.service_name = unquote(val),
        ("otlp", "pod_cidrs") => cfg.otlp.pod_cidrs = unquote(val),
        ("otlp", "pod_attribution") => cfg.otlp.pod_attribution = parse_bool(&unquote(val))?,

        _ => return Err(Error::Config(format!("unknown key '[{section}] {key}'"))),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_sections_and_types() {
        let cfg = Config::from_str(
            r#"
            [capture]
            backend = "ebpf"
            interface = "eth0"
            [detect]
            rst_storm_per_sec = 12.5
            dup_ack_threshold = 5
            [otlp]
            enabled = true
            endpoint = "http://collector:4318"
            pod_attribution = true
            pod_cidrs = "10.244.0.0/16"
            "#,
        )
        .expect("valid config");
        assert_eq!(cfg.capture.backend, Backend::Ebpf);
        assert_eq!(cfg.capture.interface, "eth0");
        assert_eq!(cfg.detect.rst_storm_per_sec, 12.5);
        assert_eq!(cfg.detect.dup_ack_threshold, 5);
        assert!(cfg.otlp.enabled);
        assert!(cfg.otlp.pod_attribution);
        assert_eq!(cfg.otlp.endpoint, "http://collector:4318");
    }

    #[test]
    fn rejects_unknown_key() {
        let err = Config::from_str("[detect]\nbogus = 1\n");
        assert!(err.is_err());
    }

    #[test]
    fn defaults_are_conservative() {
        let cfg = Config::default();
        assert!(!cfg.otlp.enabled);
        assert_eq!(cfg.export.prometheus_addr, "127.0.0.1:9560");
    }
}
