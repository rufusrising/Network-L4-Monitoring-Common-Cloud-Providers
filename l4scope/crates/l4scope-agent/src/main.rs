//! `l4scope` — the agent daemon. Wires config -> capture -> detection -> export.
//!
//! Examples:
//!   l4scope --demo                          # synthetic traffic, prints events
//!   l4scope --pcap capture.pcap             # replay a pcap file
//!   l4scope --backend live --iface eth0     # live via tcpdump/tshark
//!   l4scope --config /etc/l4scope.toml      # full config file
//!
//! Metrics are served at http://127.0.0.1:9560/metrics (configurable).

use std::collections::BTreeMap;
use std::process::ExitCode;

use l4scope_core::config::{Backend, Config, OtlpConfig};
use l4scope_core::types::{L4Event, Severity};
use l4scope_detect::Engine;
use l4scope_export::{serve, start_otlp, JsonSink, PodMatcher, Registry};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("l4scope: error: {e}");
            ExitCode::FAILURE
        }
    }
}

struct Args {
    config: Option<String>,
    backend: Option<String>,
    pcap: Option<String>,
    iface: Option<String>,
    live_cmd: Option<String>,
    json: Option<String>,
    no_metrics: bool,
    quiet: bool,
}

fn parse_args() -> std::result::Result<Args, String> {
    let mut a = Args {
        config: None,
        backend: None,
        pcap: None,
        iface: None,
        live_cmd: None,
        json: None,
        no_metrics: false,
        quiet: false,
    };
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                print_help();
                std::process::exit(0);
            }
            "--config" => a.config = Some(it.next().ok_or("--config needs a value")?),
            "--backend" => a.backend = Some(it.next().ok_or("--backend needs a value")?),
            "--pcap" => a.pcap = Some(it.next().ok_or("--pcap needs a value")?),
            "--iface" => a.iface = Some(it.next().ok_or("--iface needs a value")?),
            "--live-cmd" => a.live_cmd = Some(it.next().ok_or("--live-cmd needs a value")?),
            "--json" => a.json = Some(it.next().ok_or("--json needs a value")?),
            "--demo" => a.backend = Some("synthetic".into()),
            "--no-metrics" => a.no_metrics = true,
            "--quiet" => a.quiet = true,
            other => return Err(format!("unknown argument '{other}' (try --help)")),
        }
    }
    Ok(a)
}

fn print_help() {
    println!(
        "l4scope — cross-platform Layer-4 network health agent\n\n\
USAGE:\n  l4scope [OPTIONS]\n\n\
OPTIONS:\n\
  --demo                 Run the built-in synthetic traffic (no privileges needed)\n\
  --pcap <FILE>          Replay a classic .pcap file\n\
  --backend <NAME>       pcap_file | synthetic | live | ebpf | etw\n\
  --iface <NAME>         Interface for live/ebpf/etw backends (eth0, en0, Ethernet)\n\
  --live-cmd \"<CMD>\"     Override the live capture command\n\
  --config <FILE>        Load a TOML config file\n\
  --json <TARGET>        Event sink: stdout | stderr | <path> | off\n\
  --no-metrics           Do not start the Prometheus endpoint\n\
  --quiet                Do not print events to stderr\n\
  -h, --help             Show this help\n"
    );
}

fn apply_backend(cfg: &mut Config, name: &str) -> std::result::Result<(), String> {
    cfg.capture.backend = match name {
        "pcap_file" | "pcap" => Backend::PcapFile,
        "synthetic" | "demo" => Backend::Synthetic,
        "live" | "tcpdump" => Backend::Live,
        "ebpf" => Backend::Ebpf,
        "etw" => Backend::Etw,
        other => return Err(format!("unknown backend '{other}'")),
    };
    Ok(())
}

fn run() -> std::result::Result<(), String> {
    let args = parse_args()?;

    // Layer config: defaults -> file -> CLI overrides.
    let mut cfg = match &args.config {
        Some(path) => Config::load(path).map_err(|e| e.to_string())?,
        None => Config::default(),
    };
    if let Some(b) = &args.backend {
        apply_backend(&mut cfg, b)?;
    }
    if let Some(p) = &args.pcap {
        cfg.capture.backend = Backend::PcapFile;
        cfg.capture.pcap_path = p.clone();
    }
    if let Some(i) = &args.iface {
        cfg.capture.interface = i.clone();
    }
    if let Some(c) = &args.live_cmd {
        cfg.capture.live_command = c.clone();
    }
    if let Some(j) = &args.json {
        cfg.export.json_events = j.clone();
    }

    eprintln!(
        "l4scope: backend={:?} iface='{}' metrics='{}'",
        cfg.capture.backend,
        cfg.capture.interface,
        if args.no_metrics { "off" } else { cfg.export.prometheus_addr.as_str() }
    );

    // Export sinks.
    let registry = Registry::new();
    let _metrics_handle = if !args.no_metrics && !cfg.export.prometheus_addr.trim().is_empty() {
        match serve(&cfg.export.prometheus_addr, registry.clone()) {
            Ok(h) => {
                eprintln!("l4scope: metrics on http://{}/metrics", cfg.export.prometheus_addr);
                Some(h)
            }
            Err(e) => {
                eprintln!("l4scope: warning: metrics disabled: {e}");
                None
            }
        }
    } else {
        None
    };
    let mut json_sink = JsonSink::from_target(&cfg.export.json_events).map_err(|e| e.to_string())?;

    // Pod-level attribution (K8s): resolve a flow to its local pod IP via CIDRs.
    let pod_matcher = if cfg.otlp.pod_attribution && !cfg.otlp.pod_cidrs.trim().is_empty() {
        Some(PodMatcher::new(&cfg.otlp.pod_cidrs))
    } else {
        None
    };

    // OTLP/HTTP metrics push to an OpenTelemetry Collector. Keep the resource
    // attributes around for a final flush on shutdown.
    let otlp_ctx = if cfg.otlp.enabled {
        let attrs = build_resource_attrs(&cfg.otlp);
        match start_otlp(registry.clone(), &cfg.otlp, attrs.clone()) {
            Ok(h) => {
                eprintln!("l4scope: otlp -> {}{}", cfg.otlp.endpoint, cfg.otlp.path);
                Some((h, attrs))
            }
            Err(e) => {
                eprintln!("l4scope: warning: otlp disabled: {e}");
                None
            }
        }
    } else {
        None
    };

    // Capture + engine.
    let mut source = l4scope_capture::open(&cfg.capture).map_err(|e| e.to_string())?;
    let mut engine = Engine::new(cfg.detect.clone());
    eprintln!("l4scope: capturing from '{}' — press Ctrl-C to stop", source.name());

    let mut summary: BTreeMap<&'static str, u64> = BTreeMap::new();
    let mut packets: u64 = 0;
    let mut last_ts: u64 = 0;

    loop {
        match source.next_packet() {
            Ok(Some(pkt)) => {
                packets += 1;
                last_ts = pkt.ts_nanos;
                let pod_ip = pod_matcher.as_ref().and_then(|m| m.local_pod_ip(&pkt.key));
                registry.record_packet(pod_ip.as_deref());
                for ev in engine.process(&pkt) {
                    handle_event(
                        &ev, &registry, &mut json_sink, &mut summary, args.quiet,
                        pod_matcher.as_ref(),
                    );
                }
                if packets % 512 == 0 {
                    update_gauges(&engine, &registry, last_ts);
                }
            }
            Ok(None) => break, // clean end of stream (file/synthetic)
            Err(e) => {
                eprintln!("l4scope: capture error: {e}");
                break;
            }
        }
    }

    // Final sweep flushes handshake timeouts, then refresh gauges.
    for ev in engine.sweep(last_ts) {
        handle_event(
            &ev, &registry, &mut json_sink, &mut summary, args.quiet,
            pod_matcher.as_ref(),
        );
    }
    update_gauges(&engine, &registry, last_ts);

    // Deterministic final OTLP push so short runs (file replay / demo) still export.
    if let Some((_, attrs)) = &otlp_ctx {
        if let Err(e) = l4scope_export::otlp::flush(&registry, &cfg.otlp, attrs) {
            eprintln!("l4scope: otlp final flush failed: {e}");
        }
    }

    eprintln!("\nl4scope: processed {packets} packets");
    if summary.is_empty() {
        eprintln!("l4scope: no L4 anomalies detected");
    } else {
        eprintln!("l4scope: event summary:");
        for (kind, n) in &summary {
            eprintln!("  {kind:>18}: {n}");
        }
    }
    Ok(())
}

fn handle_event(
    ev: &L4Event,
    registry: &Registry,
    json: &mut JsonSink,
    summary: &mut BTreeMap<&'static str, u64>,
    quiet: bool,
    pod_matcher: Option<&PodMatcher>,
) {
    let pod_ip = pod_matcher.and_then(|m| m.local_pod_ip(&ev.key));
    registry.record_event(ev, pod_ip.as_deref());
    json.emit(ev);
    *summary.entry(ev.kind.as_str()).or_insert(0) += 1;
    if !quiet {
        let tag = match ev.severity {
            Severity::Info => "INFO",
            Severity::Warning => "WARN",
            Severity::Critical => "CRIT",
        };
        eprintln!("[{tag}] {}: {}", ev.kind.as_str(), ev.detail);
    }
}

fn update_gauges(engine: &Engine, registry: &Registry, now_ns: u64) {
    let s = engine.stats(now_ns);
    registry.set_gauges(
        s.active_flows as u64,
        s.half_open_max as u64,
        s.rst_per_sec,
        s.new_flow_per_sec,
    );
}

/// Assemble OTLP resource attributes from config + environment. Works on VMs
/// (host/cloud) and Kubernetes (node/cluster). The Collector's k8sattributes
/// processor turns per-datapoint `k8s.pod.ip` into pod/namespace/workload.
fn build_resource_attrs(cfg: &OtlpConfig) -> Vec<(String, String)> {
    let mut v: Vec<(String, String)> = Vec::new();
    v.push(("service.name".to_string(), cfg.service_name.clone()));

    // Well-known env → resource attribute mappings (set via DaemonSet/systemd).
    let env_map = [
        ("HOSTNAME", "host.name"),
        ("K8S_NODE_NAME", "k8s.node.name"),
        ("NODE_NAME", "k8s.node.name"),
        ("K8S_CLUSTER_NAME", "k8s.cluster.name"),
        ("CLOUD_PROVIDER", "cloud.provider"),
        ("CLOUD_REGION", "cloud.region"),
        ("CLOUD_ACCOUNT_ID", "cloud.account.id"),
    ];
    for (env, key) in env_map {
        if let Ok(val) = std::env::var(env) {
            if !val.is_empty() {
                v.push((key.to_string(), val));
            }
        }
    }

    // Config-provided attributes (k=v,k=v).
    push_kv_list(&mut v, &cfg.resource_attributes);
    // Standard OTEL env (k=v,k=v).
    if let Ok(s) = std::env::var("OTEL_RESOURCE_ATTRIBUTES") {
        push_kv_list(&mut v, &s);
    }
    v
}

fn push_kv_list(v: &mut Vec<(String, String)>, s: &str) {
    for kv in s.split(',') {
        if let Some((k, val)) = kv.split_once('=') {
            let k = k.trim();
            if !k.is_empty() {
                v.push((k.to_string(), val.trim().to_string()));
            }
        }
    }
}
