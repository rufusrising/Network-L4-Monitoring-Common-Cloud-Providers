//! OTLP/HTTP metrics exporter using JSON encoding — dependency-free.
//!
//! The OpenTelemetry protocol supports JSON over HTTP (`Content-Type:
//! application/json`, POST to `/v1/metrics`), so we can push to any OTel
//! Collector without protobuf or gRPC libraries. TLS is intentionally out of
//! scope for the agent: point `endpoint` at a node-local Collector over HTTP and
//! let the Collector handle TLS/auth to the cloud backend (the standard pattern).

use std::io::{Read, Write};
use std::net::TcpStream;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use l4scope_core::config::OtlpConfig;
use l4scope_core::error::{Error, Result};

use crate::metrics::{MetricsSnapshot, Registry};

const NS_PER_SEC: u64 = 1_000_000_000;

struct Target {
    host: String,
    port: u16,
    path: String,
    headers: Vec<(String, String)>,
}

/// Start the periodic OTLP push. Returns the pusher thread handle.
pub fn start(
    registry: Registry,
    cfg: &OtlpConfig,
    resource_attrs: Vec<(String, String)>,
) -> Result<JoinHandle<()>> {
    let target = parse_target(cfg)?;
    let interval = Duration::from_secs(cfg.interval_secs.max(1));
    let start_ns = l4scope_core::now_nanos();

    let handle = thread::spawn(move || loop {
        thread::sleep(interval);
        if let Err(e) = build_and_post(&target, &registry, &resource_attrs, start_ns) {
            eprintln!("l4scope: otlp push failed: {e}");
        }
    });
    Ok(handle)
}

/// Push the current metrics once (used for a deterministic flush on shutdown and
/// for tests).
pub fn flush(
    registry: &Registry,
    cfg: &OtlpConfig,
    resource_attrs: &[(String, String)],
) -> Result<()> {
    let target = parse_target(cfg)?;
    build_and_post(&target, registry, resource_attrs, l4scope_core::now_nanos())
        .map_err(|e| Error::Io(std::io::Error::other(e)))
}

fn build_and_post(
    target: &Target,
    registry: &Registry,
    resource_attrs: &[(String, String)],
    start_ns: u64,
) -> std::result::Result<(), String> {
    let snap = registry.snapshot();
    let body = build_body(&snap, resource_attrs, start_ns, l4scope_core::now_nanos());
    post(target, &body)
}

fn parse_target(cfg: &OtlpConfig) -> Result<Target> {
    let ep = cfg.endpoint.trim();
    let rest = if let Some(r) = ep.strip_prefix("http://") {
        r
    } else if ep.starts_with("https://") {
        return Err(Error::Config(
            "otlp endpoint must be http:// (run a node-local Collector for TLS/cloud)".into(),
        ));
    } else {
        ep
    };
    // authority[/ignored-path]
    let authority = rest.split('/').next().unwrap_or(rest);
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse::<u16>().unwrap_or(4318)),
        None => (authority.to_string(), 4318),
    };
    if host.is_empty() {
        return Err(Error::Config("otlp endpoint has no host".into()));
    }
    let headers = cfg
        .headers
        .split(',')
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();
    Ok(Target { host, port, path: cfg.path.clone(), headers })
}

fn post(t: &Target, body: &str) -> std::result::Result<(), String> {
    let mut stream = TcpStream::connect((t.host.as_str(), t.port))
        .map_err(|e| format!("connect {}:{}: {e}", t.host, t.port))?;
    stream.set_write_timeout(Some(Duration::from_secs(5))).ok();
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();

    let mut req = String::new();
    req.push_str(&format!("POST {} HTTP/1.1\r\n", t.path));
    req.push_str(&format!("Host: {}:{}\r\n", t.host, t.port));
    req.push_str("Content-Type: application/json\r\n");
    req.push_str(&format!("Content-Length: {}\r\n", body.len()));
    for (k, v) in &t.headers {
        if !k.is_empty() {
            req.push_str(&format!("{k}: {v}\r\n"));
        }
    }
    req.push_str("Connection: close\r\n\r\n");

    stream.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
    stream.write_all(body.as_bytes()).map_err(|e| e.to_string())?;
    stream.flush().ok();

    // Read the status line to surface 4xx/5xx from the Collector.
    let mut buf = [0u8; 256];
    let n = stream.read(&mut buf).unwrap_or(0);
    if n > 0 {
        let line = String::from_utf8_lossy(&buf[..n]);
        if let Some(status) = line.split_whitespace().nth(1) {
            if !status.starts_with('2') {
                return Err(format!("collector returned HTTP {status}"));
            }
        }
    }
    Ok(())
}

// --- JSON assembly (OTLP/JSON proto mapping) ---------------------------------

fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c => o.push(c),
        }
    }
    o
}

fn attr_str(key: &str, val: &str) -> String {
    format!("{{\"key\":\"{}\",\"value\":{{\"stringValue\":\"{}\"}}}}", esc(key), esc(val))
}

fn attrs_array(pairs: &[(&str, &str)]) -> String {
    let items: Vec<String> = pairs.iter().map(|(k, v)| attr_str(k, v)).collect();
    format!("[{}]", items.join(","))
}

fn sum_dp_int(value: u64, start_ns: u64, now_ns: u64, attrs: &str) -> String {
    format!(
        "{{\"asInt\":\"{value}\",\"startTimeUnixNano\":\"{start_ns}\",\"timeUnixNano\":\"{now_ns}\",\"attributes\":{attrs}}}"
    )
}

fn gauge_dp_int(value: u64, now_ns: u64) -> String {
    format!("{{\"asInt\":\"{value}\",\"timeUnixNano\":\"{now_ns}\",\"attributes\":[]}}")
}

fn gauge_dp_double(value: f64, now_ns: u64) -> String {
    format!("{{\"asDouble\":{value},\"timeUnixNano\":\"{now_ns}\",\"attributes\":[]}}")
}

fn metric_sum(name: &str, unit: &str, dps: &[String]) -> String {
    format!(
        "{{\"name\":\"{name}\",\"unit\":\"{unit}\",\"sum\":{{\"aggregationTemporality\":2,\"isMonotonic\":true,\"dataPoints\":[{}]}}}}",
        dps.join(",")
    )
}

fn metric_gauge(name: &str, unit: &str, dps: &[String]) -> String {
    format!(
        "{{\"name\":\"{name}\",\"unit\":\"{unit}\",\"gauge\":{{\"dataPoints\":[{}]}}}}",
        dps.join(",")
    )
}

fn build_body(
    snap: &MetricsSnapshot,
    resource_attrs: &[(String, String)],
    start_ns: u64,
    now_ns: u64,
) -> String {
    let mut metrics: Vec<String> = Vec::new();

    // packets (node-level)
    metrics.push(metric_sum(
        "l4scope.packets",
        "1",
        &[sum_dp_int(snap.packets_total, start_ns, now_ns, "[]")],
    ));

    // events by kind/severity (node-level)
    let ev_dps: Vec<String> = snap
        .event_counts
        .iter()
        .map(|&(k, s, n)| {
            sum_dp_int(n, start_ns, now_ns, &attrs_array(&[("l4.kind", k), ("severity", s)]))
        })
        .collect();
    if !ev_dps.is_empty() {
        metrics.push(metric_sum("l4scope.events", "1", &ev_dps));
    }

    // pod-level events
    let pod_ev_dps: Vec<String> = snap
        .pod_event_counts
        .iter()
        .map(|(ip, k, s, n)| {
            sum_dp_int(
                *n,
                start_ns,
                now_ns,
                &attrs_array(&[("k8s.pod.ip", ip.as_str()), ("l4.kind", *k), ("severity", *s)]),
            )
        })
        .collect();
    if !pod_ev_dps.is_empty() {
        metrics.push(metric_sum("l4scope.pod.events", "1", &pod_ev_dps));
    }

    // pod-level packets
    let pod_pkt_dps: Vec<String> = snap
        .pod_packets
        .iter()
        .map(|(ip, n)| sum_dp_int(*n, start_ns, now_ns, &attrs_array(&[("k8s.pod.ip", ip.as_str())])))
        .collect();
    if !pod_pkt_dps.is_empty() {
        metrics.push(metric_sum("l4scope.pod.packets", "1", &pod_pkt_dps));
    }

    // node-level gauges
    metrics.push(metric_gauge("l4scope.active_flows", "1", &[gauge_dp_int(snap.active_flows, now_ns)]));
    metrics.push(metric_gauge("l4scope.half_open_max", "1", &[gauge_dp_int(snap.half_open_max, now_ns)]));
    metrics.push(metric_gauge(
        "l4scope.rst_per_second",
        "1/s",
        &[gauge_dp_double(snap.rst_per_sec, now_ns)],
    ));
    metrics.push(metric_gauge(
        "l4scope.new_flows_per_second",
        "1/s",
        &[gauge_dp_double(snap.new_flow_per_sec, now_ns)],
    ));

    let res_attr_items: Vec<String> =
        resource_attrs.iter().map(|(k, v)| attr_str(k, v)).collect();

    let _ = NS_PER_SEC; // available for future unit conversions
    format!(
        "{{\"resourceMetrics\":[{{\"resource\":{{\"attributes\":[{}]}},\"scopeMetrics\":[{{\"scope\":{{\"name\":\"l4scope\",\"version\":\"0.1.0\"}},\"metrics\":[{}]}}]}}]}}",
        res_attr_items.join(","),
        metrics.join(",")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::MetricsSnapshot;

    fn braces_balanced(s: &str) -> bool {
        let mut depth = 0i32;
        for c in s.chars() {
            match c {
                '{' | '[' => depth += 1,
                '}' | ']' => depth -= 1,
                _ => {}
            }
            if depth < 0 {
                return false;
            }
        }
        depth == 0
    }

    #[test]
    fn build_body_is_well_formed() {
        let snap = MetricsSnapshot {
            packets_total: 100,
            events_total: 2,
            event_counts: vec![("retransmission", "warning", 2)],
            pod_event_counts: vec![("10.244.0.5".to_string(), "zero_window", "warning", 1)],
            pod_packets: vec![("10.244.0.5".to_string(), 50)],
            active_flows: 4,
            half_open_max: 1,
            rst_per_sec: 0.0,
            new_flow_per_sec: 3.0,
        };
        let attrs = vec![
            ("service.name".to_string(), "l4scope".to_string()),
            ("k8s.node.name".to_string(), "node-1".to_string()),
        ];
        let body = build_body(&snap, &attrs, 1, 2);
        assert!(braces_balanced(&body), "JSON braces/brackets balanced");
        assert!(body.contains("\"resourceMetrics\""));
        assert!(body.contains("l4scope.events"));
        assert!(body.contains("l4scope.pod.events"));
        assert!(body.contains("\"k8s.pod.ip\""));
        assert!(body.contains("\"aggregationTemporality\":2"));
        assert!(body.contains("k8s.node.name"));
    }

    #[test]
    fn https_endpoint_is_rejected() {
        let mut cfg = l4scope_core::config::Config::default().otlp;
        cfg.endpoint = "https://example:4318".to_string();
        assert!(parse_target(&cfg).is_err());
    }
}
