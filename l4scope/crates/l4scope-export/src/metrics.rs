//! In-memory metrics registry with node-level and (optional) pod-level series.
//! Renders Prometheus text and provides a snapshot for the OTLP exporter.
//! Dependency-free (std only). Shared across threads via `Registry`.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use l4scope_core::types::L4Event;

#[derive(Default)]
struct Metrics {
    packets_total: u64,
    events_total: u64,
    // node-level: (kind, severity) -> count
    event_counts: BTreeMap<(&'static str, &'static str), u64>,
    // pod-level: (pod_ip, kind, severity) -> count
    pod_event_counts: BTreeMap<(String, &'static str, &'static str), u64>,
    // pod-level: pod_ip -> packets
    pod_packets: BTreeMap<String, u64>,
    active_flows: u64,
    half_open_max: u64,
    rst_per_sec: f64,
    new_flow_per_sec: f64,
}

/// A consistent copy of the registry for the OTLP exporter.
pub struct MetricsSnapshot {
    pub packets_total: u64,
    pub events_total: u64,
    pub event_counts: Vec<(&'static str, &'static str, u64)>,
    pub pod_event_counts: Vec<(String, &'static str, &'static str, u64)>,
    pub pod_packets: Vec<(String, u64)>,
    pub active_flows: u64,
    pub half_open_max: u64,
    pub rst_per_sec: f64,
    pub new_flow_per_sec: f64,
}

/// Thread-safe, cloneable handle to the metrics registry.
#[derive(Clone)]
pub struct Registry {
    inner: Arc<Mutex<Metrics>>,
}

impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}

impl Registry {
    pub fn new() -> Self {
        Registry { inner: Arc::new(Mutex::new(Metrics::default())) }
    }

    pub fn record_packet(&self, pod_ip: Option<&str>) {
        if let Ok(mut m) = self.inner.lock() {
            m.packets_total += 1;
            if let Some(ip) = pod_ip {
                *m.pod_packets.entry(ip.to_string()).or_insert(0) += 1;
            }
        }
    }

    pub fn record_event(&self, ev: &L4Event, pod_ip: Option<&str>) {
        if let Ok(mut m) = self.inner.lock() {
            m.events_total += 1;
            let (k, s) = (ev.kind.as_str(), ev.severity.as_str());
            *m.event_counts.entry((k, s)).or_insert(0) += 1;
            if let Some(ip) = pod_ip {
                *m.pod_event_counts.entry((ip.to_string(), k, s)).or_insert(0) += 1;
            }
        }
    }

    pub fn set_gauges(
        &self,
        active_flows: u64,
        half_open_max: u64,
        rst_per_sec: f64,
        new_flow_per_sec: f64,
    ) {
        if let Ok(mut m) = self.inner.lock() {
            m.active_flows = active_flows;
            m.half_open_max = half_open_max;
            m.rst_per_sec = rst_per_sec;
            m.new_flow_per_sec = new_flow_per_sec;
        }
    }

    /// Snapshot for the OTLP exporter.
    pub fn snapshot(&self) -> MetricsSnapshot {
        let m = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        MetricsSnapshot {
            packets_total: m.packets_total,
            events_total: m.events_total,
            event_counts: m.event_counts.iter().map(|(&(k, s), &n)| (k, s, n)).collect(),
            pod_event_counts: m
                .pod_event_counts
                .iter()
                .map(|((ip, k, s), &n)| (ip.clone(), *k, *s, n))
                .collect(),
            pod_packets: m.pod_packets.iter().map(|(ip, &n)| (ip.clone(), n)).collect(),
            active_flows: m.active_flows,
            half_open_max: m.half_open_max,
            rst_per_sec: m.rst_per_sec,
            new_flow_per_sec: m.new_flow_per_sec,
        }
    }

    /// Render the current metrics in Prometheus text exposition format.
    pub fn render_prometheus(&self) -> String {
        let m = match self.inner.lock() {
            Ok(m) => m,
            Err(_) => return String::from("# metrics unavailable\n"),
        };
        let mut s = String::new();

        s.push_str("# HELP l4scope_packets_total Packets processed by the engine.\n");
        s.push_str("# TYPE l4scope_packets_total counter\n");
        s.push_str(&format!("l4scope_packets_total {}\n", m.packets_total));

        s.push_str("# HELP l4scope_events_total L4 anomaly events emitted.\n");
        s.push_str("# TYPE l4scope_events_total counter\n");
        s.push_str(&format!("l4scope_events_total {}\n", m.events_total));

        s.push_str("# HELP l4scope_events Anomaly events by kind and severity.\n");
        s.push_str("# TYPE l4scope_events counter\n");
        for ((kind, sev), n) in m.event_counts.iter() {
            s.push_str(&format!("l4scope_events{{kind=\"{kind}\",severity=\"{sev}\"}} {n}\n"));
        }

        if !m.pod_event_counts.is_empty() {
            s.push_str("# HELP l4scope_pod_events Anomaly events by pod, kind and severity.\n");
            s.push_str("# TYPE l4scope_pod_events counter\n");
            for ((ip, kind, sev), n) in m.pod_event_counts.iter() {
                s.push_str(&format!(
                    "l4scope_pod_events{{pod_ip=\"{ip}\",kind=\"{kind}\",severity=\"{sev}\"}} {n}\n"
                ));
            }
            s.push_str("# HELP l4scope_pod_packets_total Packets processed per pod.\n");
            s.push_str("# TYPE l4scope_pod_packets_total counter\n");
            for (ip, n) in m.pod_packets.iter() {
                s.push_str(&format!("l4scope_pod_packets_total{{pod_ip=\"{ip}\"}} {n}\n"));
            }
        }

        s.push_str("# HELP l4scope_active_flows Flows currently tracked.\n");
        s.push_str("# TYPE l4scope_active_flows gauge\n");
        s.push_str(&format!("l4scope_active_flows {}\n", m.active_flows));

        s.push_str("# HELP l4scope_half_open_max Max concurrent half-open connections to one service.\n");
        s.push_str("# TYPE l4scope_half_open_max gauge\n");
        s.push_str(&format!("l4scope_half_open_max {}\n", m.half_open_max));

        s.push_str("# HELP l4scope_rst_per_second Host-wide TCP RST rate.\n");
        s.push_str("# TYPE l4scope_rst_per_second gauge\n");
        s.push_str(&format!("l4scope_rst_per_second {:.3}\n", m.rst_per_sec));

        s.push_str("# HELP l4scope_new_flows_per_second Host-wide new-flow rate.\n");
        s.push_str("# TYPE l4scope_new_flows_per_second gauge\n");
        s.push_str(&format!("l4scope_new_flows_per_second {:.3}\n", m.new_flow_per_sec));

        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use l4scope_core::types::{Endpoint, EventKind, FlowKey, L4Event, Protocol, Severity};
    use std::net::{IpAddr, Ipv4Addr};

    fn sample_event() -> L4Event {
        let a = Endpoint::new(IpAddr::V4(Ipv4Addr::new(10, 244, 0, 5)), 5000);
        let b = Endpoint::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9)), 80);
        let (k, _) = FlowKey::canonical(a, b, Protocol::Tcp);
        L4Event::new(1, EventKind::Retransmission, Severity::Warning, k, 0.5, "x")
    }

    #[test]
    fn records_and_renders() {
        let r = Registry::new();
        r.record_packet(Some("10.244.0.5"));
        r.record_event(&sample_event(), Some("10.244.0.5"));
        r.set_gauges(3, 7, 1.5, 2.0);

        let text = r.render_prometheus();
        assert!(text.contains("l4scope_events{kind=\"retransmission\",severity=\"warning\"} 1"));
        assert!(text.contains("l4scope_pod_events{pod_ip=\"10.244.0.5\""));
        assert!(text.contains("l4scope_active_flows 3"));

        let snap = r.snapshot();
        assert_eq!(snap.packets_total, 1);
        assert_eq!(snap.events_total, 1);
        assert_eq!(snap.pod_event_counts.len(), 1);
        assert_eq!(snap.half_open_max, 7);
    }
}
