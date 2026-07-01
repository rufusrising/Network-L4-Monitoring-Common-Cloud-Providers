//! Pod-level attribution: map a flow to the local pod IP by testing its
//! endpoints against the node's pod CIDR(s). Keeps pod resolution in the agent
//! (std-only) while the OTel Collector's `k8sattributes` processor turns
//! `k8s.pod.ip` into pod/namespace/workload metadata.

use std::net::IpAddr;

use l4scope_core::types::FlowKey;

/// Longest-prefix-free CIDR set for classifying "is this a local pod IP?".
pub struct PodMatcher {
    cidrs: Vec<(IpAddr, u32)>,
}

impl PodMatcher {
    /// Parse a comma-separated CIDR list, e.g. "10.244.0.0/16, fd00::/48".
    /// Invalid entries are skipped.
    pub fn new(spec: &str) -> Self {
        let mut cidrs = Vec::new();
        for part in spec.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            if let Some((net, pfx)) = part.split_once('/') {
                if let (Ok(ip), Ok(p)) = (net.trim().parse::<IpAddr>(), pfx.trim().parse::<u32>()) {
                    cidrs.push((ip, p));
                }
            }
        }
        PodMatcher { cidrs }
    }

    pub fn is_empty(&self) -> bool {
        self.cidrs.is_empty()
    }

    /// Return the flow endpoint IP that lies within a pod CIDR, as a string.
    pub fn local_pod_ip(&self, key: &FlowKey) -> Option<String> {
        for ep in [key.low, key.high] {
            if self.contains(ep.ip) {
                return Some(ep.ip.to_string());
            }
        }
        None
    }

    fn contains(&self, ip: IpAddr) -> bool {
        self.cidrs.iter().any(|(net, pfx)| cidr_contains(*net, *pfx, ip))
    }
}

fn cidr_contains(net: IpAddr, prefix: u32, ip: IpAddr) -> bool {
    match (net, ip) {
        (IpAddr::V4(n), IpAddr::V4(a)) => {
            if prefix > 32 {
                return false;
            }
            let mask: u32 = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
            (u32::from(n) & mask) == (u32::from(a) & mask)
        }
        (IpAddr::V6(n), IpAddr::V6(a)) => {
            if prefix > 128 {
                return false;
            }
            let mask: u128 = if prefix == 0 { 0 } else { u128::MAX << (128 - prefix) };
            (u128::from(n) & mask) == (u128::from(a) & mask)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use l4scope_core::types::{Endpoint, FlowKey, Protocol};
    use std::net::{IpAddr, Ipv4Addr};

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn matches_pod_endpoint_in_cidr() {
        let m = PodMatcher::new("10.244.0.0/16, 192.168.0.0/24");
        let pod = Endpoint::new(ip("10.244.5.7"), 5000);
        let peer = Endpoint::new(ip("8.8.8.8"), 443);
        let (key, _) = FlowKey::canonical(pod, peer, Protocol::Tcp);
        assert_eq!(m.local_pod_ip(&key).as_deref(), Some("10.244.5.7"));
    }

    #[test]
    fn no_match_outside_cidr() {
        let m = PodMatcher::new("10.244.0.0/16");
        let a = Endpoint::new(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)), 1);
        let b = Endpoint::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 2);
        let (key, _) = FlowKey::canonical(a, b, Protocol::Tcp);
        assert!(m.local_pod_ip(&key).is_none());
    }

    #[test]
    fn empty_and_invalid_specs() {
        assert!(PodMatcher::new("").is_empty());
        assert!(PodMatcher::new("garbage,10/x").is_empty());
    }
}
