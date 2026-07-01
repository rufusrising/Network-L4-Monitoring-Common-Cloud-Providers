//! Zero-copy-ish header parsing: link layer -> IPv4/IPv6 -> TCP/UDP -> PacketMeta.
//!
//! Deliberately tolerant: on any truncated/unknown packet we return `None`
//! rather than erroring, because capture streams routinely contain frames we do
//! not care about. Only structural stream errors abort the pipeline.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use l4scope_core::types::{Direction, Endpoint, FlowKey, PacketMeta, Protocol, TcpFlags};

// Common DLT / LINKTYPE values.
pub const DLT_EN10MB: u32 = 1; // Ethernet II
pub const DLT_RAW: u32 = 101; // raw IP
pub const DLT_LINUX_SLL: u32 = 113; // Linux "cooked" v1
pub const DLT_NULL: u32 = 0; // BSD loopback (4-byte family header)

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;
const ETH_P_VLAN: u16 = 0x8100;
const ETH_P_QINQ: u16 = 0x88A8;

const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

#[inline]
fn be16(b: &[u8]) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(0)?, *b.get(1)?]))
}
#[inline]
fn be32(b: &[u8]) -> Option<u32> {
    Some(u32::from_be_bytes([*b.get(0)?, *b.get(1)?, *b.get(2)?, *b.get(3)?]))
}

/// Parse a full link-layer frame into a normalized [`PacketMeta`].
pub fn parse_frame(linktype: u32, data: &[u8], ts_nanos: u64, iface: u32) -> Option<PacketMeta> {
    let (ethertype, l3) = strip_link(linktype, data)?;
    match ethertype {
        ETH_P_IP => parse_ipv4(l3, ts_nanos, iface),
        ETH_P_IPV6 => parse_ipv6(l3, ts_nanos, iface),
        _ => None,
    }
}

/// Remove the link-layer header and return the L3 ethertype plus the L3 slice.
fn strip_link(linktype: u32, data: &[u8]) -> Option<(u16, &[u8])> {
    match linktype {
        DLT_EN10MB => {
            let mut off = 12usize;
            let mut et = be16(data.get(off..)?)?;
            off += 2;
            // Walk one or two VLAN/QinQ tags.
            for _ in 0..2 {
                if et == ETH_P_VLAN || et == ETH_P_QINQ {
                    et = be16(data.get(off + 2..)?)?;
                    off += 4;
                } else {
                    break;
                }
            }
            Some((et, data.get(off..)?))
        }
        DLT_LINUX_SLL => {
            // 16-byte cooked header; ethertype at offset 14.
            let et = be16(data.get(14..)?)?;
            Some((et, data.get(16..)?))
        }
        DLT_RAW => {
            let v = data.first()? >> 4;
            match v {
                4 => Some((ETH_P_IP, data)),
                6 => Some((ETH_P_IPV6, data)),
                _ => None,
            }
        }
        DLT_NULL => {
            // 4-byte host-endian address family; detect by IP version nibble.
            let v = data.get(4)? >> 4;
            match v {
                4 => Some((ETH_P_IP, data.get(4..)?)),
                6 => Some((ETH_P_IPV6, data.get(4..)?)),
                _ => None,
            }
        }
        _ => None,
    }
}

fn parse_ipv4(d: &[u8], ts_nanos: u64, iface: u32) -> Option<PacketMeta> {
    if d.len() < 20 {
        return None;
    }
    let ihl = ((d[0] & 0x0f) as usize) * 4;
    if ihl < 20 || d.len() < ihl {
        return None;
    }
    let total_len = be16(&d[2..])? as usize;
    let proto = d[9];
    let ttl = d[8];
    let src = IpAddr::V4(Ipv4Addr::new(d[12], d[13], d[14], d[15]));
    let dst = IpAddr::V4(Ipv4Addr::new(d[16], d[17], d[18], d[19]));
    // Payload length reported by IP, clamped to what we actually captured.
    let ip_payload = total_len.saturating_sub(ihl).min(d.len() - ihl);
    let l4 = &d[ihl..];
    finish(proto, src, dst, ttl, l4, ip_payload, ts_nanos, iface)
}

fn parse_ipv6(d: &[u8], ts_nanos: u64, iface: u32) -> Option<PacketMeta> {
    if d.len() < 40 {
        return None;
    }
    let payload_len = be16(&d[4..])? as usize;
    let mut next = d[6];
    let ttl = d[7]; // hop limit
    let mut src_o = [0u8; 16];
    let mut dst_o = [0u8; 16];
    src_o.copy_from_slice(&d[8..24]);
    dst_o.copy_from_slice(&d[24..40]);
    let src = IpAddr::V6(Ipv6Addr::from(src_o));
    let dst = IpAddr::V6(Ipv6Addr::from(dst_o));

    // Walk a bounded number of extension headers to reach L4.
    let mut off = 40usize;
    let end = (40 + payload_len).min(d.len());
    for _ in 0..8 {
        match next {
            IPPROTO_TCP | IPPROTO_UDP => break,
            0 | 43 | 60 | 51 => {
                // Hop-by-hop / Routing / Dest-opts / AH: (next, hdr_ext_len).
                let hdr = d.get(off..off + 2)?;
                next = hdr[0];
                let len = if next == 51 {
                    (hdr[1] as usize + 2) * 4 // AH length is in 4-byte units + 2
                } else {
                    (hdr[1] as usize + 1) * 8
                };
                off += len;
            }
            44 => {
                // Fragment header is fixed 8 bytes; only first fragment has L4.
                next = *d.get(off)?;
                off += 8;
            }
            _ => return None,
        }
        if off >= end {
            return None;
        }
    }
    let l4 = d.get(off..)?;
    let l4_payload = end.saturating_sub(off);
    finish(next, src, dst, ttl, l4, l4_payload, ts_nanos, iface)
}

#[allow(clippy::too_many_arguments)]
fn finish(
    proto_num: u8,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    ttl: u8,
    l4: &[u8],
    ip_payload_len: usize,
    ts_nanos: u64,
    iface: u32,
) -> Option<PacketMeta> {
    match proto_num {
        IPPROTO_TCP => {
            if l4.len() < 20 {
                return None;
            }
            let sport = be16(&l4[0..])?;
            let dport = be16(&l4[2..])?;
            let seq = be32(&l4[4..])?;
            let ack = be32(&l4[8..])?;
            let data_off = ((l4[12] >> 4) as usize) * 4;
            if data_off < 20 {
                return None;
            }
            let flags = TcpFlags(l4[13] & 0x3f);
            let window = be16(&l4[14..])? as u32;
            let payload_len = ip_payload_len.saturating_sub(data_off) as u32;
            Some(build(
                src_ip, sport, dst_ip, dport, Protocol::Tcp, flags, seq, ack, window,
                payload_len, ttl, ts_nanos, iface,
            ))
        }
        IPPROTO_UDP => {
            if l4.len() < 8 {
                return None;
            }
            let sport = be16(&l4[0..])?;
            let dport = be16(&l4[2..])?;
            let ulen = be16(&l4[4..])? as u32;
            let payload_len = ulen.saturating_sub(8);
            Some(build(
                src_ip, sport, dst_ip, dport, Protocol::Udp, TcpFlags(0), 0, 0, 0,
                payload_len, ttl, ts_nanos, iface,
            ))
        }
        _ => None,
    }
}

#[allow(clippy::too_many_arguments)]
fn build(
    src_ip: IpAddr,
    sport: u16,
    dst_ip: IpAddr,
    dport: u16,
    proto: Protocol,
    flags: TcpFlags,
    seq: u32,
    ack: u32,
    window: u32,
    payload_len: u32,
    ttl: u8,
    ts_nanos: u64,
    iface: u32,
) -> PacketMeta {
    let src = Endpoint::new(src_ip, sport);
    let dst = Endpoint::new(dst_ip, dport);
    let (key, dir): (FlowKey, Direction) = FlowKey::canonical(src, dst, proto);
    PacketMeta {
        ts_nanos,
        key,
        dir,
        proto,
        flags,
        seq,
        ack,
        window,
        payload_len,
        ttl,
        iface,
    }
}
