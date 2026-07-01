//! Deterministic synthetic traffic generator. Emits a scripted packet sequence
//! that trips every detector, so `l4scope --demo` produces meaningful output
//! with zero setup and gives CI a stable golden input.

use std::net::{IpAddr, Ipv4Addr};

use l4scope_core::error::Result;
use l4scope_core::types::{Direction, Endpoint, FlowKey, PacketMeta, Protocol, TcpFlags};

use crate::CaptureSource;

pub struct SyntheticSource {
    packets: Vec<PacketMeta>,
    idx: usize,
}

impl SyntheticSource {
    pub fn new() -> Self {
        SyntheticSource { packets: build_script(), idx: 0 }
    }
}

impl Default for SyntheticSource {
    fn default() -> Self {
        Self::new()
    }
}

impl CaptureSource for SyntheticSource {
    fn name(&self) -> &str {
        "synthetic"
    }
    fn next_packet(&mut self) -> Result<Option<PacketMeta>> {
        if self.idx >= self.packets.len() {
            return Ok(None);
        }
        let p = self.packets[self.idx].clone();
        self.idx += 1;
        Ok(Some(p))
    }
}

const MS: u64 = 1_000_000;
const SEC: u64 = 1_000_000_000;

fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

/// Build a `PacketMeta` from an observed (src,dst) pair.
#[allow(clippy::too_many_arguments)]
fn pkt(
    ts: u64,
    src_ip: IpAddr,
    sport: u16,
    dst_ip: IpAddr,
    dport: u16,
    proto: Protocol,
    flags: u8,
    seq: u32,
    ack: u32,
    window: u32,
    payload_len: u32,
) -> PacketMeta {
    let src = Endpoint::new(src_ip, sport);
    let dst = Endpoint::new(dst_ip, dport);
    let (key, dir): (FlowKey, Direction) = FlowKey::canonical(src, dst, proto);
    PacketMeta {
        ts_nanos: ts,
        key,
        dir,
        proto,
        flags: TcpFlags(flags),
        seq,
        ack,
        window,
        payload_len,
        ttl: 64,
        iface: 0,
    }
}

fn build_script() -> Vec<PacketMeta> {
    let mut p = Vec::new();
    let t0 = 1_700_000_000u64 * SEC; // fixed epoch base for determinism
    let client = v4(10, 0, 0, 5);
    let server = v4(10, 0, 0, 9);
    let tcp = Protocol::Tcp;

    // 1) High-RTT handshake: SYN, then SYN-ACK 300ms later, then ACK.
    let cp = 40001u16;
    p.push(pkt(t0, client, cp, server, 443, tcp, TcpFlags::SYN, 1000, 0, 64240, 0));
    p.push(pkt(t0 + 300 * MS, server, 443, client, cp, tcp, TcpFlags::SYN | TcpFlags::ACK, 5000, 1001, 65160, 0));
    p.push(pkt(t0 + 305 * MS, client, cp, server, 443, tcp, TcpFlags::ACK, 1001, 5001, 64240, 0));

    // 2) Retransmissions on an established flow: same data segment sent 4x.
    let dp = 40002u16;
    let base = t0 + 400 * MS;
    p.push(pkt(base, client, dp, server, 80, tcp, TcpFlags::SYN, 2000, 0, 64240, 0));
    p.push(pkt(base + MS, server, 80, client, dp, tcp, TcpFlags::SYN | TcpFlags::ACK, 9000, 2001, 65160, 0));
    p.push(pkt(base + 2 * MS, client, dp, server, 80, tcp, TcpFlags::ACK, 2001, 9001, 64240, 0));
    // First transmission of a 200-byte segment, then 3 retransmits (seq unchanged).
    for i in 0..4u64 {
        p.push(pkt(
            base + (10 + i * 200) * MS,
            client, dp, server, 80, tcp,
            TcpFlags::ACK | TcpFlags::PSH, 2001, 9001, 64240, 200,
        ));
    }

    // 3) Duplicate ACKs from the server (3x same ack, no payload) => fast-retx sig.
    for i in 0..4u64 {
        p.push(pkt(
            base + (900 + i * 5) * MS,
            server, 80, client, dp, tcp, TcpFlags::ACK, 9001, 2201, 65160, 0,
        ));
    }

    // 4) Zero-window stall: receiver advertises window 0 on an established flow.
    let zp = 40003u16;
    let zt = t0 + 2 * SEC;
    p.push(pkt(zt, client, zp, server, 5432, tcp, TcpFlags::SYN, 3000, 0, 64240, 0));
    p.push(pkt(zt + MS, server, 5432, client, zp, tcp, TcpFlags::SYN | TcpFlags::ACK, 7000, 3001, 65160, 0));
    p.push(pkt(zt + 2 * MS, client, zp, server, 5432, tcp, TcpFlags::ACK, 3001, 7001, 64240, 0));
    p.push(pkt(zt + 50 * MS, client, zp, server, 5432, tcp, TcpFlags::ACK, 3001, 7001, 0, 0)); // window 0

    // 5) RST storm: a server refuses many clients within one second.
    let rt = t0 + 3 * SEC;
    for i in 0..40u32 {
        let cli = v4(10, 0, 1, (i % 250) as u8 + 1);
        let sp = 50000u16 + i as u16;
        // client SYN, server RST.
        p.push(pkt(rt + i as u64 * 10 * MS, cli, sp, server, 8080, tcp, TcpFlags::SYN, 4000 + i, 0, 64240, 0));
        p.push(pkt(rt + i as u64 * 10 * MS + MS, server, 8080, cli, sp, tcp, TcpFlags::RST | TcpFlags::ACK, 0, 4001 + i, 0, 0));
    }

    // 6) SYN backlog / handshake timeout: many half-open SYNs, no SYN-ACK.
    let st = t0 + 5 * SEC;
    for i in 0..80u32 {
        let cli = v4(10, 0, 2, (i % 250) as u8 + 1);
        let sp = 60000u16 + i as u16;
        p.push(pkt(st + i as u64 * MS, cli, sp, server, 3306, tcp, TcpFlags::SYN, 6000 + i, 0, 64240, 0));
    }
    // A late packet advances the clock so the sweep can flag timeouts.
    p.push(pkt(st + 10 * SEC, client, 40009, server, 22, tcp, TcpFlags::SYN, 7000, 0, 64240, 0));

    p
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthetic_yields_packets_starting_with_syn() {
        let mut src = SyntheticSource::new();
        let first = src.next_packet().unwrap().expect("at least one packet");
        assert!(first.flags.is_syn_only(), "script starts with a SYN");

        let mut count = 1;
        let mut saw_zero_window = false;
        while let Some(p) = src.next_packet().unwrap() {
            count += 1;
            if p.window == 0 {
                saw_zero_window = true;
            }
        }
        assert!(count > 100, "script exercises many flows, got {count}");
        assert!(saw_zero_window, "script includes a zero-window packet");
    }
}
