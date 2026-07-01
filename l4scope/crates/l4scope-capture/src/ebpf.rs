//! Native eBPF/CO-RE capture backend (Linux). Compiled only with `--features
//! ebpf`. Loads the CO-RE program (`bpf/l4scope.bpf.c`, compiled by `build.rs`),
//! attaches it to the interface's TC ingress+egress hooks, and reads fixed-size
//! `BpfL4Event` records from a ring buffer — decoding each into the same
//! [`PacketMeta`] every other backend produces.
//!
//! Tested against `aya` 0.13. Because this crate cannot be compiled in every
//! environment (needs clang, libbpf, and a generated `bpf/vmlinux.h`), treat the
//! first `cargo build --features ebpf` as a compile-and-verify step.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::AsRawFd;

use aya::maps::RingBuf;
use aya::programs::{tc, SchedClassifier, TcAttachType};
use aya::{include_bytes_aligned, Ebpf};

use l4scope_core::config::CaptureConfig;
use l4scope_core::error::{Error, Result};
use l4scope_core::types::{Endpoint, FlowKey, PacketMeta, Protocol, TcpFlags};

use crate::CaptureSource;

/// On-wire record the BPF program writes to the ring buffer. `#[repr(C)]` so the
/// kernel and userspace agree byte-for-byte. Field order/size mirror the C
/// `struct l4_event` in `bpf/l4scope.bpf.c`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct BpfL4Event {
    pub ts_nanos: u64, // CLOCK_MONOTONIC (converted to wall clock in userspace)
    pub saddr: [u8; 16],
    pub daddr: [u8; 16],
    pub sport: u16,
    pub dport: u16,
    pub seq: u32,
    pub ack: u32,
    pub window: u32,
    pub payload_len: u32,
    pub family: u8, // 4 or 6
    pub proto: u8,  // 6=tcp, 17=udp
    pub flags: u8,  // TCP flags byte
    pub ttl: u8,
    pub iface: u32,
}

// Object emitted by build.rs when the `ebpf` feature is enabled.
static PROG_OBJ: &[u8] = include_bytes_aligned!(concat!(env!("OUT_DIR"), "/l4scope.bpf.o"));

pub struct EbpfSource {
    name: String,
    // Keep the loaded program alive so the TC hooks stay attached.
    _ebpf: Ebpf,
    ring: RingBuf<aya::maps::MapData>,
    // realtime - monotonic, in ns; converts BPF ktime to wall clock.
    wall_offset_ns: u64,
}

pub fn open(cfg: &CaptureConfig) -> Result<Box<dyn CaptureSource>> {
    let iface = if cfg.interface.trim().is_empty() {
        "eth0".to_string()
    } else {
        cfg.interface.clone()
    };

    let mut ebpf = Ebpf::load(PROG_OBJ)
        .map_err(|e| Error::UnsupportedBackend(format!("failed to load BPF object: {e}")))?;

    let program: &mut SchedClassifier = ebpf
        .program_mut("l4scope_tc")
        .ok_or_else(|| Error::UnsupportedBackend("program l4scope_tc not found".into()))?
        .try_into()
        .map_err(|e| Error::UnsupportedBackend(format!("not a SchedClassifier: {e}")))?;
    program
        .load()
        .map_err(|e| Error::UnsupportedBackend(format!("program load failed: {e}")))?;

    // Ensure the clsact qdisc exists (ignore "already exists").
    let _ = tc::qdisc_add_clsact(&iface);
    program
        .attach(&iface, TcAttachType::Ingress)
        .map_err(|e| Error::UnsupportedBackend(format!("attach ingress on {iface}: {e}")))?;
    program
        .attach(&iface, TcAttachType::Egress)
        .map_err(|e| Error::UnsupportedBackend(format!("attach egress on {iface}: {e}")))?;

    let ring = RingBuf::try_from(
        ebpf.take_map("events")
            .ok_or_else(|| Error::UnsupportedBackend("ring buffer map 'events' not found".into()))?,
    )
    .map_err(|e| Error::UnsupportedBackend(format!("ring buffer open failed: {e}")))?;

    Ok(Box::new(EbpfSource {
        name: format!("ebpf:{iface}"),
        _ebpf: ebpf,
        ring,
        wall_offset_ns: wall_offset_ns(),
    }))
}

impl CaptureSource for EbpfSource {
    fn name(&self) -> &str {
        &self.name
    }

    fn next_packet(&mut self) -> Result<Option<PacketMeta>> {
        loop {
            if let Some(item) = self.ring.next() {
                let bytes: &[u8] = &item;
                if bytes.len() >= std::mem::size_of::<BpfL4Event>() {
                    // SAFETY: the kernel writes a `BpfL4Event` and we checked length.
                    let ev: BpfL4Event =
                        unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const BpfL4Event) };
                    if let Some(pkt) = self.decode(&ev) {
                        return Ok(Some(pkt));
                    }
                }
                continue; // short/undecodable record — skip
            }
            // Ring empty: block until the fd is readable, then retry.
            self.poll_readable()?;
        }
    }
}

impl EbpfSource {
    fn decode(&self, ev: &BpfL4Event) -> Option<PacketMeta> {
        let proto = match ev.proto {
            6 => Protocol::Tcp,
            17 => Protocol::Udp,
            _ => return None,
        };
        let (src_ip, dst_ip) = match ev.family {
            4 => (
                IpAddr::V4(Ipv4Addr::new(ev.saddr[0], ev.saddr[1], ev.saddr[2], ev.saddr[3])),
                IpAddr::V4(Ipv4Addr::new(ev.daddr[0], ev.daddr[1], ev.daddr[2], ev.daddr[3])),
            ),
            6 => (IpAddr::V6(Ipv6Addr::from(ev.saddr)), IpAddr::V6(Ipv6Addr::from(ev.daddr))),
            _ => return None,
        };
        let src = Endpoint::new(src_ip, ev.sport);
        let dst = Endpoint::new(dst_ip, ev.dport);
        let (key, dir) = FlowKey::canonical(src, dst, proto);
        Some(PacketMeta {
            ts_nanos: self.wall_offset_ns.wrapping_add(ev.ts_nanos),
            key,
            dir,
            proto,
            flags: TcpFlags(ev.flags),
            seq: ev.seq,
            ack: ev.ack,
            window: ev.window,
            payload_len: ev.payload_len,
            ttl: ev.ttl,
            iface: ev.iface,
        })
    }

    fn poll_readable(&self) -> Result<()> {
        let mut pfd = libc::pollfd {
            fd: self.ring.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // 1s timeout so callers can still make progress / shut down.
        let rc = unsafe { libc::poll(&mut pfd as *mut libc::pollfd, 1, 1000) };
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                return Ok(());
            }
            return Err(Error::Io(err));
        }
        Ok(())
    }
}

/// realtime - monotonic (ns): add to a CLOCK_MONOTONIC value to get wall time.
fn wall_offset_ns() -> u64 {
    unsafe {
        let mut mono: libc::timespec = std::mem::zeroed();
        let mut real: libc::timespec = std::mem::zeroed();
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut mono);
        libc::clock_gettime(libc::CLOCK_REALTIME, &mut real);
        let mono_ns = (mono.tv_sec as u64) * 1_000_000_000 + mono.tv_nsec as u64;
        let real_ns = (real.tv_sec as u64) * 1_000_000_000 + real.tv_nsec as u64;
        real_ns.wrapping_sub(mono_ns)
    }
}
