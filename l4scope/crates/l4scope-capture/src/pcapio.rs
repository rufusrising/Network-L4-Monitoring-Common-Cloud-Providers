//! Streaming reader for the classic pcap format (magic `a1b2c3d4`), shared by
//! the file-replay backend and the live `tcpdump`/`tshark` backend (both are the
//! same byte stream — one from a file, one from a child process stdout).

use std::io::Read;

use l4scope_core::error::{Error, Result};
use l4scope_core::types::PacketMeta;

use crate::parse;

const MAGIC_US_LE: u32 = 0xa1b2_c3d4; // microsecond, little-endian on-disk
const MAGIC_US_BE: u32 = 0xd4c3_b2a1;
const MAGIC_NS_LE: u32 = 0xa1b2_3c4d; // nanosecond
const MAGIC_NS_BE: u32 = 0x4d3c_b2a1;

pub struct PcapStream<R: Read> {
    inner: R,
    little: bool,
    nanos: bool,
    linktype: u32,
    iface: u32,
}

impl<R: Read> PcapStream<R> {
    /// Read and validate the 24-byte global header.
    pub fn new(mut inner: R, iface: u32) -> Result<Self> {
        let mut hdr = [0u8; 24];
        read_full(&mut inner, &mut hdr)?;
        let magic = u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
        let (little, nanos) = match magic {
            MAGIC_US_LE => (true, false),
            MAGIC_US_BE => (false, false),
            MAGIC_NS_LE => (true, true),
            MAGIC_NS_BE => (false, true),
            other => {
                return Err(Error::Parse(format!("not a pcap stream (magic {other:#010x})")))
            }
        };
        let linktype = read_u32(&hdr[20..24], little);
        Ok(PcapStream { inner, little, nanos, linktype, iface })
    }

    pub fn linktype(&self) -> u32 {
        self.linktype
    }

    /// Return the next parsed packet, `Ok(None)` at clean end-of-stream, or an
    /// error on a structurally broken record. Frames we do not care about
    /// (non-IP, truncated L4) are skipped internally.
    pub fn next_packet(&mut self) -> Result<Option<PacketMeta>> {
        loop {
            let mut rec = [0u8; 16];
            match read_full_opt(&mut self.inner, &mut rec)? {
                false => return Ok(None), // EOF between records = clean end
                true => {}
            }
            let ts_sec = read_u32(&rec[0..4], self.little) as u64;
            let ts_frac = read_u32(&rec[4..8], self.little) as u64;
            let incl_len = read_u32(&rec[8..12], self.little) as usize;
            if incl_len > 262_144 {
                return Err(Error::Parse(format!("implausible record length {incl_len}")));
            }
            let mut buf = vec![0u8; incl_len];
            read_full(&mut self.inner, &mut buf)?;

            let ts_nanos = ts_sec
                .saturating_mul(1_000_000_000)
                .saturating_add(if self.nanos { ts_frac } else { ts_frac * 1_000 });

            if let Some(pkt) = parse::parse_frame(self.linktype, &buf, ts_nanos, self.iface) {
                return Ok(Some(pkt));
            }
            // else: uninteresting frame, keep reading.
        }
    }
}

fn read_u32(b: &[u8], little: bool) -> u32 {
    let a = [b[0], b[1], b[2], b[3]];
    if little {
        u32::from_le_bytes(a)
    } else {
        u32::from_be_bytes(a)
    }
}

/// Read exactly `buf.len()` bytes or error.
fn read_full<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<()> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) => return Err(Error::Parse("unexpected end of pcap stream".into())),
            Ok(k) => n += k,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(Error::Io(e)),
        }
    }
    Ok(())
}

/// Like `read_full`, but a clean EOF *before any byte* returns `Ok(false)`.
fn read_full_opt<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<bool> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) => {
                if n == 0 {
                    return Ok(false);
                }
                return Err(Error::Parse("truncated pcap record header".into()));
            }
            Ok(k) => n += k,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(Error::Io(e)),
        }
    }
    Ok(true)
}
