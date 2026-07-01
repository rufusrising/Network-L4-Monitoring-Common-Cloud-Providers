//! `l4scope-capture` — the pluggable capture layer.
//!
//! Every backend implements [`CaptureSource`] and yields normalized
//! [`PacketMeta`] records, giving the detection engine identical input whether
//! packets come from a pcap file, a live `tcpdump`/`tshark` process, native
//! eBPF, or Windows ETW. This is the "parity" contract: add a backend, get all
//! detectors for free.

use std::fs::File;
use std::io::{BufReader, Read};
use std::process::Child;

use l4scope_core::config::{Backend, CaptureConfig};
use l4scope_core::error::{Error, Result};
use l4scope_core::types::PacketMeta;

mod live;
mod parse;
mod pcapio;
mod synthetic;

#[cfg(all(feature = "ebpf", target_os = "linux"))]
pub mod ebpf;
#[cfg(all(feature = "etw", target_os = "windows"))]
pub mod etw;

pub use pcapio::PcapStream;
pub use synthetic::SyntheticSource;

/// A pull-based source of normalized packets. `next_packet` returns `Ok(None)`
/// at end of stream (file replay / synthetic) and blocks for live sources.
pub trait CaptureSource: Send {
    /// Stable identifier for logs/metrics (e.g. `"pcap_file"`, `"live:tcpdump"`).
    fn name(&self) -> &str;
    /// Next packet, `Ok(None)` at clean end of stream.
    fn next_packet(&mut self) -> Result<Option<PacketMeta>>;
}

/// Generic pcap-stream source used by both file replay and the live backend.
pub struct PcapSource<R: Read + Send + 'static> {
    name: String,
    stream: PcapStream<R>,
    // Keeps the capture child process alive for the live backend; killed on drop.
    _child: Option<Child>,
}

impl<R: Read + Send + 'static> PcapSource<R> {
    pub fn from_reader(
        name: String,
        reader: R,
        iface: u32,
        child: Option<Child>,
    ) -> Result<Self> {
        let stream = PcapStream::new(reader, iface)?;
        Ok(PcapSource { name, stream, _child: child })
    }
}

impl<R: Read + Send + 'static> Drop for PcapSource<R> {
    fn drop(&mut self) {
        if let Some(child) = self._child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl<R: Read + Send + 'static> CaptureSource for PcapSource<R> {
    fn name(&self) -> &str {
        &self.name
    }
    fn next_packet(&mut self) -> Result<Option<PacketMeta>> {
        self.stream.next_packet()
    }
}

/// Construct the configured capture backend. This is the single dispatch point
/// that maps `config` + build features + platform to a concrete source.
pub fn open(cfg: &CaptureConfig) -> Result<Box<dyn CaptureSource>> {
    match cfg.backend {
        Backend::Synthetic => Ok(Box::new(SyntheticSource::new())),

        Backend::PcapFile => {
            if cfg.pcap_path.trim().is_empty() {
                return Err(Error::Config("pcap_file backend needs capture.pcap_path".into()));
            }
            let file = File::open(&cfg.pcap_path)
                .map_err(|e| Error::Config(format!("cannot open {}: {e}", cfg.pcap_path)))?;
            let source = PcapSource::from_reader(
                format!("pcap_file:{}", cfg.pcap_path),
                BufReader::new(file),
                0,
                None,
            )?;
            Ok(Box::new(source))
        }

        Backend::Live => live::open_live(cfg),

        Backend::Ebpf => open_ebpf(cfg),
        Backend::Etw => open_etw(cfg),
    }
}

#[cfg(all(feature = "ebpf", target_os = "linux"))]
fn open_ebpf(cfg: &CaptureConfig) -> Result<Box<dyn CaptureSource>> {
    ebpf::open(cfg)
}
#[cfg(not(all(feature = "ebpf", target_os = "linux")))]
fn open_ebpf(_cfg: &CaptureConfig) -> Result<Box<dyn CaptureSource>> {
    Err(Error::UnsupportedBackend(
        "ebpf backend not built in; rebuild on Linux with `--features l4scope-agent/ebpf` \
         (see docs/BUILD_NATIVE.md)"
            .into(),
    ))
}

#[cfg(all(feature = "etw", target_os = "windows"))]
fn open_etw(cfg: &CaptureConfig) -> Result<Box<dyn CaptureSource>> {
    etw::open(cfg)
}
#[cfg(not(all(feature = "etw", target_os = "windows")))]
fn open_etw(_cfg: &CaptureConfig) -> Result<Box<dyn CaptureSource>> {
    Err(Error::UnsupportedBackend(
        "etw backend not built in; rebuild on Windows with `--features l4scope-agent/etw` \
         (see docs/BUILD_NATIVE.md)"
            .into(),
    ))
}
