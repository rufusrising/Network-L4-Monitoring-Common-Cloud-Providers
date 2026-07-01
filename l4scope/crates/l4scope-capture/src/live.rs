//! Live capture without FFI: spawn the platform's packet tool with a pcap
//! stream on stdout and parse it through the shared [`PcapStream`] reader.
//!
//!   Linux / macOS : `tcpdump -i <if> -w - -U -n -s 256 <filter>`
//!   Windows       : `tshark  -i <if> -w - -F pcap -s 256 -f "<filter>"`
//!
//! This gives a genuinely cross-platform live backend that works the moment the
//! standard tool is installed, and keeps L4Scope decoupled from any one capture
//! library. The eBPF and ETW backends (see `ebpf.rs`/`etw.rs`) are the native,
//! higher-performance alternatives selected via config + build features.

use std::io::BufReader;
use std::process::{Child, Command, Stdio};

use l4scope_core::config::CaptureConfig;
use l4scope_core::error::{Error, Result};

use crate::{PcapSource, CaptureSource};

/// Build the default argv for the current OS.
fn default_command(iface: &str, filter: &str) -> Vec<String> {
    let iface = if iface.is_empty() { "any" } else { iface };
    if cfg!(target_os = "windows") {
        let mut v = vec![
            "tshark".into(), "-i".into(), iface.into(),
            "-w".into(), "-".into(), "-F".into(), "pcap".into(),
            "-s".into(), "256".into(),
        ];
        if !filter.is_empty() {
            v.push("-f".into());
            v.push(filter.into());
        }
        v
    } else {
        let mut v = vec![
            "tcpdump".into(), "-i".into(), iface.into(),
            "-w".into(), "-".into(), "-U".into(), "-n".into(),
            "-s".into(), "256".into(),
        ];
        if !filter.is_empty() {
            // tcpdump takes the BPF filter as trailing expression tokens.
            for tok in filter.split_whitespace() {
                v.push(tok.into());
            }
        }
        v
    }
}

pub fn open_live(cfg: &CaptureConfig) -> Result<Box<dyn CaptureSource>> {
    let argv = if cfg.live_command.trim().is_empty() {
        default_command(&cfg.interface, &cfg.filter)
    } else {
        cfg.live_command.split_whitespace().map(String::from).collect()
    };
    if argv.is_empty() {
        return Err(Error::Config("empty live_command".into()));
    }

    let mut child: Child = Command::new(&argv[0])
        .args(&argv[1..])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| {
            Error::UnsupportedBackend(format!(
                "failed to spawn '{}' (is it installed / do you have capture privileges?): {e}",
                argv[0]
            ))
        })?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| Error::Io(std::io::Error::other("no stdout from capture tool")))?;

    let reader = BufReader::new(stdout);
    let source = PcapSource::from_reader(format!("live:{}", argv[0]), reader, 0, Some(child))?;
    Ok(Box::new(source))
}
