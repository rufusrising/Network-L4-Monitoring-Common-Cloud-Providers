//! NDJSON event sink: one JSON object per line, to stdout/stderr/a file, or off.
//! Suitable for shipping into Loki, Elasticsearch, or any log pipeline.

use std::fs::{File, OpenOptions};
use std::io::Write;

use l4scope_core::error::{Error, Result};
use l4scope_core::types::L4Event;

pub enum JsonSink {
    Off,
    Stdout,
    Stderr,
    File(File),
}

impl JsonSink {
    /// Build from the config string: "", "stdout", "stderr", or a file path.
    pub fn from_target(target: &str) -> Result<JsonSink> {
        match target.trim() {
            "" | "off" | "none" => Ok(JsonSink::Off),
            "stdout" => Ok(JsonSink::Stdout),
            "stderr" => Ok(JsonSink::Stderr),
            path => {
                let f = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .map_err(|e| Error::Config(format!("cannot open json_events {path}: {e}")))?;
                Ok(JsonSink::File(f))
            }
        }
    }

    pub fn emit(&mut self, ev: &L4Event) {
        let line = ev.to_json();
        match self {
            JsonSink::Off => {}
            JsonSink::Stdout => {
                let out = std::io::stdout();
                let mut h = out.lock();
                let _ = writeln!(h, "{line}");
            }
            JsonSink::Stderr => {
                let err = std::io::stderr();
                let mut h = err.lock();
                let _ = writeln!(h, "{line}");
            }
            JsonSink::File(f) => {
                let _ = writeln!(f, "{line}");
            }
        }
    }
}
