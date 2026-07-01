//! Crate-wide error type. Kept dependency-free (no `thiserror`).

use std::fmt;

#[derive(Debug)]
pub enum Error {
    /// I/O failure from a capture source, file, or socket.
    Io(std::io::Error),
    /// A capture/pcap/packet buffer was malformed or truncated.
    Parse(String),
    /// Configuration was invalid or referenced an unknown option.
    Config(String),
    /// A requested capture backend is not available on this platform/build.
    UnsupportedBackend(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "io error: {e}"),
            Error::Parse(m) => write!(f, "parse error: {m}"),
            Error::Config(m) => write!(f, "config error: {m}"),
            Error::UnsupportedBackend(m) => write!(f, "unsupported capture backend: {m}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;
