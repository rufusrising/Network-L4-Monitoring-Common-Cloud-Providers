//! Minimal, dependency-free HTTP/1.1 endpoint for `/metrics` and `/healthz`.
//! One background thread; connections handled serially (metrics scrapes are
//! infrequent and cheap, so this is deliberately simple and allocation-light).

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::thread::{self, JoinHandle};

use l4scope_core::error::{Error, Result};

use crate::metrics::Registry;

/// Start the metrics server. Returns a join handle for the accept loop.
pub fn serve(addr: &str, registry: Registry) -> Result<JoinHandle<()>> {
    let listener = TcpListener::bind(addr)
        .map_err(|e| Error::Config(format!("cannot bind metrics addr {addr}: {e}")))?;

    let handle = thread::spawn(move || {
        for stream in listener.incoming() {
            match stream {
                Ok(s) => {
                    let _ = handle_conn(s, &registry);
                }
                Err(_) => continue,
            }
        }
    });
    Ok(handle)
}

fn handle_conn(mut stream: TcpStream, registry: &Registry) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;

    // Drain the remaining header lines (we don't use them).
    let mut line = String::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line)?;
        if n == 0 || line == "\r\n" || line == "\n" {
            break;
        }
    }

    let path = request_line.split_whitespace().nth(1).unwrap_or("/");
    let (status, ctype, body) = match path {
        p if p.starts_with("/metrics") => {
            ("200 OK", "text/plain; version=0.0.4", registry.render_prometheus())
        }
        p if p.starts_with("/healthz") => ("200 OK", "text/plain", "ok\n".to_string()),
        _ => ("404 Not Found", "text/plain", "not found\n".to_string()),
    };

    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes())?;
    stream.flush()?;
    Ok(())
}
