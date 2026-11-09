//! A socket-activated HTTP server for the testkit's own tests of
//! `ServerProcess`. It takes its listener the way `oneiron-server serve` does
//! (systemd socket activation: `LISTEN_PID`, `LISTEN_FDS`, descriptor 3),
//! sends `READY=1` to `NOTIFY_SOCKET`, and answers every request with
//! `pid <its pid>`. Never shipped; the testkit is a dev-dependency only.

#[cfg(unix)]
fn main() -> std::io::Result<()> {
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::os::fd::FromRawFd;
    use std::os::unix::net::UnixDatagram;

    let pid = std::process::id();
    let for_us = std::env::var("LISTEN_PID").ok().and_then(|value| value.parse::<u32>().ok()) == Some(pid);
    let count = std::env::var("LISTEN_FDS").ok().and_then(|value| value.parse::<u32>().ok());
    if !for_us || count != Some(1) {
        eprintln!("oneiron-testkit-probe-server: no activated socket for pid {pid}");
        std::process::exit(2);
    }
    // SAFETY: socket activation passed this very pid (checked above) one
    // listening socket at descriptor 3, which nothing else here owns.
    let listener = unsafe { TcpListener::from_raw_fd(3) };
    if let Some(path) = std::env::var_os("NOTIFY_SOCKET") {
        UnixDatagram::unbound()?.send_to(b"READY=1", path)?;
    }
    for stream in listener.incoming() {
        let mut stream = stream?;
        let mut reader = BufReader::new(stream.try_clone()?);
        let mut line = String::new();
        // The request line and headers, up to the blank line.
        while reader.read_line(&mut line)? > 0 && line != "\r\n" && line != "\n" {
            line.clear();
        }
        let body = format!("pid {pid}");
        write!(
            stream,
            "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        )?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn main() {
    eprintln!("oneiron-testkit-probe-server: Unix only");
    std::process::exit(2);
}
