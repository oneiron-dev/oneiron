//! Fenced stdio carrier for a browser that speaks CDP only over TCP.
//!
//! `oneiron-browser-relay PORT -- COMMAND [ARGS]` starts the command (the
//! browser, listening on the guest's own 127.0.0.1:PORT), with stdin null
//! and its stdout on stderr, so the session's stdin and stdout are this
//! relay's alone. It connects to 127.0.0.1:PORT, trying again while the
//! browser starts, then copies stdin to that connection and the connection
//! to stdout. Either side's end ends the relay: it kills and reaps the
//! browser. Inside the fence the connect reaches only the guest's virtual
//! loopback; no host socket or port is involved.
//!
//! Exit status: 0 once a carried connection ended, 1 when the browser did
//! not listen within [`CONNECT_WITHIN`] or exited first, 2 on a usage
//! error, 127 when the command could not start.

use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpStream};
use std::process::{Child, ExitCode, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// How long the relay keeps trying the browser's port while it starts.
const CONNECT_WITHIN: Duration = Duration::from_secs(10);
/// How long the relay waits between two tries: a cadence, not a bound.
const CONNECT_RETRY: Duration = Duration::from_millis(50);

fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let port = args
        .first()
        .and_then(|port| port.to_str())
        .and_then(|port| port.parse::<u16>().ok());
    let Some(port) = port.filter(|_| args.len() > 2 && args[1] == "--") else {
        eprintln!("usage: oneiron-browser-relay PORT -- COMMAND [ARGS]");
        return ExitCode::from(2);
    };
    let started = oneiron_spawn::command(&args[2])
        .args(&args[3..])
        .stdin(Stdio::null())
        .stdout(io::stderr())
        .spawn();
    let mut child = match started {
        Ok(child) => child,
        Err(error) => {
            eprintln!("oneiron-browser-relay: {error}");
            return ExitCode::from(127);
        }
    };
    let code = match connect(port, &mut child) {
        Ok(stream) => carry(&stream),
        Err(error) => {
            eprintln!("oneiron-browser-relay: 127.0.0.1:{port}: {error}");
            ExitCode::FAILURE
        }
    };
    let _ = child.kill();
    let _ = child.wait();
    code
}

/// The browser's connection, tried until [`CONNECT_WITHIN`] ends or the
/// browser exits.
fn connect(port: u16, child: &mut Child) -> io::Result<TcpStream> {
    let address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let deadline = Instant::now() + CONNECT_WITHIN;
    loop {
        let error = match TcpStream::connect(address) {
            Ok(stream) => return Ok(stream),
            Err(error) => error,
        };
        if child.try_wait()?.is_some() {
            return Err(io::Error::other("the browser exited before it listened"));
        }
        if Instant::now() >= deadline {
            return Err(error);
        }
        std::thread::sleep(CONNECT_RETRY);
    }
}

/// Copies stdin to `stream` and `stream` to stdout until either ends.
fn carry(stream: &TcpStream) -> ExitCode {
    let (Ok(upload), Ok(download)) = (stream.try_clone(), stream.try_clone()) else {
        return ExitCode::FAILURE;
    };
    let (ended, end) = mpsc::channel();
    let uploaded = ended.clone();
    std::thread::spawn(move || {
        let _ = pump(io::stdin().lock(), upload);
        let _ = uploaded.send(());
    });
    std::thread::spawn(move || {
        let _ = pump(download, io::stdout().lock());
        let _ = ended.send(());
    });
    let _ = end.recv();
    let _ = stream.shutdown(Shutdown::Both);
    ExitCode::SUCCESS
}

/// Copies `from` to `to`, flushing each read, until `from` ends.
fn pump(mut from: impl Read, mut to: impl Write) -> io::Result<()> {
    let mut bytes = [0; 32768];
    loop {
        let n = match from.read(&mut bytes) {
            Ok(0) => return Ok(()),
            Ok(n) => n,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        to.write_all(&bytes[..n])?;
        to.flush()?;
    }
}
