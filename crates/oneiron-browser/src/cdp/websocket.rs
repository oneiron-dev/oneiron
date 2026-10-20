//! CDP over a WebSocket, for a Lightpanda guest (FIX 6680, BROWSER-SPLIT).
//! Lightpanda serves CDP on a TCP port only: its guest's relay
//! (`oneiron-browser-relay`) dials the guest's own 127.0.0.1:9222 inside the
//! fence and carries that one connection over the session's stdin and
//! stdout. The host opens no socket: the discovery, the upgrade and every
//! frame ride the session's two byte halves.
//!
//! The pipe first asks `GET /json/version` over HTTP/1.1 and reads its head
//! and its whole Content-Length body, each within [`DISCOVERY_BYTES`], then
//! upgrades to `/` on the same connection. Nothing is pipelined: Lightpanda
//! refuses bytes past a request's body. The advertised `webSocketDebuggerUrl`
//! is checked, never dialled. Both answer by [`HANDSHAKE`].
//!
//! One pump thread owns the WebSocket. A feeder thread hands it the guest's
//! bytes and each call hands it its message, through one bounded queue, so a
//! call goes out while no reply arrives and no lock is held across a read.
//! Its writes reach the guest through a writer thread, so a guest slow to
//! read never stops it taking replies. A message past [`MAX_MESSAGE`] fails
//! only its own call, or is dropped as an event, as one past it on
//! Chromium's pipe does: the frame gate (`gate`) keeps it from tungstenite,
//! whose own bounds stay as they are. Every message is routed as
//! Chromium's are.

mod gate;

use super::{MAX_MESSAGE, Outbound, Pipe, overrun, route};
use crate::BrowserError;
use gate::Gate;
use oneiron_container::EgressRelay;
use serde_json::Value;
use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender, SyncSender};
use std::time::{Duration, Instant};
use tungstenite::protocol::WebSocketConfig;
use tungstenite::{HandshakeError, Message, Utf8Bytes, WebSocket};

/// The `Host` the discovery and the upgrade name: the guest's own CDP port,
/// on which its entrypoint serves Lightpanda (guest-only, never a host
/// port). Lightpanda takes an upgrade only for an IP literal or
/// `localhost:<port>`; the name is never looked up.
const HOST: &str = "localhost:9222";
/// How long the browser has to answer its discovery and its upgrade: the
/// relay tries its port for 10 s while the browser starts, then one call's
/// bound.
const HANDSHAKE: Duration = Duration::from_secs(20);
/// The most the discovery's answer holds: its head, and its body.
const DISCOVERY_BYTES: usize = 16 << 10;
/// The pump's queue, in events: reads of the guest's bytes and calls.
const QUEUE: usize = 64;
/// The most one read of the guest's bytes takes.
const CHUNK: usize = 32 << 10;

/// What the pump takes, in order.
enum Event {
    /// Bytes the guest wrote.
    Read(Vec<u8>),
    /// The guest's output ended or failed, or a write to it failed.
    Ended,
    /// One call's message, sent as one text frame.
    Call(Utf8Bytes),
}

/// The session's two halves as the WebSocket's one stream. A read takes the
/// guest's bytes the pump fed it, and would block once they are spent until
/// the guest ended; a write goes to the writer thread.
struct Carrier {
    read: VecDeque<u8>,
    ended: bool,
    write: Sender<Vec<u8>>,
}

impl Read for Carrier {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.read.is_empty() && !self.ended {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        self.read.read(buf)
    }
}

impl Write for Carrier {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.write
            .send(bytes.to_vec())
            .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A call's side of the pipe: its message goes to the pump.
struct Socket(SyncSender<Event>);

impl Outbound for Socket {
    fn send(&mut self, message: Vec<u8>) -> io::Result<()> {
        let text = Utf8Bytes::try_from(message)
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
        self.0
            .send(Event::Call(text))
            .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))
    }
}

/// Opens the pipe to a Lightpanda guest over its session's two halves, once
/// its browser answered the discovery and the upgrade.
pub(super) fn open(
    reader: impl Read + Send + 'static,
    writer: impl Write + Send + 'static,
    relay: Option<Arc<dyn EgressRelay>>,
) -> Result<Pipe, BrowserError> {
    let (events, inbound) = mpsc::sync_channel(QUEUE);
    let fed = events.clone();
    std::thread::spawn(move || feed(reader, &fed));
    let (write, outbound) = mpsc::channel();
    let failed = events.clone();
    std::thread::spawn(move || send_out(writer, &outbound, &failed));
    let mut carrier = Carrier {
        read: VecDeque::new(),
        ended: false,
        write,
    };
    let deadline = Instant::now() + HANDSHAKE;
    discover(&mut carrier, &inbound, deadline)?;
    let (socket, ahead) = upgrade(carrier, &inbound, deadline)?;
    let pipe = Pipe::routed(Box::new(Socket(events)), relay.is_some());
    let handle = pipe.clone();
    std::thread::spawn(move || {
        pump(socket, ahead, &inbound, &handle, relay.as_ref());
        handle.end();
    });
    Ok(pipe)
}

/// Hands the guest's bytes to the pump until its output ends.
fn feed(mut reader: impl Read, events: &SyncSender<Event>) {
    let mut chunk = vec![0; CHUNK];
    loop {
        let read = match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        };
        if events.send(Event::Read(chunk[..read].to_vec())).is_err() {
            return;
        }
    }
    let _ = events.send(Event::Ended);
}

/// Writes the WebSocket's bytes to the guest, in order. A write that fails
/// ends the pump, as the guest's own end does.
fn send_out(mut writer: impl Write, outbound: &Receiver<Vec<u8>>, events: &SyncSender<Event>) {
    for bytes in outbound {
        if writer
            .write_all(&bytes)
            .and_then(|()| writer.flush())
            .is_err()
        {
            let _ = events.send(Event::Ended);
            return;
        }
    }
}

/// Asks the browser its `/json/version` and reads the whole answer: a 200
/// whose body names the WebSocket it serves.
fn discover(
    carrier: &mut Carrier,
    inbound: &Receiver<Event>,
    deadline: Instant,
) -> Result<(), BrowserError> {
    let ask = format!("GET /json/version HTTP/1.1\r\nHost: {HOST}\r\n\r\n");
    carrier
        .write_all(ask.as_bytes())
        .map_err(|_| BrowserError::GuestLost)?;
    let end = loop {
        if let Some(end) = head_end(carrier.read.make_contiguous()) {
            break end;
        }
        if carrier.read.len() > DISCOVERY_BYTES {
            return Err(refused("its discovery answer's head is past its bound"));
        }
        take(carrier, inbound, deadline)?;
    };
    let head: Vec<u8> = carrier.read.drain(..end).collect();
    let head = String::from_utf8_lossy(&head);
    let mut lines = head.split("\r\n");
    let status = lines.next().unwrap_or("");
    if !status.starts_with("HTTP/1.1 200 ") {
        return Err(refused(&format!("its discovery answered {status}")));
    }
    let length = lines
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.trim().eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.trim().parse::<usize>().ok())
        .filter(|length| *length <= DISCOVERY_BYTES)
        .ok_or_else(|| refused("its discovery answer has no length within its bound"))?;
    while carrier.read.len() < length {
        take(carrier, inbound, deadline)?;
    }
    let body: Vec<u8> = carrier.read.drain(..length).collect();
    let version: Value =
        serde_json::from_slice(&body).map_err(|_| refused("its discovery answer is no JSON"))?;
    let serves = version
        .get("webSocketDebuggerUrl")
        .and_then(Value::as_str)
        .is_some_and(|url| url.starts_with("ws://"));
    if !serves {
        return Err(refused("its discovery names no WebSocket"));
    }
    Ok(())
}

/// Where an HTTP head ends in `bytes`: past its blank line.
fn head_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|at| at + 4)
}

/// Upgrades the discovered connection to the browser's WebSocket at `/`,
/// its messages and frames bounded as the pipe's are. tungstenite is handed
/// the upgrade's answer up to and with its blank line, never past it: the
/// bytes past it (`ahead`) go through the frame gate once the socket exists.
fn upgrade(
    carrier: Carrier,
    inbound: &Receiver<Event>,
    deadline: Instant,
) -> Result<(WebSocket<Carrier>, Vec<u8>), BrowserError> {
    let bound = usize::try_from(MAX_MESSAGE).unwrap_or(usize::MAX);
    let config = WebSocketConfig::default()
        .max_message_size(Some(bound))
        .max_frame_size(Some(bound));
    let url = format!("ws://{HOST}/");
    let mut head: Vec<u8> = carrier.read.iter().copied().collect();
    let mut ahead = Vec::new();
    let mut shaking = tungstenite::client::client_with_config(url, carrier, Some(config));
    loop {
        match shaking {
            Ok((socket, _)) => return Ok((socket, ahead)),
            Err(HandshakeError::Interrupted(mut mid)) => {
                let bytes = receive(inbound, deadline)?;
                let given = split_head(&mut head, &bytes);
                mid.get_mut().get_mut().read.extend(&bytes[..given]);
                ahead.extend_from_slice(&bytes[given..]);
                shaking = mid.handshake();
            }
            Err(HandshakeError::Failure(error)) => {
                return Err(refused(&format!("its upgrade failed: {error}")));
            }
        }
    }
}

/// How many of `bytes`, the guest's next during the upgrade, belong to its
/// answer's head: up to and with its blank line, which may straddle reads.
/// `head` holds the answer as far as it came; once it ended, none do.
fn split_head(head: &mut Vec<u8>, bytes: &[u8]) -> usize {
    if head_end(head).is_some() {
        return 0;
    }
    let from = head.len().saturating_sub(3);
    head.extend_from_slice(bytes);
    match head_end(&head[from..]) {
        Some(end) => {
            let past = head.len() - (from + end);
            head.truncate(from + end);
            bytes.len() - past
        }
        None => bytes.len(),
    }
}

/// Takes the guest's next bytes into `carrier`, by `deadline`.
fn take(
    carrier: &mut Carrier,
    inbound: &Receiver<Event>,
    deadline: Instant,
) -> Result<(), BrowserError> {
    carrier.read.extend(receive(inbound, deadline)?);
    Ok(())
}

/// The guest's next bytes, by `deadline`.
fn receive(inbound: &Receiver<Event>, deadline: Instant) -> Result<Vec<u8>, BrowserError> {
    match inbound.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
        Ok(Event::Read(bytes)) => Ok(bytes),
        // No call is sent before the pipe exists.
        Ok(Event::Call(_)) => Ok(Vec::new()),
        Ok(Event::Ended) | Err(RecvTimeoutError::Disconnected) => {
            Err(refused("the guest ended first"))
        }
        Err(RecvTimeoutError::Timeout) => Err(BrowserError::Timeout(
            "lightpanda's CDP WebSocket".to_owned(),
        )),
    }
}

/// The guest's browser did not open its CDP WebSocket, for `why`.
fn refused(why: &str) -> BrowserError {
    BrowserError::Unavailable(format!("lightpanda did not open its CDP WebSocket: {why}"))
}

/// Runs the WebSocket until the guest ends or the socket closes or fails:
/// the guest's bytes pass the frame gate, those past the upgrade's answer
/// (`ahead`) first, are read into whole messages and routed, and each call
/// is sent.
fn pump(
    mut socket: WebSocket<Carrier>,
    ahead: Vec<u8>,
    inbound: &Receiver<Event>,
    pipe: &Pipe,
    relay: Option<&Arc<dyn EgressRelay>>,
) {
    let mut gate = Gate::default();
    for event in std::iter::once(Event::Read(ahead)).chain(inbound) {
        let open = match event {
            Event::Read(bytes) => {
                let over = gate.pass(&bytes, &mut socket.get_mut().read);
                over.iter()
                    .all(|prefix| overrun::oversize_message_policy(pipe, prefix))
                    && deliver(&mut socket, pipe, relay)
            }
            Event::Ended => {
                socket.get_mut().ended = true;
                deliver(&mut socket, pipe, relay);
                false
            }
            Event::Call(text) => socket.send(Message::Text(text)).is_ok(),
        };
        if !open {
            return;
        }
    }
}

/// Routes every whole message the guest's bytes hold so far, then sends
/// what the socket owes (a pong, a close); false once the socket closed or
/// failed.
fn deliver(
    socket: &mut WebSocket<Carrier>,
    pipe: &Pipe,
    relay: Option<&Arc<dyn EgressRelay>>,
) -> bool {
    loop {
        let open = match socket.read() {
            Ok(Message::Text(text)) => route(pipe, relay, text.as_bytes()),
            Ok(Message::Binary(bytes)) => route(pipe, relay, &bytes),
            Ok(Message::Ping(_) | Message::Pong(_) | Message::Frame(_)) => true,
            Ok(Message::Close(_)) => false,
            Err(tungstenite::Error::Io(error)) if error.kind() == io::ErrorKind::WouldBlock => {
                return socket.flush().is_ok();
            }
            Err(_) => false,
        };
        if !open {
            return false;
        }
    }
}
