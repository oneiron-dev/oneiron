//! A minimal HTTP/1.1 server on loopback for the scripted provider: one
//! request per connection, answered with `Connection: close`. Standard library
//! only, so it runs the same under a sync test and inside any async runtime.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

/// The largest request body the provider reads.
const MAX_BODY: usize = 64 << 20;
/// How long a connection may stall mid-request before the provider drops
/// it. A safety net against a hung client, never part of a test's logic.
const READ_STALL_LIMIT: Duration = Duration::from_secs(60);

/// One HTTP request, as the provider reads it.
pub(crate) struct Request {
    pub(crate) method: String,
    pub(crate) path: String,
    pub(crate) body: Vec<u8>,
}

/// What a handler does with one connection.
pub(crate) type Handler = Arc<dyn Fn(Request, &mut TcpStream) + Send + Sync>;

/// The accept loop. Dropping it stops accepting; connections already being
/// answered finish on their own threads.
pub(crate) struct Listener {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Listener {
    /// Binds `127.0.0.1:0` and answers each connection on its own thread.
    pub(crate) fn start(handler: Handler) -> io::Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        let addr = listener.local_addr()?;
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = Arc::clone(&stop);
        let thread = std::thread::Builder::new()
            .name("testkit-provider-accept".into())
            .spawn(move || {
                for stream in listener.incoming() {
                    if stopping.load(Ordering::Acquire) {
                        break;
                    }
                    let Ok(stream) = stream else { continue };
                    let handler = Arc::clone(&handler);
                    let spawned = std::thread::Builder::new()
                        .name("testkit-provider-conn".into())
                        .spawn(move || serve_connection(stream, &handler));
                    drop(spawned);
                }
            })?;
        Ok(Self {
            addr,
            stop,
            thread: Some(thread),
        })
    }

    pub(crate) fn addr(&self) -> SocketAddr {
        self.addr
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        // Wake the blocking accept so the loop sees the flag.
        let _ = TcpStream::connect(self.addr);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn serve_connection(mut stream: TcpStream, handler: &Handler) {
    let _ = stream.set_read_timeout(Some(READ_STALL_LIMIT));
    match read_request(&mut stream) {
        Ok(Some(request)) => handler(request, &mut stream),
        Ok(None) => {}
        Err(error) => {
            let _ = write_body(&mut stream, 400, "text/plain", error.to_string().as_bytes());
        }
    }
    let _ = stream.flush();
    let _ = stream.shutdown(Shutdown::Both);
}

/// Reads one request; `None` when the client closed before sending one.
fn read_request(stream: &mut TcpStream) -> io::Result<Option<Request>> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    if reader.read_line(&mut line)? == 0 {
        return Ok(None);
    }
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_owned();
    let target = parts.next().unwrap_or_default();
    let path = target.split('?').next().unwrap_or_default().to_owned();
    let mut length = None;
    let mut chunked = false;
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "headers ended early",
            ));
        }
        let header = line.trim_end();
        if header.is_empty() {
            break;
        }
        let Some((name, value)) = header.split_once(':') else {
            continue;
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            length = value.parse::<usize>().ok();
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            chunked = value.to_ascii_lowercase().contains("chunked");
        }
    }
    let body = if chunked {
        read_chunked(&mut reader)?
    } else {
        let length = length.unwrap_or(0);
        if length > MAX_BODY {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "request body too large",
            ));
        }
        let mut body = vec![0; length];
        reader.read_exact(&mut body)?;
        body
    };
    Ok(Some(Request { method, path, body }))
}

fn read_chunked(reader: &mut impl BufRead) -> io::Result<Vec<u8>> {
    let mut body = Vec::new();
    let mut line = String::new();
    loop {
        line.clear();
        reader.read_line(&mut line)?;
        let size = line.trim().split(';').next().unwrap_or_default();
        let size = usize::from_str_radix(size, 16)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad chunk size"))?;
        if size == 0 {
            // Trailers end with an empty line.
            loop {
                line.clear();
                if reader.read_line(&mut line)? == 0 || line.trim().is_empty() {
                    return Ok(body);
                }
            }
        }
        if body.len() + size > MAX_BODY {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "request body too large",
            ));
        }
        let start = body.len();
        body.resize(start + size, 0);
        reader.read_exact(&mut body[start..])?;
        line.clear();
        reader.read_line(&mut line)?;
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "Status",
    }
}

/// Writes a complete response with a `Content-Length` body.
pub(crate) fn write_body(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> io::Result<()> {
    let head = format!(
        "HTTP/1.1 {status} {}\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        reason(status),
        body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

/// Writes an event stream, one chunk per event. With `cut` set the stream
/// stops after the events and the connection closes with no final chunk: a
/// provider that died mid-answer.
pub(crate) fn write_events(stream: &mut TcpStream, events: &[String], cut: bool) -> io::Result<()> {
    stream.write_all(
        b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ncache-control: no-cache\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n",
    )?;
    for event in events {
        write!(stream, "{:x}\r\n", event.len())?;
        stream.write_all(event.as_bytes())?;
        stream.write_all(b"\r\n")?;
        stream.flush()?;
    }
    if !cut {
        stream.write_all(b"0\r\n\r\n")?;
    }
    stream.flush()
}
