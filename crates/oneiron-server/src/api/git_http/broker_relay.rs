//! What every loopback relay that sends Git's exchanges through the
//! credential broker shares (ARCH-0069 OSH-3): an outside import's source
//! relay (FIX 15702) and an exact publish's mirror relay (FIX 19083).
//!
//! Each relay spools a request body to a private unnamed file, decoded from
//! any gzip, so its digest and its send cover the identity bytes; takes its
//! digest in the git digest domain; and answers Git with the broker's reply
//! as it streams, its end clean only when the broker says so. Each notes the
//! first refusal any exchange met, spelled with its own prefix. None bounds
//! a pack's size or a call's time: each frame waits at most the host's
//! transfer idle limit, and a relay with a disk floor refuses a write that
//! would cross it, never a body by its size.

use std::io::{self, Read as _, Seek as _, SeekFrom, Write as _};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::http::StatusCode;
use axum::http::header::{CONTENT_ENCODING, CONTENT_TYPE, HeaderValue};
use axum::http::request::Parts;
use axum::response::Response;
use futures_util::StreamExt as _;
use oneiron::origin::smart_http::{AtDiskFloor, SpillFloor};
use oneiron_broker::{
    BrokerError, GitReply, GitRequestDigest, GitTarget, Outcome, StreamPart, git_request_digest,
};
use tokio::runtime::Handle;
use tokio::sync::oneshot;

use super::gate::{header_value, text_response};
use crate::machine::DiskFloor;

/// How much of a spool one read takes as its digest is taken.
const SPOOL_READ: usize = 64 << 10;

/// The first refusal code any exchange of one relay met, each code spelled
/// with the relay's own prefix.
pub(super) struct RelayNotes {
    prefix: &'static str,
    first: Mutex<Option<String>>,
}

impl RelayNotes {
    /// No note yet; every code this relay spells begins with `prefix`.
    pub(super) fn new(prefix: &'static str) -> Self {
        Self {
            prefix,
            first: Mutex::new(None),
        }
    }

    /// The prefix this relay's codes begin with.
    pub(super) fn prefix(&self) -> &'static str {
        self.prefix
    }

    /// Notes `code`, unless an earlier one stands.
    pub(super) fn note(&self, code: &str) {
        if let Ok(mut first) = self.first.lock() {
            first.get_or_insert_with(|| code.to_owned());
        }
    }

    /// Notes `code` and answers Git with it.
    pub(super) fn refuse(&self, status: StatusCode, code: &str) -> Response {
        self.note(code);
        text_response(status, code)
    }

    /// The first code noted.
    pub(super) fn first(&self) -> Option<String> {
        self.first.lock().ok().and_then(|first| first.clone())
    }
}

/// Why a request body was not spooled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SpoolFault {
    /// An outer content encoding other than gzip or identity.
    EncodingUnsupported,
    /// The spool file could not be made, read back or rewound.
    SpoolFailed,
    /// Git sent no frame for the idle limit.
    Idle,
    /// The body broke off.
    Broken,
    /// A frame could not be decoded or written.
    Unreadable,
    /// A write would have crossed the relay's disk floor.
    AtDiskFloor,
}

impl SpoolFault {
    /// The fault's refusal code under `prefix`.
    pub(super) fn code(self, prefix: &str) -> String {
        let fault = match self {
            Self::EncodingUnsupported => "encoding_unsupported",
            Self::SpoolFailed => "spool_failed",
            Self::Idle => "idle",
            Self::Broken => "broken",
            Self::Unreadable => "unreadable",
            Self::AtDiskFloor => "at_disk_floor",
        };
        format!("{prefix}_request_{fault}")
    }

    /// The status Git is answered with.
    pub(super) fn status(self) -> StatusCode {
        match self {
            Self::AtDiskFloor => StatusCode::INSUFFICIENT_STORAGE,
            _ => StatusCode::BAD_REQUEST,
        }
    }
}

/// A spool file, each write to which first asks `floor`, when there is
/// one, for room above its reserve.
struct FloorFile {
    file: std::fs::File,
    floor: Option<DiskFloor>,
}

impl io::Write for FloorFile {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self
            .floor
            .as_ref()
            .is_some_and(|floor| !floor.has_room_for(bytes.len() as u64))
        {
            return Err(io::Error::new(io::ErrorKind::StorageFull, AtDiskFloor));
        }
        self.file.write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

/// Where a request body is spooled: as it came, or decoded from gzip.
enum Sink {
    Plain(FloorFile),
    Gzip(flate2::write::GzDecoder<FloorFile>),
}

impl Sink {
    fn write(&mut self, bytes: &[u8]) -> io::Result<()> {
        match self {
            Self::Plain(file) => file.write_all(bytes),
            Self::Gzip(decoder) => decoder.write_all(bytes),
        }
    }

    fn finish(self) -> io::Result<std::fs::File> {
        match self {
            Self::Plain(file) => Ok(file.file),
            Self::Gzip(decoder) => decoder.finish().map(|file| file.file),
        }
    }
}

/// The fault of a write to the spool: the floor's refusal, or another.
fn write_fault(error: &io::Error) -> SpoolFault {
    if AtDiskFloor::is_in(error) {
        SpoolFault::AtDiskFloor
    } else {
        SpoolFault::Unreadable
    }
}

/// Spools Git's request body to a private unnamed file, decoded from its
/// outer gzip when it carries one, so the digest and the send cover the
/// identity bytes; rewound. Each frame waits at most `idle`. With `floor`,
/// the file is made on the disk it measures and each write first asks it
/// for room above its reserve; without, the file is the host's temp file.
pub(super) async fn spool_request(
    parts: &Parts,
    body: Body,
    idle: Duration,
    floor: Option<&DiskFloor>,
) -> Result<std::fs::File, SpoolFault> {
    let encoding = header_value(&parts.headers, CONTENT_ENCODING.as_str()).unwrap_or_default();
    let encoding = encoding.trim();
    let gzip = if encoding.is_empty() || encoding.eq_ignore_ascii_case("identity") {
        false
    } else if encoding.eq_ignore_ascii_case("gzip") || encoding.eq_ignore_ascii_case("x-gzip") {
        true
    } else {
        return Err(SpoolFault::EncodingUnsupported);
    };
    let file = match floor {
        None => tempfile::tempfile(),
        Some(floor) => SpillFloor::spool_dir(floor)
            .ok_or_else(|| io::Error::other("no spool directory on the floored disk"))
            .and_then(tempfile::tempfile_in),
    }
    .map_err(|_| SpoolFault::SpoolFailed)?;
    let file = FloorFile {
        file,
        floor: floor.cloned(),
    };
    let mut sink = if gzip {
        Sink::Gzip(flate2::write::GzDecoder::new(file))
    } else {
        Sink::Plain(file)
    };
    let mut frames = body.into_data_stream();
    loop {
        let frame = match tokio::time::timeout(idle, frames.next()).await {
            Err(_) => return Err(SpoolFault::Idle),
            Ok(None) => break,
            Ok(Some(Err(_))) => return Err(SpoolFault::Broken),
            Ok(Some(Ok(frame))) => frame,
        };
        sink.write(&frame).map_err(|error| write_fault(&error))?;
    }
    let mut file = sink.finish().map_err(|error| write_fault(&error))?;
    file.seek(SeekFrom::Start(0))
        .map_err(|_| SpoolFault::SpoolFailed)?;
    Ok(file)
}

/// The digest of an exchange to `target` with `headers` and the spooled
/// `body` (none for an advertisement), its length, and the body rewound.
pub(super) fn digest_body(
    target: &GitTarget,
    headers: &[(String, String)],
    body: Option<std::fs::File>,
) -> Result<(String, u64, Option<std::fs::File>), SpoolFault> {
    let Some(mut file) = body else {
        let digest =
            git_request_digest(target, headers, &[]).map_err(|_| SpoolFault::SpoolFailed)?;
        return Ok((digest, 0, None));
    };
    let len = file.metadata().map_err(|_| SpoolFault::SpoolFailed)?.len();
    let mut digest = GitRequestDigest::new(target, headers, len);
    let mut buffer = vec![0; SPOOL_READ];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| SpoolFault::SpoolFailed)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|_| SpoolFault::SpoolFailed)?;
    let digest = digest.finish().map_err(|_| SpoolFault::SpoolFailed)?;
    Ok((digest, len, Some(file)))
}

/// A broker error's refusal code under `prefix`.
pub(super) fn broker_code(prefix: &str, error: BrokerError) -> String {
    match error {
        BrokerError::Refused(reason) => format!("{prefix}_refused_{}", code(&reason)),
        BrokerError::Lost => format!("{prefix}_broker_lost"),
        BrokerError::Unreachable => format!("{prefix}_broker_unreachable"),
        BrokerError::Peer => format!("{prefix}_broker_peer_refused"),
    }
}

/// A broker code's wire spelling.
pub(super) fn code<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_else(|| "unknown".to_owned())
}

/// Git's answer from the broker's `reply`: its status and content type, and
/// its body streamed as it comes. A refused or failed exchange, a non-2xx
/// status, a cut or a broken reply is noted in `notes`.
pub(super) fn answer(reply: GitReply, notes: &Arc<RelayNotes>) -> Response {
    let prefix = notes.prefix();
    let (status, headers) = match reply.outcome() {
        Outcome::Answered { status, headers } => (*status, headers.clone()),
        Outcome::Refused { reason } => {
            let code = format!("{prefix}_refused_{}", code(reason));
            return notes.refuse(StatusCode::BAD_GATEWAY, &code);
        }
        Outcome::Failed { reason } => {
            let code = format!("{prefix}_failed_{}", code(reason));
            return notes.refuse(StatusCode::BAD_GATEWAY, &code);
        }
    };
    if !(200..300).contains(&status) {
        notes.note(&format!("{prefix}_http_{status}"));
    }
    let mut response = Response::new(reply_body(reply, Arc::clone(notes)));
    *response.status_mut() = StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY);
    if let Some(value) = headers
        .iter()
        .find(|(name, _)| name == "content-type")
        .and_then(|(_, value)| HeaderValue::from_str(value).ok())
    {
        response.headers_mut().insert(CONTENT_TYPE, value);
    }
    response
}

/// A reply's body as Git reads it: each chunk as it comes, the end clean
/// only when the broker says so. A cut or broken reply ends with an error,
/// so Git never reads a cut pack as whole.
fn reply_body(reply: GitReply, notes: Arc<RelayNotes>) -> Body {
    let chunks = futures_util::stream::unfold(Some((reply, notes)), |state| async move {
        let (mut reply, notes) = state?;
        match reply.next().await {
            Ok(StreamPart::Chunk(mut chunk)) => Some((
                Ok::<Vec<u8>, io::Error>(std::mem::take(&mut *chunk)),
                Some((reply, notes)),
            )),
            Ok(StreamPart::End) => None,
            Ok(StreamPart::Cut(reason)) => {
                notes.note(&format!("{}_cut_{}", notes.prefix(), code(&reason)));
                Some((Err(io::Error::other("the brokered reply was cut")), None))
            }
            Err(_) => {
                notes.note(&format!("{}_broker_lost", notes.prefix()));
                Some((Err(io::Error::other("the brokered reply broke")), None))
            }
        }
    });
    Body::from_stream(chunks)
}

/// Serves `app` on an OS-assigned loopback port on `runtime` until the
/// returned sender fires or drops; `relay` names it in a stop error's
/// warning.
pub(super) fn serve_loopback(
    runtime: &Handle,
    app: Router,
    relay: &'static str,
) -> oneiron::Result<(u16, oneshot::Sender<()>)> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let port = listener.local_addr()?.port();
    let listener = {
        let _entered = runtime.enter();
        tokio::net::TcpListener::from_std(listener)?
    };
    let (stop, stopped) = oneshot::channel::<()>();
    drop(runtime.spawn(async move {
        let shutdown = async move {
            let _ = stopped.await;
        };
        if let Err(error) = axum::serve(listener, app)
            .with_graceful_shutdown(shutdown)
            .await
        {
            tracing::warn!(%error, "{relay} stopped with an error");
        }
    }));
    Ok((port, stop))
}
