//! One native call on the house EXL3 worker's Unix socket: its connection,
//! peer-checked; its `generate` frame with the input region's descriptor
//! riding on the first byte (SCM_RIGHTS); its events; and its cancel.
//!
//! Each call opens its own connection. A call dropped before its terminal
//! sends `cancel` and waits, on a task of its own, for the worker's word that
//! the call has ended (`released`, or its terminal if it ended first, or the
//! connection's close), and only then lets its lease on the incarnation go.
//! Nothing here resends a call: once `generate` may have left, a fault is
//! the caller's to settle under its own retry authority.
use std::io::{self, IoSlice};
use std::mem::MaybeUninit;
use std::os::fd::BorrowedFd;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use oneiron_driver::WorkerLease;
use rustix::net::{SendAncillaryBuffer, SendAncillaryMessage, SendFlags, sendmsg};
use serde_json::{Value as JsonValue, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, Interest};
use tokio::net::UnixStream;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};

use super::buffer::InputRegion;
use super::wire::{self, Incoming, Outgoing};

/// A send to a worker that has gone fails with EPIPE rather than raising
/// SIGPIPE; macOS has no such flag, and this process ignores the signal.
#[cfg(target_os = "linux")]
const SEND_FLAGS: SendFlags = SendFlags::NOSIGNAL;
#[cfg(not(target_os = "linux"))]
const SEND_FLAGS: SendFlags = SendFlags::empty();

/// Request ids, unique in this process.
static NEXT_REQUEST_ID: AtomicU64 = AtomicU64::new(1);

pub(super) fn next_request_id() -> u64 {
    NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed)
}

/// One connection to the worker's socket.
pub(super) struct Channel {
    reader: BufReader<OwnedReadHalf>,
    writer: OwnedWriteHalf,
}

impl Channel {
    /// Connects to the socket at `path`; refused unless the process that
    /// answers runs as this process's own user.
    pub(super) async fn connect(path: &Path) -> io::Result<Self> {
        let stream = UnixStream::connect(path).await?;
        let peer = stream.peer_cred()?;
        if peer.uid() != rustix::process::geteuid().as_raw() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "the worker's socket answers as another user",
            ));
        }
        let (reader, writer) = stream.into_split();
        Ok(Self {
            reader: BufReader::new(reader),
            writer,
        })
    }

    fn frame(
        op: &str,
        request_id: u64,
        epoch: Option<&str>,
        body: JsonValue,
    ) -> io::Result<Vec<u8>> {
        wire::encode(&Outgoing {
            v: wire::SCHEMA_VERSION,
            op,
            request_id,
            epoch,
            body,
        })
        .map_err(io::Error::other)
    }

    /// Sends one frame, whole.
    pub(super) async fn send(
        &mut self,
        op: &str,
        request_id: u64,
        epoch: Option<&str>,
        body: JsonValue,
    ) -> io::Result<()> {
        let bytes = Self::frame(op, request_id, epoch, body)?;
        self.writer.write_all(&bytes).await
    }

    /// Sends one frame with `fd` riding on its first byte, then the rest of
    /// it.
    async fn send_with_fd(
        &mut self,
        op: &str,
        request_id: u64,
        epoch: Option<&str>,
        body: JsonValue,
        fd: BorrowedFd<'_>,
    ) -> io::Result<()> {
        let bytes = Self::frame(op, request_id, epoch, body)?;
        let fds = [fd];
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut control = SendAncillaryBuffer::new(&mut space);
        if !control.push(SendAncillaryMessage::ScmRights(&fds)) {
            return Err(io::Error::other(
                "the descriptor does not fit its control message",
            ));
        }
        let stream: &UnixStream = self.writer.as_ref();
        let sent = stream
            .async_io(Interest::WRITABLE, || {
                sendmsg(stream, &[IoSlice::new(&bytes)], &mut control, SEND_FLAGS)
                    .map_err(io::Error::from)
            })
            .await?;
        if sent == 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }
        self.writer.write_all(&bytes[sent..]).await
    }

    /// The next frame, or `None` once the worker has closed the connection.
    pub(super) async fn next(&mut self) -> io::Result<Option<Incoming>> {
        let mut header = [0_u8; wire::HEADER_BYTES];
        if let Err(error) = self.reader.read_exact(&mut header).await {
            return if error.kind() == io::ErrorKind::UnexpectedEof {
                Ok(None)
            } else {
                Err(error)
            };
        }
        let length = u64::from_be_bytes(header);
        let mut payload = Vec::new();
        let read = (&mut self.reader)
            .take(length)
            .read_to_end(&mut payload)
            .await?;
        if u64::try_from(read).ok() != Some(length) {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        wire::decode(&payload).map(Some).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "the worker sent a frame this side cannot read",
            )
        })
    }

    /// Sends `op` and returns the body of the worker's frame of the same op
    /// and id.
    pub(super) async fn ask(&mut self, op: &str, body: JsonValue) -> io::Result<JsonValue> {
        let request_id = next_request_id();
        self.send(op, request_id, None, body).await?;
        loop {
            match self.next().await? {
                Some(frame) if frame.request_id == request_id && frame.op == op => {
                    return Ok(frame.body);
                }
                Some(frame) if frame.request_id == request_id => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("the worker answered {op} with {}", frame.op),
                    ));
                }
                Some(_) => {}
                None => return Err(io::ErrorKind::UnexpectedEof.into()),
            }
        }
    }

    /// Sends `cancel` for `request_id` and waits until the worker says the
    /// call has ended: its `released`, its terminal if it ended first, a
    /// `cancel_ack` that found nothing, or the connection's close. No
    /// deadline: the worker releases at its next pass.
    async fn cancel(mut self, request_id: u64) {
        if self
            .send("cancel", request_id, None, json!({}))
            .await
            .is_err()
        {
            return;
        }
        loop {
            match self.next().await {
                Ok(Some(frame)) if frame.request_id == request_id => match frame.op.as_str() {
                    "released" | "final" | "refused" => return,
                    "cancel_ack"
                        if frame.body.get("found").and_then(JsonValue::as_bool) == Some(false) =>
                    {
                        return;
                    }
                    _ => {}
                },
                Ok(Some(_)) => {}
                Ok(None) | Err(_) => return,
            }
        }
    }
}

/// How a call's start went wrong.
pub(super) enum Start {
    /// Nothing left this side: the worker never saw the call.
    NotSent,
    /// The worker refused it before anything ran, with this body.
    Refused(JsonValue),
    /// The channel failed after the call went out: it may have run.
    Cut,
}

/// One event of a call in flight.
pub(super) enum Event {
    /// The worker sampled the call's first token.
    FirstToken,
    /// A piece of the reply, reasoning or answer.
    Token { reasoning: bool, text: String },
    /// The call's terminal, with its body.
    Final(JsonValue),
}

/// The channel failed, or the worker ended the call some other way, before
/// its `final`: the call may have run.
pub(super) struct Cut;

/// One `generate` in flight on its own connection.
pub(super) struct Call {
    channel: Option<Channel>,
    request_id: u64,
    /// The lease on the incarnation the call went to, held until the call
    /// has ended there.
    lease: Option<WorkerLease>,
    ended: bool,
}

impl Call {
    /// Connects to `path`, sends the call with `conversation` as its input
    /// region, and waits for the worker to accept or refuse it.
    pub(super) async fn start(
        path: &Path,
        epoch: &str,
        conversation: &JsonValue,
        params: JsonValue,
        stream: bool,
        lease: Option<WorkerLease>,
    ) -> Result<Self, Start> {
        let bytes = serde_json::to_vec(conversation).map_err(|_| Start::NotSent)?;
        let input = InputRegion::new(&bytes).map_err(|_| Start::NotSent)?;
        let mut channel = Channel::connect(path).await.map_err(|_| Start::NotSent)?;
        let request_id = next_request_id();
        let body = wire::generate_body(request_id, input.len(), params, stream);
        let sent = channel
            .send_with_fd("generate", request_id, Some(epoch), body, input.fd())
            .await;
        let mut call = Self {
            channel: Some(channel),
            request_id,
            lease,
            ended: false,
        };
        if sent.is_err() {
            call.ended = true;
            return Err(Start::Cut);
        }
        loop {
            let frame = match call.channel_mut().next().await {
                Ok(Some(frame)) => frame,
                Ok(None) | Err(_) => {
                    call.ended = true;
                    return Err(Start::Cut);
                }
            };
            if frame.request_id != request_id {
                continue;
            }
            match frame.op.as_str() {
                "accepted" => {
                    // The worker holds its own copy of the region now.
                    drop(input);
                    return Ok(call);
                }
                "refused" => {
                    call.ended = true;
                    return Err(Start::Refused(frame.body));
                }
                _ => {
                    call.ended = true;
                    return Err(Start::Cut);
                }
            }
        }
    }

    fn channel_mut(&mut self) -> &mut Channel {
        self.channel
            .as_mut()
            .unwrap_or_else(|| unreachable!("a call keeps its channel until it drops"))
    }

    /// The call's next event, until its `final`.
    pub(super) async fn next(&mut self) -> Result<Event, Cut> {
        if self.ended {
            return Err(Cut);
        }
        loop {
            let frame = match self.channel_mut().next().await {
                Ok(Some(frame)) => frame,
                Ok(None) | Err(_) => {
                    self.ended = true;
                    return Err(Cut);
                }
            };
            if frame.request_id != self.request_id {
                continue;
            }
            match frame.op.as_str() {
                "first_token" => return Ok(Event::FirstToken),
                "token" => {
                    let reasoning =
                        frame.body.get("phase").and_then(JsonValue::as_str) == Some("reasoning");
                    let text = frame
                        .body
                        .get("text")
                        .and_then(JsonValue::as_str)
                        .unwrap_or_default()
                        .to_owned();
                    return Ok(Event::Token { reasoning, text });
                }
                "final" => {
                    self.ended = true;
                    return Ok(Event::Final(frame.body));
                }
                "released" | "refused" => {
                    self.ended = true;
                    return Err(Cut);
                }
                _ => {}
            }
        }
    }
}

impl Drop for Call {
    fn drop(&mut self) {
        if self.ended {
            return;
        }
        let Some(channel) = self.channel.take() else {
            return;
        };
        let lease = self.lease.take();
        let request_id = self.request_id;
        // Outside a runtime the connection's close is the cancel: the worker
        // cancels every call of a connection that goes.
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                channel.cancel(request_id).await;
                drop(lease);
            });
        }
    }
}
