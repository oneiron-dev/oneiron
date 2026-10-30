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
//!
//! An op whose answer passes a descriptor (`session.export`) reads its
//! frames with `recvmsg`, each read no longer than what is left of the
//! frame, so no byte or descriptor of a later frame is taken; a buffered
//! read would drop the descriptor. A frame that carried more descriptors
//! than the room for them is refused, and every descriptor a frame brought
//! that its reader does not take is closed.
//!
//! Scheduling (codec v1.3, `oneiron::llm::CallSchedule`): a call's fields
//! ride at its `generate` body's top level, and its `schedule` updates go on
//! its own connection, from any task ([`CallUpdates`]): a connection's
//! writes are serialized, so no two frames interleave. The worker's
//! `admitted` and `schedule_ack` come back among the call's events. A call
//! whose worker could not release its Job (`final` error `release_failed`)
//! keeps its lease until that incarnation ends: the worker still charges it.
use std::io::{self, IoSlice, IoSliceMut};
use std::mem::MaybeUninit;
use std::os::fd::{BorrowedFd, OwnedFd};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use oneiron::llm::{CallSchedule, ScheduleAck, ScheduleUpdate, SessionOp};
use oneiron_driver::{DeviceGrant, WorkerLease};
use oneiron_llm_openai::OpenAiCompatTransportError;
use rustix::net::{
    RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags, SendAncillaryBuffer,
    SendAncillaryMessage, SendFlags, recvmsg, sendmsg,
};
use serde_json::{Value as JsonValue, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, Interest};
use tokio::net::UnixStream;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::Mutex as AsyncMutex;

use super::buffer::{InputRegion, Outbound};
use super::wire::{self, Incoming, Outgoing};

/// A send to a worker that has gone fails with EPIPE rather than raising
/// SIGPIPE; macOS has no such flag, and this process ignores the signal.
#[cfg(target_os = "linux")]
const SEND_FLAGS: SendFlags = SendFlags::NOSIGNAL;
#[cfg(not(target_os = "linux"))]
const SEND_FLAGS: SendFlags = SendFlags::empty();

/// A descriptor received is closed on exec as it arrives; macOS has no such
/// flag, and its descriptors are marked once received.
#[cfg(target_os = "linux")]
const RECV_FLAGS: RecvFlags = RecvFlags::CMSG_CLOEXEC;
#[cfg(not(target_os = "linux"))]
const RECV_FLAGS: RecvFlags = RecvFlags::empty();

/// Room for the descriptors one read can carry: an answer passes at most
/// one, and the room for more lets a frame that carries more be seen and
/// refused.
const FD_ROOM: usize = 8;

/// How much of a frame one read takes: a read size, never a cap on a frame.
const FRAME_CHUNK: usize = 1 << 16;

/// Request ids, unique in this process.
static NEXT_REQUEST_ID: AtomicU64 = AtomicU64::new(1);

pub(in crate::models) fn next_request_id() -> u64 {
    NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed)
}

/// One connection to the worker's socket. Its writer is shared, so a call's
/// `schedule` updates can go from another task.
pub(super) struct Channel {
    reader: BufReader<OwnedReadHalf>,
    writer: Arc<AsyncMutex<OwnedWriteHalf>>,
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
            writer: Arc::new(AsyncMutex::new(writer)),
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
        self.writer.lock().await.write_all(&bytes).await
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
        let mut writer = self.writer.lock().await;
        let stream: &UnixStream = (*writer).as_ref();
        let sent = stream
            .async_io(Interest::WRITABLE, || {
                sendmsg(stream, &[IoSlice::new(&bytes)], &mut control, SEND_FLAGS)
                    .map_err(io::Error::from)
            })
            .await?;
        if sent == 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }
        writer.write_all(&bytes[sent..]).await
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

    /// Fills `buf` with `recvmsg`, keeping every descriptor that rides on
    /// its bytes in `fds`; a read never runs past `buf`. `false` at a clean
    /// end of the stream before the first byte, when `eof_ok`.
    async fn recv_exact_with_fds(
        &mut self,
        buf: &mut [u8],
        fds: &mut Vec<OwnedFd>,
        eof_ok: bool,
    ) -> io::Result<bool> {
        let stream: &UnixStream = self.reader.get_ref().as_ref();
        let mut filled = 0;
        while filled < buf.len() {
            let rest = &mut buf[filled..];
            let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(FD_ROOM))];
            let mut control = RecvAncillaryBuffer::new(&mut space);
            let received = stream
                .async_io(Interest::READABLE, || {
                    recvmsg(
                        stream,
                        &mut [IoSliceMut::new(&mut *rest)],
                        &mut control,
                        RECV_FLAGS,
                    )
                    .map_err(io::Error::from)
                })
                .await?;
            for message in control.drain() {
                if let RecvAncillaryMessage::ScmRights(passed) = message {
                    for fd in passed {
                        #[cfg(not(target_os = "linux"))]
                        rustix::io::fcntl_setfd(&fd, rustix::io::FdFlags::CLOEXEC)?;
                        fds.push(fd);
                    }
                }
            }
            if received.flags.contains(ReturnFlags::CTRUNC) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "a frame carried more descriptors than this side reads",
                ));
            }
            if received.bytes == 0 {
                return if eof_ok && filled == 0 {
                    Ok(false)
                } else {
                    Err(io::ErrorKind::UnexpectedEof.into())
                };
            }
            filled += received.bytes;
        }
        Ok(true)
    }

    /// The next frame and the descriptors that rode on its bytes, read with
    /// `recvmsg` at exactly its length, or `None` once the worker has closed
    /// the connection. Only a channel that has buffered nothing through
    /// [`Self::next`] reads this way.
    async fn next_with_fds(&mut self) -> io::Result<Option<(Incoming, Vec<OwnedFd>)>> {
        if !self.reader.buffer().is_empty() {
            return Err(io::Error::other(
                "the channel holds buffered bytes a descriptor may have ridden on",
            ));
        }
        let mut fds = Vec::new();
        let mut header = [0_u8; wire::HEADER_BYTES];
        if !self
            .recv_exact_with_fds(&mut header, &mut fds, true)
            .await?
        {
            return Ok(None);
        }
        let mut left = u64::from_be_bytes(header);
        let mut payload = Vec::new();
        while left > 0 {
            let want = usize::try_from(left).map_or(FRAME_CHUNK, |rest| rest.min(FRAME_CHUNK));
            let start = payload.len();
            payload.resize(start + want, 0);
            self.recv_exact_with_fds(&mut payload[start..], &mut fds, false)
                .await?;
            left -= u64::try_from(want).unwrap_or(left);
        }
        let frame = wire::decode(&payload).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "the worker sent a frame this side cannot read",
            )
        })?;
        Ok(Some((frame, fds)))
    }

    /// Sends `op` with `body` under a new request id, and with `input`'s
    /// descriptor and its description under `input` when it carries one.
    async fn send_op(
        &mut self,
        op: &str,
        epoch: Option<&str>,
        mut body: JsonValue,
        input: Option<Outbound<'_>>,
    ) -> io::Result<u64> {
        let request_id = next_request_id();
        match input {
            Some(input) => {
                if let Some(fields) = body.as_object_mut() {
                    fields.insert(
                        "input".to_owned(),
                        wire::region(request_id, input.len, input.encoding),
                    );
                }
                self.send_with_fd(op, request_id, epoch, body, input.fd)
                    .await?;
            }
            None => self.send(op, request_id, epoch, body).await?,
        }
        Ok(request_id)
    }

    /// Sends `op` with `body`, and with `input`'s descriptor and its
    /// description under `input` when it carries one, then returns the
    /// worker's frame of the same id: the op's answer, or a `refused`.
    pub(super) async fn exchange(
        &mut self,
        op: &str,
        epoch: Option<&str>,
        body: JsonValue,
        input: Option<Outbound<'_>>,
    ) -> io::Result<Incoming> {
        let request_id = self.send_op(op, epoch, body, input).await?;
        loop {
            match self.next().await? {
                Some(frame) if frame.request_id == request_id => return Ok(frame),
                Some(_) => {}
                None => return Err(io::ErrorKind::UnexpectedEof.into()),
            }
        }
    }

    /// [`Self::exchange`] for an op whose answer passes a descriptor: the
    /// worker's frame of the same id, with every descriptor that rode on
    /// it. Those another frame brought are closed.
    pub(super) async fn exchange_with_fds(
        &mut self,
        op: &str,
        epoch: Option<&str>,
        body: JsonValue,
        input: Option<Outbound<'_>>,
    ) -> io::Result<(Incoming, Vec<OwnedFd>)> {
        let request_id = self.send_op(op, epoch, body, input).await?;
        loop {
            match self.next_with_fds().await? {
                Some((frame, fds)) if frame.request_id == request_id => return Ok((frame, fds)),
                Some(_) => {}
                None => return Err(io::ErrorKind::UnexpectedEof.into()),
            }
        }
    }

    /// Sends `cancel` for `request_id` and waits until the worker says the
    /// call has ended: its `released`, its terminal if it ended first, a
    /// `cancel_ack` that found nothing, or the connection's close. No
    /// deadline: the worker releases at its next pass. False when the
    /// terminal says the worker could not release the call's Job, which it
    /// still charges.
    async fn cancel(mut self, request_id: u64) -> bool {
        if self
            .send("cancel", request_id, None, json!({}))
            .await
            .is_err()
        {
            return true;
        }
        loop {
            match self.next().await {
                Ok(Some(frame)) if frame.request_id == request_id => match frame.op.as_str() {
                    "final" => return !release_failed(&frame.body),
                    "released" | "refused" => return true,
                    "cancel_ack"
                        if frame.body.get("found").and_then(JsonValue::as_bool) == Some(false) =>
                    {
                        return true;
                    }
                    _ => {}
                },
                Ok(Some(_)) => {}
                Ok(None) | Err(_) => return true,
            }
        }
    }
}

/// Whether a call's `final` says the worker could not release its Job: the
/// worker keeps its pages, place and reservation charged until the Job ends
/// there or the incarnation does.
fn release_failed(body: &JsonValue) -> bool {
    body.get("error")
        .and_then(|error| error.get("code"))
        .and_then(JsonValue::as_str)
        == Some(wire::RELEASE_FAILED)
}

/// Holds `lease` until its incarnation ends, on a task of its own: the
/// worker still charges a call it could not release.
fn keep_until_revoked(lease: Option<WorkerLease>, grant: Option<DeviceGrant>) {
    if lease.is_none() && grant.is_none() {
        return;
    }
    tracing::warn!(
        "a native EXL3 call's Job was not released; its lease stays until the worker ends"
    );
    if let Ok(runtime) = tokio::runtime::Handle::try_current() {
        runtime.spawn(async move {
            if let Some(lease) = &lease {
                lease.revocation().await;
            }
            drop((lease, grant));
        });
    }
}

/// A `schedule` sender for one call, on its own connection: it can go from
/// any task while the call's events are read on another.
#[derive(Clone)]
pub(super) struct CallUpdates {
    writer: Arc<AsyncMutex<OwnedWriteHalf>>,
    request_id: u64,
    epoch: String,
}

impl CallUpdates {
    /// Sends `update` under the call's id and epoch; the worker's
    /// `schedule_ack` comes back as [`Event::Scheduled`].
    pub(super) async fn send(&self, update: &ScheduleUpdate) -> io::Result<()> {
        let bytes = Channel::frame(
            "schedule",
            self.request_id,
            Some(&self.epoch),
            update.body(Instant::now()),
        )?;
        self.writer.lock().await.write_all(&bytes).await
    }
}

/// How a call's start went wrong.
pub(super) enum Start {
    /// Nothing left this side: the worker never saw the call. Carries
    /// `OpenAiCompatTransportError::NotSent`.
    NotSent(OpenAiCompatTransportError),
    /// The worker refused it before anything ran, with this body.
    Refused(JsonValue),
    /// The channel failed after the call went out, or the worker answered
    /// with a frame that is neither: it may have run.
    Cut(OpenAiCompatTransportError),
}

/// One event of a call in flight.
pub(super) enum Event {
    /// The worker's scheduler admitted the call: its queue wait, the engine
    /// round, and the worker's cheap stats then.
    Admitted(JsonValue),
    /// The worker sampled the call's first token.
    FirstToken,
    /// A piece of the reply, reasoning or answer.
    Token { reasoning: bool, text: String },
    /// The worker's answer to a `schedule` update ([`CallUpdates`]).
    Scheduled(Box<ScheduleAck>),
    /// The call's terminal, with its body.
    Final(JsonValue),
}

/// The channel failed, or the worker ended the call some other way, before
/// its `final`: the call may have run. Carries what happened.
pub(super) struct Cut(pub(super) OpenAiCompatTransportError);

/// A failed step before the call left this side, logged.
fn not_sent(stage: &'static str, cause: impl std::fmt::Display) -> Start {
    Start::NotSent(logged(OpenAiCompatTransportError::NotSent {
        stage,
        detail: cause.to_string(),
    }))
}

/// A channel failure after the call went out, logged; `None` is the
/// worker's close.
fn io_fault(stage: &'static str, cause: Option<io::Error>) -> OpenAiCompatTransportError {
    let detail = cause.map_or_else(|| "closed by the worker".to_owned(), |e| e.to_string());
    logged(OpenAiCompatTransportError::Io { stage, detail })
}

/// The worker's `refused` body as the typed refusal, logged.
pub(super) fn refusal(body: &JsonValue) -> OpenAiCompatTransportError {
    let message = body
        .get("message")
        .and_then(JsonValue::as_str)
        .map_or_else(|| body.to_string(), str::to_owned);
    logged(OpenAiCompatTransportError::Refused {
        code: wire::refusal_code(body).to_owned(),
        message,
    })
}

/// A frame the call cannot take where it came, logged.
fn unexpected(op: &str, at: &str) -> OpenAiCompatTransportError {
    logged(OpenAiCompatTransportError::UnexpectedFrame(format!(
        "`{op}` {at}"
    )))
}

/// Every native call fault reaches the log with its cause; the caller's
/// `LlmError` keeps only the retryable cut it always was.
fn logged(error: OpenAiCompatTransportError) -> OpenAiCompatTransportError {
    tracing::warn!(%error, "native EXL3 call failed");
    error
}

/// One `generate` in flight on its own connection.
pub(super) struct Call {
    channel: Option<Channel>,
    request_id: u64,
    /// The incarnation the call went to, which its updates name.
    epoch: String,
    /// The lease on the incarnation the call went to, held until the call
    /// has ended there.
    lease: Option<WorkerLease>,
    /// Its device grant follows exactly the same release/reap custody.
    grant: Option<DeviceGrant>,
    ended: bool,
}

impl Call {
    /// Connects to `path`, sends the call with `conversation` as its input
    /// region and `schedule`'s fields at its body's top level, and waits
    /// for the worker to accept or refuse it. A call that names a `session`
    /// working branch goes as `session.generate`, its body otherwise a
    /// `generate`'s.
    #[expect(
        clippy::too_many_arguments,
        reason = "each argument is one fact of the call being started"
    )]
    pub(super) async fn start(
        path: &Path,
        epoch: &str,
        conversation: &JsonValue,
        params: JsonValue,
        stream: bool,
        lease: Option<WorkerLease>,
        session: Option<JsonValue>,
        schedule: Option<&CallSchedule>,
    ) -> Result<Self, Start> {
        let bytes = serde_json::to_vec(conversation).map_err(|e| not_sent("encode input", e))?;
        let input = InputRegion::new(&bytes).map_err(|e| not_sent("input region", e))?;
        let mut channel = Channel::connect(path)
            .await
            .map_err(|e| not_sent("connect", e))?;
        let request_id = next_request_id();
        let mut body = wire::generate_body(request_id, input.len(), params, stream, schedule);
        let op = match session {
            Some(session) => {
                if let Some(fields) = body.as_object_mut() {
                    fields.insert("session".to_owned(), session);
                }
                SessionOp::Generate.wire_name()
            }
            None => "generate",
        };
        let sent = channel
            .send_with_fd(op, request_id, Some(epoch), body, input.fd())
            .await;
        let mut call = Self {
            channel: Some(channel),
            request_id,
            epoch: epoch.to_owned(),
            lease,
            grant: None,
            ended: false,
        };
        if let Err(error) = sent {
            call.ended = true;
            return Err(Start::Cut(io_fault("send generate", Some(error))));
        }
        loop {
            let frame = match call.channel_mut().next().await {
                Ok(Some(frame)) => frame,
                Ok(None) => {
                    call.ended = true;
                    return Err(Start::Cut(io_fault("await accepted", None)));
                }
                Err(error) => {
                    call.ended = true;
                    return Err(Start::Cut(io_fault("await accepted", Some(error))));
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
                op => {
                    call.ended = true;
                    return Err(Start::Cut(unexpected(op, "before `accepted`")));
                }
            }
        }
    }

    /// Binds the accepted call's device grant to its release custody.
    pub(super) fn set_grant(&mut self, grant: Option<DeviceGrant>) {
        self.grant = grant;
    }

    fn channel_mut(&mut self) -> &mut Channel {
        self.channel
            .as_mut()
            .unwrap_or_else(|| unreachable!("a call keeps its channel until it drops"))
    }

    /// A sender of this call's `schedule` updates, on its connection.
    pub(super) fn updates(&self) -> Option<CallUpdates> {
        let channel = self.channel.as_ref()?;
        Some(CallUpdates {
            writer: Arc::clone(&channel.writer),
            request_id: self.request_id,
            epoch: self.epoch.clone(),
        })
    }

    /// The call's next event, until its `final`.
    pub(super) async fn next(&mut self) -> Result<Event, Cut> {
        if self.ended {
            return Err(Cut(OpenAiCompatTransportError::Io {
                stage: "receive",
                detail: "the call already ended".to_owned(),
            }));
        }
        loop {
            let frame = match self.channel_mut().next().await {
                Ok(Some(frame)) => frame,
                Ok(None) => {
                    self.ended = true;
                    return Err(Cut(io_fault("receive", None)));
                }
                Err(error) => {
                    self.ended = true;
                    return Err(Cut(io_fault("receive", Some(error))));
                }
            };
            if frame.request_id != self.request_id {
                continue;
            }
            match frame.op.as_str() {
                "admitted" => return Ok(Event::Admitted(frame.body)),
                "first_token" => return Ok(Event::FirstToken),
                "schedule_ack" => match serde_json::from_value::<ScheduleAck>(frame.body) {
                    Ok(ack) => return Ok(Event::Scheduled(Box::new(ack))),
                    // An answer that does not read is logged; the call goes on.
                    Err(error) => {
                        tracing::warn!(%error, "a native EXL3 schedule_ack does not read");
                    }
                },
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
                    if release_failed(&frame.body) {
                        keep_until_revoked(self.lease.take(), self.grant.take());
                    }
                    return Ok(Event::Final(frame.body));
                }
                "refused" => {
                    self.ended = true;
                    return Err(Cut(refusal(&frame.body)));
                }
                "released" => {
                    self.ended = true;
                    return Err(Cut(unexpected("released", "before `final`")));
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
        let grant = self.grant.take();
        let request_id = self.request_id;
        // Outside a runtime the connection's close is the cancel: the worker
        // cancels every call of a connection that goes.
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                if !channel.cancel(request_id).await
                    && let Some(lease) = &lease
                {
                    // The worker still charges the call: so does the lease.
                    lease.revocation().await;
                }
                drop((lease, grant));
            });
        }
    }
}
