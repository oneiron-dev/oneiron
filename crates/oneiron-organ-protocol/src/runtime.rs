//! The organ side: handshake, frames, a small worker pool and cancel flags.
//!
//! An organ binary is three lines: build the organ, hand it to [`serve`],
//! return its exit code. The runtime maps each call's inputs read-only, runs
//! the verb, unmaps the inputs and sends the reply. It exits when the engine
//! closes the socket, so an organ never outlives its engine.
//!
//! On a 1.1 session a verb may ask the engine for something mid-call
//! ([`CallContext::ask`]). The reader thread routes each answer to the verb
//! that waits for it, and a cancel wakes that verb at once.

use std::collections::HashMap;
use std::ops::Deref;
use std::os::fd::{AsFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, mpsc};
use std::thread;

use serde_bytes::ByteBuf;

use crate::frame::{FrameError, recv_frame, send_frame};
use crate::region::{MappedRegion, SharedRegion};
use crate::wire::{
    Ask, AskAnswer, AskCode, AskData, AskOutcome, AskRefusal, Call, ErrorCode, FromOrgan, Hash32,
    HelloAck, INITIAL_HANDSHAKE_FRAME_BYTES, INLINE_MAX_BYTES, Input, Limits, MAX_FDS_PER_FRAME,
    Notes, OrganError, OrganIdentity, Outcome, Output, PROTOCOL, Payload, Proposal,
    ProtocolVersion, Reply, ToOrgan, TypedBody, VerbSpec,
};

/// Reads every input byte and folds it; the host's read-throughput probe.
pub const VERB_TOUCH: &str = "organ.touch";
/// Returns its args as the report; the host's round-trip probe.
pub const VERB_ECHO: &str = "organ.echo";

/// One organ: a set of verbs over typed bodies and read-only inputs.
pub trait Organ: Send + Sync + 'static {
    fn identity(&self) -> OrganIdentity;
    fn verbs(&self) -> Vec<VerbSpec>;
    /// Runs one verb. A long verb checks [`CallContext::check_cancel`]
    /// between steps.
    ///
    /// # Errors
    /// An [`OrganError`] the engine returns to its caller unchanged.
    fn call(&self, call: &CallContext<'_>) -> Result<Answer, OrganError>;
}

/// What a verb returns. The runtime decides how each output crosses.
#[derive(Debug, Clone, PartialEq)]
pub struct Answer {
    pub body: Option<TypedBody>,
    pub outputs: Vec<OutputBytes>,
    pub report: rmpv::Value,
    pub notes: Notes,
}

impl Default for Answer {
    fn default() -> Self {
        Self {
            body: None,
            outputs: Vec::new(),
            report: rmpv::Value::Nil,
            notes: Notes::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputBytes {
    pub name: String,
    pub media_type: String,
    pub bytes: Vec<u8>,
}

/// One call as a verb sees it.
#[derive(Debug)]
pub struct CallContext<'a> {
    pub verb: &'a str,
    pub schema: u32,
    pub args: &'a rmpv::Value,
    pub body: Option<&'a TypedBody>,
    pub inputs: &'a [InputBytes],
    pub limits: Limits,
    cancel: &'a AtomicBool,
    asker: Asker,
}

impl<'a> CallContext<'a> {
    /// A context for calling an organ in this process, as the bench's
    /// in-process baseline and an embedding host do.
    #[must_use]
    pub fn new(
        verb: &'a str,
        schema: u32,
        args: &'a rmpv::Value,
        body: Option<&'a TypedBody>,
        inputs: &'a [InputBytes],
        limits: Limits,
        cancel: &'a AtomicBool,
    ) -> Self {
        Self {
            verb,
            schema,
            args,
            body,
            inputs,
            limits,
            cancel,
            asker: Asker::default(),
        }
    }

    fn with_asker(mut self, asker: Asker) -> Self {
        self.asker = asker;
        self
    }

    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }

    /// # Errors
    /// [`ErrorCode::Cancelled`] once the engine has cancelled this call.
    pub fn check_cancel(&self) -> Result<(), OrganError> {
        if self.is_cancelled() {
            Err(OrganError::new(ErrorCode::Cancelled, "cancelled"))
        } else {
            Ok(())
        }
    }

    /// Asks the engine for something mid-call and waits for its answer.
    /// One ask is in flight per call: a second, from another thread of the
    /// same verb, waits for the first. A refusal does not stop the call; the
    /// verb goes on or fails, as it chooses.
    ///
    /// # Errors
    /// The engine's refusal; [`AskCode::Unsupported`] on a 1.0 session or
    /// outside a served call, where nothing is sent; [`AskCode::Cancelled`]
    /// once the call is cancelled. A value of any size is sent whole: past
    /// [`crate::ASK_VALUE_MAX`] the engine's `[limits]` row asks, and reads it.
    pub fn ask(&self, verb: &str, value: rmpv::Value) -> Result<AskReply, AskRefusal> {
        self.asker.ask(verb, value)
    }

    /// This call's way to ask, for code that must own it, such as a library
    /// that takes a `'static` signer or fetcher. It is good for the call
    /// only: once the call has replied, it refuses without sending.
    #[must_use]
    pub fn asker(&self) -> Asker {
        self.asker.clone()
    }
}

/// What the engine answered.
#[derive(Debug)]
pub struct AskReply {
    pub value: rmpv::Value,
    /// Bytes beside the value.
    pub data: Option<AskBytes>,
}

/// An answer's bytes, in the organ's own memory. A region the engine
/// sealed is copied out and unmapped as the answer arrives, so the engine's
/// pages are never held past the ask, and what the organ keeps counts
/// against its own memory grant.
#[derive(Debug)]
pub struct AskBytes {
    pub content_hash: Hash32,
    bytes: Vec<u8>,
}

impl Deref for AskBytes {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.bytes
    }
}

/// One served call's way to ask, and the ask that waits for its answer.
#[derive(Debug, Default)]
struct CallState {
    cancel: AtomicBool,
    waiting: Mutex<Option<(u32, mpsc::SyncSender<Wake>)>>,
}

impl CallState {
    /// Marks the call cancelled and wakes the ask that waits, if any. The
    /// flag is set before the wait is looked at, and an ask registers its
    /// wait before it reads the flag, so one of the two always sees the
    /// other.
    fn cancel(&self) {
        self.cancel.store(true, Ordering::SeqCst);
        if let Some((_, wake)) = lock(&self.waiting).take() {
            let _ = wake.try_send(Wake::Cancelled);
        }
    }

    /// Hands an answer to the ask it names; any other answer is dropped.
    fn answer(&self, answer: AskAnswer, fds: Vec<OwnedFd>) {
        let mut waiting = lock(&self.waiting);
        if waiting.as_ref().is_some_and(|(id, _)| *id == answer.id)
            && let Some((_, wake)) = waiting.take()
        {
            let _ = wake.try_send(Wake::Answer(answer.outcome, fds));
        }
    }
}

#[derive(Debug)]
enum Wake {
    Answer(AskOutcome, Vec<OwnedFd>),
    Cancelled,
}

/// One call's way to ask the engine ([`CallContext::ask`]). Cloning it
/// shares the call's one ask in flight.
#[derive(Debug, Clone, Default)]
pub struct Asker {
    line: Option<Arc<AskLine>>,
}

impl Asker {
    /// [`CallContext::ask`], from code that owns the asker.
    ///
    /// # Errors
    /// As [`CallContext::ask`]; outside a served call, or once the call has
    /// replied, [`AskCode::Unsupported`] or [`AskCode::Cancelled`] without
    /// sending.
    pub fn ask(&self, verb: &str, value: rmpv::Value) -> Result<AskReply, AskRefusal> {
        match &self.line {
            Some(line) => line.ask(verb, value),
            None => Err(AskRefusal::new(
                AskCode::Unsupported,
                "this call has no engine to ask",
            )),
        }
    }
}

/// How a served call asks: the socket's writer, this call's state.
#[derive(Debug)]
struct AskLine {
    writer: Arc<Mutex<UnixStream>>,
    limit: u32,
    call: u64,
    state: Arc<CallState>,
    asks: bool,
    next: AtomicU32,
    one: Mutex<()>,
}

impl AskLine {
    fn ask(&self, verb: &str, value: rmpv::Value) -> Result<AskReply, AskRefusal> {
        if !self.asks {
            return Err(AskRefusal::new(
                AskCode::Unsupported,
                "the engine speaks 1.0, which carries no asks",
            ));
        }
        let cancelled = || AskRefusal::new(AskCode::Cancelled, "the call was cancelled");
        let _one = lock(&self.one);
        let id = self.next.fetch_add(1, Ordering::SeqCst) + 1;
        let (wake, woken) = mpsc::sync_channel(1);
        *lock(&self.state.waiting) = Some((id, wake));
        // The flag is read under the writer: the call's reply needs the
        // writer too, and is sent only after the flag is set, so an ask is
        // either on the wire before the reply or never sent.
        let writer = lock(&self.writer);
        if self.state.cancel.load(Ordering::SeqCst) {
            lock(&self.state.waiting).take();
            return Err(cancelled());
        }
        let ask = FromOrgan::Ask(Ask {
            call: self.call,
            id,
            verb: verb.to_owned(),
            value,
        });
        let sent = send_frame(&writer, &ask, &[], self.limit);
        drop(writer);
        if sent.is_err() {
            lock(&self.state.waiting).take();
            return Err(AskRefusal::new(AskCode::Failed, "the ask was not sent"));
        }
        match woken.recv() {
            Ok(Wake::Answer(AskOutcome::Answered { value, data }, fds)) => Ok(AskReply {
                value,
                data: data.map(|data| answer_bytes(data, fds)).transpose()?,
            }),
            Ok(Wake::Answer(AskOutcome::Refused(refusal), _)) => Err(refusal),
            Ok(Wake::Cancelled) | Err(_) => Err(cancelled()),
        }
    }
}

fn answer_bytes(data: AskData, fds: Vec<OwnedFd>) -> Result<AskBytes, AskRefusal> {
    let broken = |what: &str| AskRefusal::new(AskCode::Failed, format!("answer data: {what}"));
    let bytes = match data.data {
        Payload::Inline(bytes) if bytes.len() as u64 == data.len => bytes.into_vec(),
        Payload::Inline(_) => return Err(broken("inline length")),
        Payload::Slot(slot) => {
            let fd = fds
                .into_iter()
                .nth(usize::from(slot))
                .ok_or_else(|| broken("slot"))?;
            // Mapped, copied, and unmapped here; the descriptor closes too.
            MappedRegion::map(fd, data.len)
                .map_err(|err| broken(&err.to_string()))?
                .to_vec()
        }
    };
    Ok(AskBytes {
        content_hash: data.content_hash,
        bytes,
    })
}

/// One input's bytes, valid for the call.
#[derive(Debug)]
pub struct InputBytes {
    pub media_type: String,
    pub content_hash: Hash32,
    data: InputData,
}

#[derive(Debug)]
enum InputData {
    Inline(Vec<u8>),
    Mapped(MappedRegion),
}

impl InputBytes {
    /// An input held in this process's own memory.
    #[must_use]
    pub fn inline(media_type: impl Into<String>, bytes: Vec<u8>) -> Self {
        Self {
            media_type: media_type.into(),
            content_hash: Hash32::of(&bytes),
            data: InputData::Inline(bytes),
        }
    }
}

impl Deref for InputBytes {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        match &self.data {
            InputData::Inline(bytes) => bytes,
            InputData::Mapped(region) => region,
        }
    }
}

/// Serves `organ` on the descriptor the host passed (`ONEIRON_ORGAN_FD`,
/// default 3) until the engine closes it.
#[must_use]
pub fn serve<O: Organ>(organ: O) -> ExitCode {
    let fd = std::env::var("ONEIRON_ORGAN_FD")
        .ok()
        .and_then(|value| value.parse::<i32>().ok())
        .unwrap_or(3);
    // SAFETY: the host starts this process with its end of the organ socket
    // on this descriptor and nothing else in the process owns it.
    let stream = unsafe { UnixStream::from_raw_fd(fd) };
    match serve_stream(Arc::new(organ), &stream) {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::from(1),
    }
}

struct Shared<O> {
    organ: Arc<O>,
    verbs: Vec<VerbSpec>,
    writer: Arc<Mutex<UnixStream>>,
    calls: Mutex<HashMap<u64, Arc<CallState>>>,
    limits: Limits,
    /// The version this session speaks: the lower minor of both sides.
    session: ProtocolVersion,
}

struct Job {
    call: Call,
    fds: Vec<OwnedFd>,
    state: Arc<CallState>,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Serves `organ` on `stream`: the handshake, then calls until the engine
/// closes the socket or sends `shutdown`.
///
/// # Errors
/// A broken frame or a protocol violation by the engine.
pub fn serve_stream<O: Organ>(organ: Arc<O>, stream: &UnixStream) -> Result<(), FrameError> {
    // The hello and the ack cross under the pre-session bound alone
    // (FIX 7648): no session's frame limit holds until the handshake sets
    // one.
    let (first, _) = recv_frame::<ToOrgan>(stream, INITIAL_HANDSHAKE_FRAME_BYTES)?;
    let ToOrgan::Hello(hello) = first else {
        return Err(FrameError::Protocol("the first frame must be hello"));
    };
    let mut verbs = organ.verbs();
    verbs.extend(builtin_verbs());
    let ack = FromOrgan::HelloAck(HelloAck {
        protocol: PROTOCOL,
        organ: organ.identity(),
        verbs: verbs.clone(),
    });
    send_frame(stream, &ack, &[], INITIAL_HANDSHAKE_FRAME_BYTES)?;
    let limits = hello.limits;
    let session = PROTOCOL.session(hello.protocol).unwrap_or(ProtocolVersion {
        major: PROTOCOL.major,
        minor: 0,
    });
    let shared = Arc::new(Shared {
        organ,
        verbs,
        writer: Arc::new(Mutex::new(stream.try_clone()?)),
        calls: Mutex::new(HashMap::new()),
        limits,
        session,
    });
    let (jobs, queue) = mpsc::channel::<Job>();
    let queue = Arc::new(Mutex::new(queue));
    for _ in 0..limits.threads.max(1) {
        let shared = Arc::clone(&shared);
        let queue = Arc::clone(&queue);
        thread::spawn(move || work(&shared, &queue));
    }
    loop {
        crate::spin::poll_readable(stream);
        match recv_frame::<ToOrgan>(stream, limits.max_call_frame) {
            Ok((ToOrgan::Call(call), fds)) => {
                let state = Arc::new(CallState::default());
                lock(&shared.calls).insert(call.id, Arc::clone(&state));
                if jobs.send(Job { call, fds, state }).is_err() {
                    return Ok(());
                }
            }
            Ok((ToOrgan::Cancel { id, .. }, _)) => {
                let state = lock(&shared.calls).get(&id).cloned();
                if let Some(state) = state {
                    state.cancel();
                }
            }
            // An answer for a call that has ended is dropped with its fds.
            Ok((ToOrgan::Answer(answer), fds)) if shared.session.asks() => {
                let state = lock(&shared.calls).get(&answer.call).cloned();
                if let Some(state) = state {
                    state.answer(answer, fds);
                }
            }
            Ok((ToOrgan::Answer(_), _)) => {
                return Err(FrameError::Protocol("an answer on a 1.0 session"));
            }
            Ok((ToOrgan::Shutdown, _)) | Err(FrameError::Closed) => return Ok(()),
            Ok((ToOrgan::Hello(_), _)) => return Err(FrameError::Protocol("a second hello")),
            Err(err) => return Err(err),
        }
    }
}

fn builtin_verbs() -> [VerbSpec; 2] {
    [VERB_TOUCH, VERB_ECHO].map(|name| VerbSpec {
        name: name.to_owned(),
        schema: 1,
        kinds: Vec::new(),
    })
}

fn work<O: Organ>(shared: &Shared<O>, queue: &Mutex<mpsc::Receiver<Job>>) {
    loop {
        // Spinning holds the queue: the other workers would only wait on it.
        let next = crate::spin::recv_spinning(&lock(queue), None);
        let Ok(job) = next else { return };
        let id = job.call.id;
        let (outcome, fds) = answer(shared, job);
        lock(&shared.calls).remove(&id);
        let borrowed: Vec<BorrowedFd<'_>> = fds.iter().map(AsFd::as_fd).collect();
        let writer = lock(&shared.writer);
        let reply = FromOrgan::Reply(Reply { id, outcome });
        let sent = match send_frame(&writer, &reply, &borrowed, shared.limits.max_reply_frame) {
            // Nothing left, so the engine can still be told why.
            Err(err) if err.is_local() => {
                let code = if matches!(err, FrameError::Encode(_)) {
                    ErrorCode::Internal
                } else {
                    ErrorCode::TooLarge
                };
                let refused = FromOrgan::Reply(Reply {
                    id,
                    outcome: Outcome::Error(OrganError::new(
                        code,
                        format!("reply not sent: {err}"),
                    )),
                });
                send_frame(&writer, &refused, &[], shared.limits.max_reply_frame)
            }
            other => other,
        };
        // The engine may send the next call the moment the reply lands:
        // close the outputs' descriptors at once.
        drop(borrowed);
        drop(fds);
        drop(writer);
        if sent.is_err() {
            // The engine is gone or the socket is broken: nothing can reach it.
            std::process::exit(2);
        }
    }
}

fn answer<O: Organ>(shared: &Shared<O>, job: Job) -> (Outcome, Vec<OwnedFd>) {
    let Job { call, fds, state } = job;
    let Some(spec) = shared.verbs.iter().find(|spec| spec.name == call.verb) else {
        let error = OrganError::new(ErrorCode::UnknownVerb, call.verb);
        return (Outcome::Error(error), Vec::new());
    };
    if spec.schema != call.schema {
        let detail = format!(
            "{} speaks schema {}, not {}",
            spec.name, spec.schema, call.schema
        );
        return (
            Outcome::Error(OrganError::new(ErrorCode::SchemaMismatch, detail)),
            Vec::new(),
        );
    }
    let inputs = match map_inputs(call.inputs, fds) {
        Ok(inputs) => inputs,
        Err(error) => return (Outcome::Error(error), Vec::new()),
    };
    let asker = Asker {
        line: Some(Arc::new(AskLine {
            writer: Arc::clone(&shared.writer),
            limit: shared.limits.max_reply_frame,
            call: call.id,
            state: Arc::clone(&state),
            asks: shared.session.asks(),
            next: AtomicU32::new(0),
            one: Mutex::new(()),
        })),
    };
    let ctx = CallContext::new(
        &call.verb,
        call.schema,
        &call.args,
        call.body.as_ref(),
        &inputs,
        shared.limits,
        &state.cancel,
    )
    .with_asker(asker);
    let result = catch_unwind(AssertUnwindSafe(|| match call.verb.as_str() {
        VERB_TOUCH => Ok(touch(&ctx)),
        VERB_ECHO => Ok(Answer {
            report: ctx.args.clone(),
            ..Answer::default()
        }),
        _ => shared.organ.call(&ctx),
    }))
    .unwrap_or_else(|_| Err(OrganError::new(ErrorCode::Internal, "the verb panicked")));
    // An asker the verb kept refuses from here on, without sending.
    state.cancel();
    drop(inputs);
    match result.and_then(encode_answer) {
        Ok((proposal, fds)) => (Outcome::Proposal(proposal), fds),
        Err(error) => (Outcome::Error(error), Vec::new()),
    }
}

fn map_inputs(inputs: Vec<Input>, fds: Vec<OwnedFd>) -> Result<Vec<InputBytes>, OrganError> {
    let mut slots: Vec<Option<OwnedFd>> = fds.into_iter().map(Some).collect();
    inputs
        .into_iter()
        .map(|input| {
            let data = match input.data {
                Payload::Inline(bytes) if bytes.len() as u64 == input.len => {
                    InputData::Inline(bytes.into_vec())
                }
                Payload::Inline(_) => {
                    return Err(OrganError::new(ErrorCode::BadRequest, "inline length"));
                }
                Payload::Slot(slot) => {
                    let fd = slots
                        .get_mut(usize::from(slot))
                        .and_then(Option::take)
                        .ok_or_else(|| OrganError::new(ErrorCode::BadRequest, "input slot"))?;
                    let region = MappedRegion::map(fd, input.len).map_err(|err| {
                        OrganError::new(ErrorCode::BadRequest, format!("input region: {err}"))
                    })?;
                    InputData::Mapped(region)
                }
            };
            Ok(InputBytes {
                media_type: input.media_type,
                content_hash: input.content_hash,
                data,
            })
        })
        .collect()
}

fn touch(ctx: &CallContext<'_>) -> Answer {
    let fold = ctx
        .inputs
        .iter()
        .fold(0, |fold, input| fold ^ touch_fold(input));
    let len: u64 = ctx.inputs.iter().map(|input| input.len() as u64).sum();
    let report = rmpv::Value::Map(vec![
        ("fold".into(), fold.into()),
        ("len".into(), len.into()),
    ]);
    Answer {
        report,
        ..Answer::default()
    }
}

/// The fold `organ.touch` reports for one input: the XOR of its
/// little-endian 8-byte words, the tail packed low-first.
#[must_use]
pub fn touch_fold(bytes: &[u8]) -> u64 {
    let mut fold = 0u64;
    let mut words = bytes.chunks_exact(8);
    for word in &mut words {
        fold ^= <[u8; 8]>::try_from(word).map_or(0, u64::from_le_bytes);
    }
    for (shift, byte) in words.remainder().iter().enumerate() {
        fold ^= u64::from(*byte) << (8 * shift);
    }
    fold
}

fn encode_answer(answer: Answer) -> Result<(Proposal, Vec<OwnedFd>), OrganError> {
    let mut fds = Vec::new();
    let mut outputs = Vec::with_capacity(answer.outputs.len());
    for output in answer.outputs {
        let data = if output.bytes.len() <= INLINE_MAX_BYTES || !cfg!(target_os = "linux") {
            Payload::Inline(ByteBuf::from(output.bytes))
        } else {
            if fds.len() >= MAX_FDS_PER_FRAME {
                return Err(OrganError::new(
                    ErrorCode::TooLarge,
                    format!("more than {MAX_FDS_PER_FRAME} region outputs"),
                ));
            }
            let region = SharedRegion::from_bytes(&output.bytes).map_err(|err| {
                OrganError::new(ErrorCode::Internal, format!("output region: {err}"))
            })?;
            let slot = u16::try_from(fds.len())
                .map_err(|_| OrganError::new(ErrorCode::TooLarge, "too many outputs"))?;
            fds.push(region.into_fd());
            Payload::Slot(slot)
        };
        outputs.push(Output {
            name: output.name,
            media_type: output.media_type,
            data,
        });
    }
    let proposal = Proposal {
        body: answer.body,
        outputs,
        report: answer.report,
        notes: answer.notes,
    };
    Ok((proposal, fds))
}
