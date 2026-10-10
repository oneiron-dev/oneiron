//! The organ side: handshake, frames, a small worker pool and cancel flags.
//!
//! An organ binary is three lines: build the organ, hand it to [`serve`],
//! return its exit code. The runtime maps each call's inputs read-only, runs
//! the verb, unmaps the inputs and sends the reply. It exits when the engine
//! closes the socket, so an organ never outlives its engine.

use std::collections::HashMap;
use std::ops::Deref;
use std::os::fd::{AsFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, mpsc};
use std::thread;

use serde_bytes::ByteBuf;

use crate::frame::{FrameError, recv_frame, send_frame};
use crate::region::{MappedRegion, SharedRegion};
use crate::wire::{
    Call, DEFAULT_FRAME_LIMIT, ErrorCode, FromOrgan, Hash32, HelloAck, INLINE_MAX_BYTES, Input,
    Limits, MAX_FDS_PER_FRAME, Notes, OrganError, OrganIdentity, Outcome, Output, PROTOCOL,
    Payload, Proposal, Reply, ToOrgan, TypedBody, VerbSpec,
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
        }
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
    writer: Mutex<UnixStream>,
    cancels: Mutex<HashMap<u64, Arc<AtomicBool>>>,
    limits: Limits,
}

struct Job {
    call: Call,
    fds: Vec<OwnedFd>,
    cancel: Arc<AtomicBool>,
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
    let (first, _) = recv_frame::<ToOrgan>(stream, DEFAULT_FRAME_LIMIT)?;
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
    send_frame(stream, &ack, &[], hello.limits.max_reply_frame)?;
    let limits = hello.limits;
    let shared = Arc::new(Shared {
        organ,
        verbs,
        writer: Mutex::new(stream.try_clone()?),
        cancels: Mutex::new(HashMap::new()),
        limits,
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
                let cancel = Arc::new(AtomicBool::new(false));
                lock(&shared.cancels).insert(call.id, Arc::clone(&cancel));
                if jobs.send(Job { call, fds, cancel }).is_err() {
                    return Ok(());
                }
            }
            Ok((ToOrgan::Cancel { id, .. }, _)) => {
                if let Some(flag) = lock(&shared.cancels).get(&id) {
                    flag.store(true, Ordering::Relaxed);
                }
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
        lock(&shared.cancels).remove(&id);
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
        if sent.is_err() {
            // The engine is gone or the socket is broken: nothing can reach it.
            std::process::exit(2);
        }
    }
}

fn answer<O: Organ>(shared: &Shared<O>, job: Job) -> (Outcome, Vec<OwnedFd>) {
    let Job { call, fds, cancel } = job;
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
    let ctx = CallContext::new(
        &call.verb,
        call.schema,
        &call.args,
        call.body.as_ref(),
        &inputs,
        shared.limits,
        &cancel,
    );
    let result = catch_unwind(AssertUnwindSafe(|| match call.verb.as_str() {
        VERB_TOUCH => Ok(touch(&ctx)),
        VERB_ECHO => Ok(Answer {
            report: ctx.args.clone(),
            ..Answer::default()
        }),
        _ => shared.organ.call(&ctx),
    }))
    .unwrap_or_else(|_| Err(OrganError::new(ErrorCode::Internal, "the verb panicked")));
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
