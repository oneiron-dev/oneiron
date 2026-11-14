//! The MCP stdio transport (row L8-27): a connector this host installed as
//! `mcp_stdio` is a child process it starts under the vault's runner fence
//! (canon `#runner-fence`), and speaks MCP to as newline-delimited JSON-RPC
//! over the child's standard input and output.
//!
//! One child serves each connector name, started at its first call, kept
//! for the calls after it, and started again after it exits, with a new
//! session manifest each time. One call is in flight on a child at a time.
//! A child that keeps exiting (five starts within a minute) is not started
//! again until that minute has passed: its calls are not sent meanwhile.
//! A changed command, environment, working directory or pinned revision
//! starts a new child.
//!
//! A writer thread owns the child's input, so no write waits past its
//! request's bound: writing a request and reading its answer share one
//! bound, and every wait ends within [`STOP_CHECK`] once the server stops.
//!
//! The child starts with only `HOME`, `LOGNAME`, `PATH`, `SHELL`, `TERM` and
//! `USER` of this process's environment (the MCP SDKs' default for a stdio
//! server), its own `TMPDIR`, and the section's `env`. Nothing is presented
//! to it: a send whose route would present a credential is not sent until
//! the broker path (B2). The client declares no capability, so it is asked
//! no question; a `ping` is answered, every other request from the child is
//! refused, and its notifications are dropped. A line on its standard output
//! that is not JSON is dropped (a log line the child should have written to
//! its standard error, which is read and dropped). A line over 8 MiB is
//! unreadable.
//!
//! Each call's session manifest (backend `runner:connector-stdio`) names the
//! child's program and arguments and states the fence's ruleset hash, or
//! that the fence is unproven; it rides on the call's delivered reply.

use std::collections::{BTreeMap, VecDeque};
use std::io::{self, BufRead, Write as _};
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, sync_channel};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::thread;

use oneiron::outbound_consent::ZeroizingBufReader;
use oneiron_container::SessionManifest;
use zeroize::{Zeroize as _, Zeroizing};

use super::*;
use crate::runtime::runner_fence::{HostRunnerFence, runner_session_manifest};

/// The backend a stdio connector child's session manifest names.
pub const STDIO_RUNNER_BACKEND: &str = "runner:connector-stdio";

/// The variables a child keeps of this process's environment: the MCP
/// SDKs' default inherited set on a Unix host.
const INHERITED_ENV: [&str; 6] = ["HOME", "LOGNAME", "PATH", "SHELL", "TERM", "USER"];

/// The longest line read from a child's standard output.
const MAX_LINE_BYTES: usize = 8 * 1024 * 1024;

/// Lines read ahead of the call that reads them: the child waits on its
/// pipe past this many.
const READ_AHEAD_LINES: usize = 4;

/// How long a child has to exit once its input is closed, before it is
/// killed.
const STOP_GRACE: Duration = Duration::from_secs(2);

/// How often a stopping child is checked for its exit.
const STOP_POLL: Duration = Duration::from_millis(20);

/// How often a wait on a child checks whether its server is stopping.
const STOP_CHECK: Duration = Duration::from_millis(100);

/// A connector whose child started this many times within
/// [`RESTART_WINDOW`] is not started again until the window has passed.
const STARTS_PER_WINDOW: usize = 5;
const RESTART_WINDOW: Duration = Duration::from_secs(60);

/// What one child's standard output said: a JSON message and its own
/// bytes, or a line too long to read.
enum Frame {
    Message(Value, Vec<u8>),
    Overlong,
}

/// Why a request went and no answer was read.
enum NoAnswer {
    /// The child's output ended: it exited or closed it.
    Ended,
    /// No answer came within the bound, or the server began to stop.
    TimedOut,
    /// A line too long to read came where the answer was awaited.
    Unreadable,
}

/// Why a line was not written to the child's input.
enum Unwritten {
    /// It did not go: the input is closed, or the bound had passed or the
    /// server was stopping before it was handed to the writer.
    NotSent,
    /// It may still go: the writer had it and had not written all of it
    /// when the bound passed or the server began to stop.
    Pending,
}

/// What starts one stdio connector child.
pub struct StdioStart<'a> {
    /// The connector's catalog name.
    pub name: &'a str,
    pub connector: &'a ConnectorHostConfig,
    /// The fence the child runs under; `None` runs it unfenced, with no
    /// session manifest (the vault's trees could not be named).
    pub fence: Option<&'a HostRunnerFence>,
    /// The revision `initialize` asks for.
    pub requested_revision: &'a str,
    /// Whether the revision the child answers with is one this client takes.
    pub accepts_revision: &'a dyn Fn(&str) -> bool,
    /// Set once the server stops: every wait on the child then ends within
    /// [`STOP_CHECK`]. `None` waits out each bound.
    pub stop: Option<&'a Arc<AtomicBool>>,
}

/// One running stdio connector child, its MCP session initialized.
/// Dropping it closes its input, waits [`STOP_GRACE`] for it to exit, then
/// kills and reaps it.
pub struct StdioChild {
    process: Child,
    /// Lines for the writer thread, which owns the child's input and closes
    /// it once this is dropped; `None` once the input counts as closed.
    lines: Option<SyncSender<Zeroizing<Vec<u8>>>>,
    /// The writer's word on each line: written, or the input is closed.
    written: Receiver<bool>,
    frames: Receiver<Frame>,
    /// The endpoint the child was started for: its connector's command,
    /// environment and working directory.
    identity: String,
    /// The revision its `initialize` agreed.
    revision: String,
    next_id: u64,
    session_manifest: Option<SessionManifest>,
    /// The child's `TMPDIR`, removed once it is stopped.
    scratch: Option<tempfile::TempDir>,
    /// See [`StdioStart::stop`].
    stop: Option<Arc<AtomicBool>>,
}

impl StdioChild {
    /// Starts the connector's child and initializes its session.
    ///
    /// # Errors
    /// The command did not start, the child did not answer `initialize`
    /// within the handshake bound, or it answered a revision this client
    /// does not take. The child is stopped.
    pub fn start(start: &StdioStart<'_>) -> Result<Self, &'static str> {
        let (program, args) = start
            .connector
            .command
            .split_first()
            .ok_or("the connector names no command")?;
        let workdir = start.connector.cwd.as_deref();
        let (mut command, outcome, scratch) = match start.fence {
            Some(fence) => {
                let runner = fence.command(program, workdir);
                (runner.command, Some(runner.outcome), runner.scratch)
            }
            None => {
                let mut command = oneiron_spawn::command(program);
                command.current_dir(workdir.unwrap_or(Path::new("/")));
                (command, None, None)
            }
        };
        command.args(args).env_clear();
        for name in INHERITED_ENV {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        if let Some(scratch) = &scratch {
            command.env("TMPDIR", scratch.path());
        }
        command
            .envs(&start.connector.env)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut process = command
            .spawn()
            .map_err(|_| "the connector's command did not start")?;
        let stdout = process.stdout.take();
        let stderr = process.stderr.take();
        let stdin = process.stdin.take();
        let (sender, frames) = sync_channel(READ_AHEAD_LINES);
        let (lines, queued) = sync_channel(1);
        let (wrote, written) = sync_channel(1);
        // From here on, dropping the child stops the process.
        let mut child = Self {
            process,
            lines: Some(lines),
            written,
            frames,
            identity: start.connector.installed_endpoint(start.name),
            revision: String::new(),
            next_id: 1,
            session_manifest: outcome.map(|outcome| {
                runner_session_manifest(&outcome, STDIO_RUNNER_BACKEND, program, args)
            }),
            scratch,
            stop: start.stop.map(Arc::clone),
        };
        let stdin = stdin.ok_or("the connector's input is not writable")?;
        let stdout = stdout.ok_or("the connector's output is not readable")?;
        // The writer ends once no line can come or one does not go; it is
        // not joined.
        let writer = thread::Builder::new()
            .name("connector-stdio-in".to_owned())
            .spawn(move || write_lines(stdin, &queued, &wrote))
            .map_err(|_| "the connector's input writer did not start")?;
        drop(writer);
        let name = start.name.to_owned();
        // Each reader ends when the child's stream does; neither is joined.
        let reader = thread::Builder::new()
            .name("connector-stdio-out".to_owned())
            .spawn(move || read_frames(stdout, &sender, &name))
            .map_err(|_| "the connector's output reader did not start")?;
        drop(reader);
        if let Some(mut stderr) = stderr {
            let drain = thread::Builder::new()
                .name("connector-stdio-err".to_owned())
                .spawn(move || drop(io::copy(&mut stderr, &mut io::sink())))
                .map_err(|_| "the connector's error reader did not start")?;
            drop(drain);
        }
        child.initialize(start.requested_revision, start.accepts_revision)?;
        Ok(child)
    }

    /// `initialize` with no client capability, then
    /// `notifications/initialized`.
    fn initialize(
        &mut self,
        requested: &str,
        accepts: &dyn Fn(&str) -> bool,
    ) -> Result<(), &'static str> {
        let params = json!({
            "protocolVersion": requested,
            "capabilities": {},
            "clientInfo": { "name": "oneiron", "version": env!("CARGO_PKG_VERSION") },
        });
        let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
        let result = self.request_until("initialize", params, deadline)?;
        let revision = result
            .get("protocolVersion")
            .and_then(Value::as_str)
            .ok_or("the connector's initialize answer names no revision")?;
        if !accepts(revision) {
            return Err("the connector answered a protocol revision this host does not take");
        }
        self.revision = revision.to_owned();
        zeroize_json(result);
        self.write(
            &json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
            deadline,
        )
        .map_err(|_| "the connector did not take its initialized notification")
    }

    /// The revision the child's `initialize` agreed.
    #[must_use]
    pub fn revision(&self) -> &str {
        &self.revision
    }

    /// The session manifest of this child; `None` when it runs with no
    /// fence (the vault's trees could not be named).
    #[must_use]
    pub fn session_manifest(&self) -> Option<&SessionManifest> {
        self.session_manifest.as_ref()
    }

    /// One request and its result within `timeout`; an error answer fails
    /// it.
    ///
    /// # Errors
    /// The child did not take the request or did not answer it within
    /// `timeout` (or the server began to stop), or it answered with an
    /// error.
    pub fn request(
        &mut self,
        method: &str,
        params: Value,
        timeout: Duration,
    ) -> Result<Value, &'static str> {
        self.request_until(method, params, Instant::now() + timeout)
    }

    /// [`Self::request`], written and answered before `deadline`.
    fn request_until(
        &mut self,
        method: &str,
        params: Value,
        deadline: Instant,
    ) -> Result<Value, &'static str> {
        let id = self
            .send(method, params, deadline)
            .map_err(|_| "the connector did not take the request")?;
        let (mut message, mut bytes) = self
            .answer(id, deadline)
            .map_err(|_| "the connector did not answer")?;
        bytes.zeroize();
        let result = message
            .get_mut("result")
            .map(Value::take)
            .ok_or("the connector answered with an error");
        zeroize_json(message);
        result
    }

    /// `tools/call` of `tool` with `arguments`, written and answered
    /// within [`CALL_TIMEOUT`].
    fn call_tool(&mut self, tool: &str, arguments: Value) -> StdioDelivery {
        let deadline = Instant::now() + CALL_TIMEOUT;
        let request = json!({ "name": tool, "arguments": arguments });
        let id = match self.send("tools/call", request, deadline) {
            Ok(id) => id,
            Err(Unwritten::NotSent) => return StdioDelivery::NotSent,
            // The whole request may still reach the child.
            Err(Unwritten::Pending) => return StdioDelivery::NoAnswer,
        };
        match self.answer(id, deadline) {
            Ok((message, body)) => StdioDelivery::Answered { message, body },
            Err(NoAnswer::Ended | NoAnswer::TimedOut | NoAnswer::Unreadable) => {
                StdioDelivery::NoAnswer
            }
        }
    }

    /// Writes one request before `deadline` and returns its id.
    fn send(&mut self, method: &str, params: Value, deadline: Instant) -> Result<u64, Unwritten> {
        let id = self.next_id;
        self.next_id += 1;
        let request = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
        self.write(&request, deadline)?;
        Ok(id)
    }

    /// One message, as one line on the child's input, written before
    /// `deadline`. A line that was not written all closes the input: no
    /// line is written after it.
    fn write(&mut self, message: &Value, deadline: Instant) -> Result<(), Unwritten> {
        if self.wait_slice(deadline).is_none() {
            return Err(Unwritten::NotSent);
        }
        let lines = self.lines.as_ref().ok_or(Unwritten::NotSent)?;
        let mut line = Zeroizing::new(serde_json::to_vec(message).map_err(|_| Unwritten::NotSent)?);
        line.push(b'\n');
        // The writer is idle: each line before this one was written, or
        // the input counts as closed.
        if lines.try_send(line).is_err() {
            self.lines = None;
            return Err(Unwritten::NotSent);
        }
        loop {
            let Some(wait) = self.wait_slice(deadline) else {
                self.lines = None;
                return Err(Unwritten::Pending);
            };
            match self.written.recv_timeout(wait) {
                Ok(true) => return Ok(()),
                // A line the pipe refused part of is no message.
                Ok(false) | Err(RecvTimeoutError::Disconnected) => {
                    self.lines = None;
                    return Err(Unwritten::NotSent);
                }
                Err(RecvTimeoutError::Timeout) => {}
            }
        }
    }

    /// How long the next wait on the child may last: what is left before
    /// `deadline`, at most [`STOP_CHECK`]; `None` once the deadline has
    /// passed or the server is stopping.
    fn wait_slice(&self, deadline: Instant) -> Option<Duration> {
        if self
            .stop
            .as_deref()
            .is_some_and(|stop| stop.load(Ordering::Acquire))
        {
            return None;
        }
        let left = deadline.saturating_duration_since(Instant::now());
        (!left.is_zero()).then_some(left.min(STOP_CHECK))
    }

    /// The message answering `id`, read before `deadline`. A request the
    /// child makes meanwhile is answered, and anything else it says is
    /// dropped.
    fn answer(&mut self, id: u64, deadline: Instant) -> Result<(Value, Vec<u8>), NoAnswer> {
        loop {
            let wait = self.wait_slice(deadline).ok_or(NoAnswer::TimedOut)?;
            match self.frames.recv_timeout(wait) {
                Ok(Frame::Message(message, bytes)) if super::reply_read::answers(&message, id) => {
                    return Ok((message, bytes));
                }
                Ok(Frame::Message(message, mut bytes)) => {
                    bytes.zeroize();
                    self.serve(message, deadline);
                }
                Ok(Frame::Overlong) => return Err(NoAnswer::Unreadable),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return Err(NoAnswer::Ended),
            }
        }
    }

    /// Answers a request the child made, before `deadline`: a `ping` with
    /// an empty result, anything else with a refusal, since this client
    /// serves no elicitation, sampling or roots. A notification or a stale
    /// answer is dropped.
    fn serve(&mut self, message: Value, deadline: Instant) {
        let request = message.get("method").and_then(Value::as_str);
        if let (Some(method), Some(id)) = (request, message.get("id")) {
            let reply = if method == "ping" {
                json!({ "jsonrpc": "2.0", "id": id, "result": {} })
            } else {
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": { "code": -32601, "message": "this client serves no server requests" },
                })
            };
            // A child that does not take the answer fails its call's read:
            // its input counts as closed, or the bound has passed.
            let _ = self.write(&reply, deadline);
        }
        zeroize_json(message);
    }

    /// Whether the process is still running.
    fn running(&mut self) -> bool {
        matches!(self.process.try_wait(), Ok(None))
    }
}

impl Drop for StdioChild {
    fn drop(&mut self) {
        // Closing its input asks an MCP stdio server to exit: the writer
        // closes it once it has no line left to write. A writer still
        // blocked on a line ends when the child is killed.
        drop(self.lines.take());
        let deadline = Instant::now() + STOP_GRACE;
        while Instant::now() < deadline {
            if !self.running() {
                break;
            }
            thread::sleep(STOP_POLL);
        }
        if self.running() {
            drop(self.process.kill());
        }
        drop(self.process.wait());
        drop(self.scratch.take());
    }
}

/// Writes each line handed to it on a child's standard input and says
/// whether it went, until no more lines can come or one does not go; the
/// input is closed then.
fn write_lines(
    mut stdin: ChildStdin,
    lines: &Receiver<Zeroizing<Vec<u8>>>,
    written: &SyncSender<bool>,
) {
    for line in lines {
        let went = stdin.write_all(&line).and_then(|()| stdin.flush()).is_ok();
        if written.send(went).is_err() || !went {
            return;
        }
    }
}

/// Reads a child's standard output line by line until it ends or nobody
/// reads on, handing each JSON line on and dropping every other one.
fn read_frames(stdout: ChildStdout, frames: &SyncSender<Frame>, name: &str) {
    let mut reader = ZeroizingBufReader::new(stdout);
    let mut line = Zeroizing::new(Vec::new());
    loop {
        let frame = match read_line(&mut reader, &mut line) {
            Ok(LineRead::Line) => match serde_json::from_slice::<Value>(&line) {
                Ok(message) => Frame::Message(message, std::mem::take(&mut *line)),
                Err(_) => {
                    tracing::debug!(
                        connector = name,
                        "a stdio connector wrote a line that is not JSON; dropped"
                    );
                    line.zeroize();
                    continue;
                }
            },
            Ok(LineRead::Overlong) => Frame::Overlong,
            Ok(LineRead::End) | Err(_) => return,
        };
        if frames.send(frame).is_err() {
            return;
        }
    }
}

/// What one line read came to.
enum LineRead {
    /// `line` holds it, without its newline.
    Line,
    /// It was longer than [`MAX_LINE_BYTES`]; read past and dropped.
    Overlong,
    /// The output ended; a last line with no newline is dropped.
    End,
}

/// Reads one line into `line`, at most [`MAX_LINE_BYTES`] of it.
fn read_line(reader: &mut impl BufRead, line: &mut Zeroizing<Vec<u8>>) -> io::Result<LineRead> {
    line.zeroize();
    let mut overlong = false;
    loop {
        let buffer = match reader.fill_buf() {
            Ok(buffer) => buffer,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        if buffer.is_empty() {
            line.zeroize();
            return Ok(LineRead::End);
        }
        let newline = buffer.iter().position(|&byte| byte == b'\n');
        let taken = newline.unwrap_or(buffer.len());
        if !overlong {
            if line.len() + taken > MAX_LINE_BYTES {
                overlong = true;
                line.zeroize();
            } else {
                line.extend_from_slice(&buffer[..taken]);
            }
        }
        reader.consume(newline.map_or(taken, |at| at + 1));
        if newline.is_some() {
            return Ok(if overlong {
                LineRead::Overlong
            } else {
                LineRead::Line
            });
        }
    }
}

/// What one `tools/call` on a stdio connector came to.
pub enum StdioDelivery {
    /// The request never reached a child: none could be started, or its
    /// input was closed (or the server was stopping) before the request was
    /// handed to it.
    NotSent,
    /// The child answered: the message and its own bytes.
    Answered { message: Value, body: Vec<u8> },
    /// The request went, or may still have gone, and no readable answer
    /// came back within the call's bound or before the server stopped; the
    /// child is stopped.
    NoAnswer,
}

/// One `tools/call` on a stdio connector.
pub struct StdioToolCall<'a> {
    /// The connector's catalog name.
    pub name: &'a str,
    pub connector: &'a ConnectorHostConfig,
    /// The fence its child runs under; see [`StdioStart::fence`].
    pub fence: Option<&'a HostRunnerFence>,
    /// The revision the connector's key pinned.
    pub revision: &'a str,
    pub tool: &'a str,
    pub arguments: Value,
}

/// What a call came to, and the session manifest of the child it went to.
pub struct StdioToolOutcome {
    pub delivery: StdioDelivery,
    /// `None` when no child took it, or the child runs with no fence.
    pub session_manifest: Option<SessionManifest>,
}

/// The stdio connector children of one server, by normalized catalog name.
#[derive(Default)]
pub struct ConnectorStdioRegistry {
    slots: Mutex<BTreeMap<String, Arc<Mutex<StdioSlot>>>>,
    /// Set once the server stops: no child starts, and every wait on one
    /// ends.
    stopping: Arc<AtomicBool>,
}

/// One connector's child and its recent starts.
#[derive(Default)]
struct StdioSlot {
    child: Option<StdioChild>,
    starts: VecDeque<Instant>,
}

impl ConnectorStdioRegistry {
    /// Sends one `tools/call` to the connector's child, starting it first
    /// when none runs for its current settings. A call waits for the one
    /// in flight on the same child.
    pub fn call_tool(&self, call: StdioToolCall<'_>) -> StdioToolOutcome {
        let not_sent = || StdioToolOutcome {
            delivery: StdioDelivery::NotSent,
            session_manifest: None,
        };
        if self.stopping.load(Ordering::Acquire) {
            return not_sent();
        }
        let name = normalize_name(call.name);
        let slot = Arc::clone(lock(&self.slots).entry(name.clone()).or_default());
        let mut slot = lock(&slot);
        // `stop` takes each child under its slot's lock.
        if self.stopping.load(Ordering::Acquire) {
            return not_sent();
        }
        let Some(child) = slot.live(&name, &call, &self.stopping) else {
            return not_sent();
        };
        let session_manifest = child.session_manifest.clone();
        let delivery = child.call_tool(call.tool, call.arguments);
        if !matches!(delivery, StdioDelivery::Answered { .. }) {
            // A child that took no request or gave no answer is stopped.
            slot.child = None;
        }
        StdioToolOutcome {
            delivery,
            session_manifest,
        }
    }

    /// Stops every child, and starts none from here on. A call in flight
    /// stops waiting on its child within [`STOP_CHECK`]; a request it had
    /// begun to write has no known delivery. Each child's input is closed,
    /// then it is killed after [`STOP_GRACE`].
    pub fn stop(&self) {
        self.stopping.store(true, Ordering::Release);
        let slots: Vec<_> = lock(&self.slots).values().cloned().collect();
        for slot in slots {
            let child = lock(&slot).child.take();
            drop(child);
        }
    }
}

impl StdioSlot {
    /// The child for `call`'s connector settings and revision, started
    /// when none runs for them; `None` when it cannot start, or keeps
    /// exiting.
    fn live(
        &mut self,
        name: &str,
        call: &StdioToolCall<'_>,
        stop: &Arc<AtomicBool>,
    ) -> Option<&mut StdioChild> {
        let identity = call.connector.installed_endpoint(name);
        let current = self.child.as_mut().is_some_and(|child| {
            child.identity == identity && child.revision == call.revision && child.running()
        });
        if !current {
            // Dropping the old child stops it.
            self.child = None;
            let now = Instant::now();
            self.starts
                .retain(|started| now.duration_since(*started) < RESTART_WINDOW);
            if self.starts.len() >= STARTS_PER_WINDOW {
                tracing::warn!(
                    connector = name,
                    "a stdio connector keeps exiting; it is not started again until a minute has passed"
                );
                return None;
            }
            self.starts.push_back(now);
            let accepts = |answered: &str| answered == call.revision;
            let start = StdioStart {
                name,
                connector: call.connector,
                fence: call.fence,
                requested_revision: call.revision,
                accepts_revision: &accepts,
                stop: Some(stop),
            };
            match StdioChild::start(&start) {
                Ok(child) => self.child = Some(child),
                Err(reason) => {
                    tracing::warn!(connector = name, reason, "a stdio connector did not start");
                    return None;
                }
            }
        }
        self.child.as_mut()
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl ServedConnectorCallHost {
    /// One send to an `mcp_stdio` connector: its call's issuer binding is
    /// read, then the `tools/call` goes to the connector's child. A send
    /// whose route would present a credential is not sent: a stdio child
    /// has no channel for one until the broker path (B2), and its
    /// environment never carries one. A call whose tool moved a parameter
    /// into a header (`x-mcp-header`) is not sent either: stdio has no
    /// headers, and the tool would not get that parameter.
    pub(super) fn send_stdio(
        &self,
        connector: &ConnectorHostConfig,
        view: &FrozenToolCallView,
    ) -> Sent {
        if !view.headers().is_empty() {
            tracing::warn!(
                connector = view.server(),
                "a stdio connector's call carries header parameters, which stdio cannot send; it \
                 is not sent"
            );
            return Sent::not_sent(OutboundFailureKind::InvalidRequest, None);
        }
        let presents = match self.vault.route_connector_call(view.server()) {
            Ok(Some(route)) => {
                self.grant.is_some() || self.credential.is_some() || route.secret_ref.is_some()
            }
            _ => return Sent::not_sent(OutboundFailureKind::Rejected, None),
        };
        if presents {
            tracing::warn!(
                connector = view.server(),
                "a stdio connector's send would present a credential; it is not sent until the \
                 broker path"
            );
            return Sent::not_sent(OutboundFailureKind::Rejected, None);
        }
        // The door's issuer read, as a credential-free HTTP send has it
        // (FIX 9303).
        if let Some(key_ref) = view.key_ref().and_then(|hex| EntityId::from_hex(hex).ok()) {
            match self.vault.connector_issuer_hold(&key_ref, view.tool()) {
                Ok(None) => {}
                Ok(Some(reason)) => return Sent::held(reason),
                Err(error) => {
                    tracing::warn!(%error, "connector issuer binding not read");
                    return Sent::not_sent(OutboundFailureKind::TransportNotStarted, None);
                }
            }
        }
        let Some(revision) = view.protocol_revision() else {
            return Sent::not_sent(OutboundFailureKind::InvalidRequest, None);
        };
        let outcome = self.stdio.call_tool(StdioToolCall {
            name: view.server(),
            connector,
            fence: self.fence.as_deref(),
            revision,
            tool: view.tool(),
            arguments: Value::Object(
                view.arguments()
                    .iter()
                    .map(|(name, value)| (name.clone(), value.clone()))
                    .collect(),
            ),
        });
        let sent = match outcome.delivery {
            StdioDelivery::NotSent => {
                Sent::not_sent(OutboundFailureKind::TransportNotStarted, None)
            }
            StdioDelivery::NoAnswer => Sent::ambiguous("connector_no_reply"),
            StdioDelivery::Answered { message, body } => answered(message, body.into()),
        };
        Sent {
            session_manifest: outcome.session_manifest,
            ..sent
        }
    }
}

/// The child's answer to `tools/call`: a remote task it took the call as
/// (FIX 7960; no session to poll it in), else the tool's reply.
fn answered(mut message: Value, body: RawOutboundBody) -> Sent {
    if let Some(handle) = super::remote_task::remote_task_from_result(&message) {
        zeroize_json(message);
        return Sent::deferred(handle, body);
    }
    let reply = tool_result(&mut message);
    zeroize_json(message);
    match reply {
        Some(reply) => Sent::acked(Some(reply), body),
        None => Sent::ambiguous("connector_reply_unreadable"),
    }
}
