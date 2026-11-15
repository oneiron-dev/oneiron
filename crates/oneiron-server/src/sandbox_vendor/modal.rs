//! Modal's sandbox API as a [`VendorSandboxClient`] (L8-43): one sandbox
//! per batch run, made from Modal's build of the step's pinned guest image,
//! driven through the command router Modal names for the sandbox's task,
//! and terminated at the run's end.
//!
//! Modal serves its API over gRPC alone ([`super::grpc`]); the messages of
//! its published `modal_proto` that a run needs are written and read by
//! field number ([`super::protobuf`]). Two secrets reach Modal, each only at
//! its own service. The owner's key, a token id and a token secret joined by
//! a colon, read at the custody door bound to `sandbox:modal` at the run's
//! first call, goes as `x-modal-token-id` and `x-modal-token-secret` to the
//! control API this client was built with, beside the short-lived auth token
//! that API answers for it. The router token Modal answers for the one task
//! this run made goes as a bearer token to the router that answer names,
//! which must be reached as the control API is (over TLS, in service). Each
//! is held in memory that is wiped when the client drops, and each is
//! scrubbed from every error text.
//!
//! The sandbox has all network access blocked, so a vendor run has no
//! egress (module doc of `VendorBatchBackend`), and it opens no port. Modal
//! builds the guest image from its registry by digest (`FROM
//! <image>@sha256:...`) once and keeps the build for later runs. A sandbox's
//! memory is capped at the step's budget, and its processes are kept by the
//! guest itself, as on our own backends. Modal terminates a sandbox at its
//! timeout, the step's own time left plus [`LIFETIME_MARGIN`], so a lost run
//! leaves nothing running.
//!
//! A command runs with no shell and its output dropped. A file goes in and
//! out through the file tool Modal puts in every sandbox ([`FS_TOOLS`]): its
//! bytes go on the tool's stdin, or come off its stdout.

use std::io::{Read, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, Weak};
use std::time::{Duration, Instant};

use hyper::HeaderMap;
use hyper::header::{AUTHORIZATION, HeaderValue};
use oneiron::Vault;
use oneiron::code_sandbox::microvm::ExecutionBudget;
use oneiron::code_sandbox::{SandboxProposalBody, SandboxVendor};
use oneiron::engine_executor::StepCancellation;
use oneiron_agent_runtime::code_sandbox::microvm::{
    VendorCallBound, VendorSandboxClient, VendorSandboxId, VendorSandboxSpec,
};
use serde_json::json;
use zeroize::Zeroizing;

use super::grpc::{DEADLINE_EXCEEDED, GrpcChannel, GrpcEndpoint, GrpcError, GrpcReply};
use super::protobuf::{MalformedProto, ProtoMessage, ProtoWriter};
use super::vendor_http::{DELETE_TIMEOUT, OwnerVendorKey, VendorHttp, quoted, scrubbed};

/// The one vendor this client reaches.
const VENDOR: SandboxVendor = SandboxVendor::Modal;
const HTTP: VendorHttp = VendorHttp(VENDOR);
/// The gRPC services: the control API, and a task's command router.
const CONTROL: &str = "/modal.client.ModalClient/";
const ROUTER: &str = "/modal.task_command_router.TaskCommandRouter/";
/// The app every sandbox of a batch run belongs to.
const APP_NAME: &str = "oneiron-batch";
/// The file tool Modal puts in every sandbox.
const FS_TOOLS: &str = "/__modal/.bin/modal-sandbox-fs-tools";
/// Who this client says it is: the behaviour of Modal's own Go client
/// (`CLIENT_TYPE_LIBMODAL_GO`, at the version that client sends), and its
/// own name.
const CLIENT_TYPE: &str = "9";
const CLIENT_VERSION: &str = "1.0.0";
const LIBRARY_VERSION: &str = concat!("oneiron-server/", env!("CARGO_PKG_VERSION"));
/// What a sandbox lives past the step's own time left, so Modal terminates
/// one a lost run left soon after the run would have ended.
const LIFETIME_MARGIN: Duration = Duration::from_secs(60);
/// The longest lifetime Modal gives a sandbox.
const LONGEST_LIFETIME_SECS: u64 = 24 * 60 * 60;
/// The smallest memory a sandbox asks for; the step's budget is its cap.
const SMALLEST_MEMORY_MIB: u32 = 128;
/// The longest one call waits: Modal's own wait in a poll is shorter by
/// [`POLL_MARGIN`].
const LONGEST_CALL: Duration = Duration::from_secs(60);
const POLL_MARGIN: Duration = Duration::from_secs(10);
/// The pause before a poll Modal answered at once with nothing new.
const POLL_PAUSE: Duration = Duration::from_millis(500);
/// How often a call looks at the step's cancellation.
const CANCEL_POLL: Duration = Duration::from_millis(50);
/// The largest piece of a file one write to the file tool's stdin carries.
const STDIN_CHUNK: usize = 256 * 1024;
/// The most of a file tool's stderr an error quotes.
const TOOL_ERROR_BYTES: usize = 4096;

/// `ObjectCreationType.OBJECT_CREATION_TYPE_CREATE_IF_MISSING`.
const CREATE_IF_MISSING: u64 = 1;
/// `GenericResult.GenericStatus.GENERIC_STATUS_SUCCESS`.
const STATUS_SUCCESS: u64 = 1;
/// `NetworkAccess.NetworkAccessType.BLOCKED`.
const NETWORK_BLOCKED: u64 = 2;
/// `TaskExecStdoutConfig` and `TaskExecStderrConfig`: dropped, or piped
/// to the client.
const OUTPUT_DROPPED: u64 = 0;
const OUTPUT_PIPED: u64 = 1;
/// `TaskExecStdioFileDescriptor`.
const STDOUT: u64 = 0;
const STDERR: u64 = 1;

/// Where Modal's API answers.
#[derive(Debug, Clone)]
pub(crate) struct ModalEndpoints {
    /// The control API, `modal.client.ModalClient`.
    pub(crate) api: String,
}

impl Default for ModalEndpoints {
    fn default() -> Self {
        Self {
            api: "https://api.modal.com".into(),
        }
    }
}

/// The task of the sandbox this run made, and the router that serves it.
#[derive(Clone)]
struct SandboxTask {
    id: String,
    router: GrpcEndpoint,
    token: Zeroizing<String>,
}

/// The sandbox this run made, with its task once Modal ran it.
struct MadeSandbox {
    id: String,
    task: Option<SandboxTask>,
}

/// One run's client of Modal, on the owner's key the switch names.
pub(super) struct ModalClient {
    key: OwnerVendorKey,
    endpoints: ModalEndpoints,
    made: Mutex<Option<MadeSandbox>>,
    /// The number of the run's next command: its exec id, unique in the
    /// one sandbox the run made.
    execs: AtomicU64,
}

fn malformed(_: MalformedProto) -> oneiron::Error {
    HTTP.failed("modal answered a malformed message")
}

fn poisoned() -> oneiron::Error {
    HTTP.failed("the modal sandbox state is poisoned")
}

/// `value`, which Modal must answer: an empty one is missing too.
fn required<'a>(value: Option<&'a str>, what: &str) -> oneiron::Result<&'a str> {
    value
        .filter(|value| !value.is_empty())
        .ok_or_else(|| HTTP.failed(format!("modal answered no {what}")))
}

/// A metadata value holding a secret, kept out of HTTP/2's header tables.
fn secret_header(secret: &str) -> oneiron::Result<HeaderValue> {
    let mut value = HeaderValue::from_str(secret)
        .map_err(|_| HTTP.failed("a modal credential is not a header value"))?;
    value.set_sensitive(true);
    Ok(value)
}

fn grpc_failed(error: GrpcError, secrets: &[&str]) -> oneiron::Error {
    match error {
        GrpcError::Status { code, message } => HTTP.failed(format!(
            "modal answered {}: {}",
            GrpcError::code_name(code),
            quoted(&message, secrets)
        )),
        GrpcError::Transport(detail) => {
            HTTP.failed(format!("modal call failed: {}", scrubbed(&detail, secrets)))
        }
    }
}

/// The name Modal gives a `GenericResult` status.
fn generic_status(status: u64) -> &'static str {
    match status {
        1 => "success",
        2 => "failure",
        3 => "terminated",
        4 => "timeout",
        5 => "init failure",
        6 => "internal failure",
        7 => "idle timeout",
        8 | 9 => "evicted",
        10 => "out of memory",
        _ => "an unknown status",
    }
}

/// A `GenericResult`'s status, once it has one, and its exception text.
fn generic_end(result: Option<ProtoMessage<'_>>) -> oneiron::Result<Option<(u64, String)>> {
    let Some(result) = result else {
        return Ok(None);
    };
    let status = result.uint(1).map_err(malformed)?.unwrap_or_default();
    if status == 0 {
        return Ok(None);
    }
    let exception = result.string(2).map_err(malformed)?.unwrap_or_default();
    Ok(Some((status, exception.to_owned())))
}

/// The time one call may take: what is left of the step, at most
/// [`LONGEST_CALL`].
fn call_timeout(deadline: Instant) -> oneiron::Result<Duration> {
    Ok(HTTP.remaining(deadline)?.min(LONGEST_CALL))
}

/// Modal's own wait in one poll, and the call's timeout around it.
fn poll_wait(deadline: Instant) -> oneiron::Result<(f32, Duration)> {
    let call = call_timeout(deadline)?;
    let wait = call.saturating_sub(POLL_MARGIN).max(Duration::from_secs(1));
    Ok((wait.as_secs_f32(), call))
}

/// The guest image as Modal pulls it: a reference pinned by its digest, in
/// the characters a reference has, so it is one word of the build's `FROM`.
fn pinned_image(guest_image: &str) -> oneiron::Result<&str> {
    HTTP.guest_image_name(guest_image)?;
    let plain = guest_image
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || b"./:@_-".contains(&byte));
    if plain {
        Ok(guest_image)
    } else {
        Err(HTTP.failed("the guest image is not a plain image reference"))
    }
}

async fn cancelled(cancel: Option<&StepCancellation>) -> oneiron::Error {
    let Some(cancel) = cancel else {
        return std::future::pending().await;
    };
    loop {
        if let Err(error) = cancel.check() {
            return error;
        }
        tokio::time::sleep(CANCEL_POLL).await;
    }
}

/// Runs `call` on a runtime of its own, which its connections live on, and
/// ends it at `deadline` or soon after `cancel` fires.
fn run_bounded<T>(
    deadline: Instant,
    cancel: Option<&StepCancellation>,
    call: impl Future<Output = oneiron::Result<T>>,
) -> oneiron::Result<T> {
    if let Some(cancel) = cancel {
        cancel.check()?;
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| HTTP.failed("the modal client's runtime could not start"))?;
    runtime.block_on(async {
        tokio::select! {
            result = call => result,
            () = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) => {
                Err(HTTP.failed("the step's deadline passed"))
            }
            error = cancelled(cancel) => Err(error),
        }
    })
}

/// One connection to one of Modal's services, with the metadata of every
/// call on it and the secrets in that metadata.
struct ServiceConnection {
    channel: GrpcChannel,
    service: &'static str,
    metadata: HeaderMap,
    secrets: Vec<Zeroizing<String>>,
}

impl ServiceConnection {
    fn failed(&self, error: GrpcError) -> oneiron::Error {
        let mut secrets = Vec::with_capacity(self.secrets.len());
        for secret in &self.secrets {
            secrets.push(secret.as_str());
        }
        grpc_failed(error, &secrets)
    }

    async fn unary(
        &mut self,
        method: &str,
        message: ProtoWriter,
        timeout: Duration,
    ) -> Result<Vec<u8>, GrpcError> {
        let path = format!("{}{method}", self.service);
        self.channel
            .unary(&path, &self.metadata, &message.into_bytes(), timeout)
            .await
    }

    /// The one message the unary call of `method` answers.
    async fn call(
        &mut self,
        method: &str,
        message: ProtoWriter,
        timeout: Duration,
    ) -> oneiron::Result<Vec<u8>> {
        match self.unary(method, message, timeout).await {
            Ok(answer) => Ok(answer),
            Err(error) => Err(self.failed(error)),
        }
    }

    /// The reply of the server-streaming call of `method`.
    async fn stream(
        &mut self,
        method: &str,
        message: ProtoWriter,
        timeout: Duration,
    ) -> oneiron::Result<GrpcReply> {
        let path = format!("{}{method}", self.service);
        match self
            .channel
            .call(&path, &self.metadata, &message.into_bytes(), timeout)
            .await
        {
            Ok(reply) => Ok(reply),
            Err(error) => Err(self.failed(error)),
        }
    }

    /// The next message of `reply`, or `None` at its end.
    async fn next(&self, reply: &mut GrpcReply) -> oneiron::Result<Option<Vec<u8>>> {
        match reply.next_message().await {
            Ok(message) => Ok(message),
            Err(error) => Err(self.failed(error)),
        }
    }
}

/// A connection to the control API at `api` on the owner's `key`, with the
/// auth token the API answers for the key.
async fn open_control(
    api: &GrpcEndpoint,
    key: &str,
    deadline: Instant,
) -> oneiron::Result<ServiceConnection> {
    let (id, secret) = key
        .split_once(':')
        .filter(|(id, secret)| !id.is_empty() && !secret.is_empty())
        .ok_or_else(|| {
            HTTP.failed(
                "the owner's modal key is not a token id and a token secret joined by a colon",
            )
        })?;
    let mut metadata = HeaderMap::new();
    metadata.insert("x-modal-client-type", HeaderValue::from_static(CLIENT_TYPE));
    metadata.insert(
        "x-modal-client-version",
        HeaderValue::from_static(CLIENT_VERSION),
    );
    metadata.insert(
        "x-modal-libmodal-version",
        HeaderValue::from_static(LIBRARY_VERSION),
    );
    // Modal's servers do not see the `:authority`, so its clients name the
    // host they called.
    metadata.insert(
        "x-modal-host",
        HeaderValue::from_str(api.host())
            .map_err(|_| HTTP.failed("the modal control API host is not a header value"))?,
    );
    metadata.insert("x-modal-token-id", secret_header(id)?);
    metadata.insert("x-modal-token-secret", secret_header(secret)?);
    let channel = GrpcChannel::connect(api)
        .await
        .map_err(|error| grpc_failed(error, &[id, secret]))?;
    let mut control = ServiceConnection {
        channel,
        service: CONTROL,
        metadata,
        secrets: vec![
            Zeroizing::new(id.to_owned()),
            Zeroizing::new(secret.to_owned()),
        ],
    };
    let answer = Zeroizing::new(
        control
            .call("AuthTokenGet", ProtoWriter::new(), call_timeout(deadline)?)
            .await?,
    );
    let token = ProtoMessage(&answer)
        .string(1)
        .map_err(malformed)?
        .filter(|token| !token.is_empty());
    if let Some(token) = token {
        control
            .metadata
            .insert("x-modal-auth-token", secret_header(token)?);
        control.secrets.push(Zeroizing::new(token.to_owned()));
    }
    Ok(control)
}

/// A connection to the router of `task`, on its token.
async fn open_router(task: &SandboxTask) -> oneiron::Result<ServiceConnection> {
    let bearer = Zeroizing::new(format!("Bearer {}", task.token.as_str()));
    let mut metadata = HeaderMap::new();
    metadata.insert(AUTHORIZATION, secret_header(&bearer)?);
    let channel = GrpcChannel::connect(&task.router)
        .await
        .map_err(|error| grpc_failed(error, &[task.token.as_str()]))?;
    Ok(ServiceConnection {
        channel,
        service: ROUTER,
        metadata,
        secrets: vec![task.token.clone()],
    })
}

/// The image Modal built `FROM` the pinned `image` for `app`, built now if
/// Modal has no build of it yet.
async fn build_image(
    control: &mut ServiceConnection,
    app: &str,
    builder_version: &str,
    image: &str,
    deadline: Instant,
) -> oneiron::Result<String> {
    let from = format!("FROM {image}");
    let built = control
        .call(
            "ImageGetOrCreate",
            ProtoWriter::new()
                .message(2, ProtoWriter::new().strings(6, &[from.as_str()]))
                .string(4, app)
                .string(9, builder_version),
            call_timeout(deadline)?,
        )
        .await?;
    let built = ProtoMessage(&built);
    let image_id = required(built.string(1).map_err(malformed)?, "image id")?.to_owned();
    let mut end = generic_end(built.message(2).map_err(malformed)?)?;
    let mut last_entry = String::new();
    while end.is_none() {
        let (wait, timeout) = poll_wait(deadline)?;
        let mut reply = control
            .stream(
                "ImageJoinStreaming",
                ProtoWriter::new()
                    .string(1, &image_id)
                    .float(2, wait)
                    .string(3, &last_entry),
                timeout,
            )
            .await?;
        while let Some(item) = control.next(&mut reply).await? {
            let item = ProtoMessage(&item);
            if let Some(entry) = item.string(3).map_err(malformed)?.filter(|e| !e.is_empty()) {
                entry.clone_into(&mut last_entry);
            }
            end = generic_end(item.message(1).map_err(malformed)?)?;
            if end.is_some() {
                break;
            }
        }
        if end.is_none() {
            tokio::time::sleep(POLL_PAUSE).await;
        }
    }
    match end {
        Some((STATUS_SUCCESS, _)) => Ok(image_id),
        Some((status, exception)) => Err(HTTP.failed(format!(
            "modal could not build the guest image: {}: {}",
            generic_status(status),
            quoted(&exception, &[])
        ))),
        None => Err(HTTP.failed("modal ended the guest image's build with no result")),
    }
}

/// The task of `sandbox` once Modal ran it, and the router that serves it.
async fn attach(
    control: &mut ServiceConnection,
    api: &GrpcEndpoint,
    sandbox: &str,
    deadline: Instant,
) -> oneiron::Result<SandboxTask> {
    let task = loop {
        let (wait, timeout) = poll_wait(deadline)?;
        let answer = control
            .call(
                "SandboxGetTaskId",
                ProtoWriter::new()
                    .string(1, sandbox)
                    .float(2, wait)
                    .bool(3, true),
                timeout,
            )
            .await?;
        let answer = ProtoMessage(&answer);
        if let Some(task) = answer
            .string(1)
            .map_err(malformed)?
            .filter(|t| !t.is_empty())
        {
            break task.to_owned();
        }
        if let Some((status, exception)) = generic_end(answer.message(2).map_err(malformed)?)? {
            return Err(HTTP.failed(format!(
                "modal ended the sandbox before it ran: {}: {}",
                generic_status(status),
                quoted(&exception, &[])
            )));
        }
        tokio::time::sleep(POLL_PAUSE).await;
    };
    let access = Zeroizing::new(
        control
            .call(
                "TaskGetCommandRouterAccess",
                ProtoWriter::new().string(1, &task),
                call_timeout(deadline)?,
            )
            .await?,
    );
    let access = ProtoMessage(&access);
    let token = required(access.string(1).map_err(malformed)?, "router token")?;
    let url = required(access.string(2).map_err(malformed)?, "router address")?;
    // The router token goes where Modal says, but never in the clear when
    // the owner's key went over TLS.
    let router = GrpcEndpoint::parse(url)
        .filter(|router| router.tls() == api.tls())
        .ok_or_else(|| HTTP.failed("modal named a router not reached as its control API is"))?;
    Ok(SandboxTask {
        id: task,
        router,
        token: Zeroizing::new(token.to_owned()),
    })
}

/// Writes `data` at `offset` of the stdin of the command `exec`, and closes
/// it after them when `eof`.
async fn write_stdin(
    router: &mut ServiceConnection,
    task: &SandboxTask,
    exec: &str,
    offset: u64,
    data: &[u8],
    eof: bool,
    deadline: Instant,
) -> oneiron::Result<()> {
    router
        .call(
            "TaskExecStdinWrite",
            ProtoWriter::new()
                .string(1, &task.id)
                .string(2, exec)
                .uint(3, offset)
                .bytes(4, data)
                .bool(5, eof),
            call_timeout(deadline)?,
        )
        .await
        .map(drop)
}

/// The exit code of the command `exec`, once it exits. A command ended by
/// a signal fails.
async fn wait(
    router: &mut ServiceConnection,
    task: &SandboxTask,
    exec: &str,
    deadline: Instant,
) -> oneiron::Result<i32> {
    loop {
        let answer = match router
            .unary(
                "TaskExecWait",
                ProtoWriter::new().string(1, &task.id).string(2, exec),
                call_timeout(deadline)?,
            )
            .await
        {
            Ok(answer) => answer,
            // This call's own time ended before the command did.
            Err(GrpcError::Status {
                code: DEADLINE_EXCEEDED,
                ..
            }) => continue,
            Err(error) => return Err(router.failed(error)),
        };
        let answer = ProtoMessage(&answer);
        if let Some(code) = answer.int32(1).map_err(malformed)? {
            return Ok(code);
        }
        if let Some(signal) = answer.int32(2).map_err(malformed)? {
            return Err(HTTP.failed(format!("the modal command ended by signal {signal}")));
        }
        return Err(HTTP.failed("modal answered a command's end with no exit status"));
    }
}

/// The request reading `file_descriptor` of the command `exec` from its
/// start.
fn stdio_read(task: &SandboxTask, exec: &str, file_descriptor: u64) -> ProtoWriter {
    ProtoWriter::new()
        .string(1, &task.id)
        .string(2, exec)
        .uint(3, 0)
        .uint(4, file_descriptor)
}

/// The failure of a file tool's command `exec` that exited `code` while
/// it did `action`, in the tool's own words from its stderr.
async fn tool_failed(
    router: &mut ServiceConnection,
    task: &SandboxTask,
    exec: &str,
    action: &str,
    code: i32,
    deadline: Instant,
) -> oneiron::Error {
    let mut text = Vec::new();
    let read: oneiron::Result<()> = async {
        let mut reply = router
            .stream(
                "TaskExecStdioRead",
                stdio_read(task, exec, STDERR),
                call_timeout(deadline)?,
            )
            .await?;
        while let Some(message) = router.next(&mut reply).await? {
            text.extend_from_slice(
                ProtoMessage(&message)
                    .bytes(1)
                    .map_err(malformed)?
                    .unwrap_or_default(),
            );
            if text.len() >= TOOL_ERROR_BYTES {
                break;
            }
        }
        Ok(())
    }
    .await;
    if let Err(error) = read {
        tracing::debug!(%error, "the modal file tool's stderr was not read");
    }
    let mut secrets = Vec::with_capacity(router.secrets.len());
    for secret in &router.secrets {
        secrets.push(secret.as_str());
    }
    HTTP.failed(format!(
        "modal's file tool could not {action}: exit {code}: {}",
        quoted(&String::from_utf8_lossy(&text), &secrets)
    ))
}

impl ModalClient {
    pub(super) fn new(vault: Weak<Vault>, key_name: String, endpoints: ModalEndpoints) -> Self {
        Self {
            key: OwnerVendorKey::new(vault, VENDOR, key_name),
            endpoints,
            made: Mutex::new(None),
            execs: AtomicU64::new(0),
        }
    }

    fn api(&self) -> oneiron::Result<GrpcEndpoint> {
        GrpcEndpoint::parse(&self.endpoints.api)
            .ok_or_else(|| HTTP.failed("the modal control API address is not a service URL"))
    }

    /// The task of `sandbox`, the one this run made.
    fn task(&self, sandbox: &VendorSandboxId) -> oneiron::Result<SandboxTask> {
        let made = self.made.lock().map_err(|_| poisoned())?;
        made.as_ref()
            .filter(|made| made.id == sandbox.as_str())
            .and_then(|made| made.task.clone())
            .ok_or_else(|| HTTP.failed("a modal call named a sandbox this run did not make"))
    }

    /// Makes the run's sandbox from `image` within `budget`, and waits
    /// until its task runs.
    async fn make(
        &self,
        key: &str,
        image: &str,
        budget: ExecutionBudget,
        deadline: Instant,
    ) -> oneiron::Result<VendorSandboxId> {
        let api = self.api()?;
        let mut control = open_control(&api, key, deadline).await?;
        let environment = control
            .call(
                "EnvironmentGetOrCreate",
                ProtoWriter::new(),
                call_timeout(deadline)?,
            )
            .await?;
        // EnvironmentGetOrCreateResponse.metadata.settings.image_builder_version
        let builder_version = ProtoMessage(&environment)
            .string_at(&[2, 2, 1])
            .map_err(malformed)?
            .unwrap_or_default()
            .to_owned();
        let app = control
            .call(
                "AppGetOrCreate",
                ProtoWriter::new()
                    .string(1, APP_NAME)
                    .uint(3, CREATE_IF_MISSING),
                call_timeout(deadline)?,
            )
            .await?;
        let app = required(ProtoMessage(&app).string(1).map_err(malformed)?, "app id")?.to_owned();
        let image = build_image(&mut control, &app, &builder_version, image, deadline).await?;
        let lifetime = (HTTP.remaining(deadline)? + LIFETIME_MARGIN)
            .as_secs()
            .min(LONGEST_LIFETIME_SECS);
        let memory = budget.mem_mib.max(1);
        let definition = ProtoWriter::new()
            .string(3, &image)
            .message(
                5,
                ProtoWriter::new()
                    .uint(2, u64::from(memory.min(SMALLEST_MEMORY_MIB)))
                    .uint(5, u64::from(memory)),
            )
            .uint(7, lifetime)
            .message(22, ProtoWriter::new().uint(1, NETWORK_BLOCKED));
        let made = control
            .call(
                "SandboxCreate",
                ProtoWriter::new().string(1, &app).message(2, definition),
                call_timeout(deadline)?,
            )
            .await?;
        let id = required(
            ProtoMessage(&made).string(1).map_err(malformed)?,
            "sandbox id",
        )?;
        let id = VendorSandboxId::new(HTTP.segment(id)?)?;
        // From here the sandbox is this run's to terminate, on any failure.
        *self.made.lock().map_err(|_| poisoned())? = Some(MadeSandbox {
            id: id.as_str().to_owned(),
            task: None,
        });
        let task = attach(&mut control, &api, id.as_str(), deadline).await?;
        let mut made = self.made.lock().map_err(|_| poisoned())?;
        if let Some(made) = made.as_mut() {
            made.task = Some(task);
        }
        drop(made);
        Ok(id)
    }

    fn terminate(&self, key: &str, sandbox: &str) -> oneiron::Result<()> {
        let api = self.api()?;
        let deadline = Instant::now() + DELETE_TIMEOUT;
        run_bounded(deadline, None, async {
            let mut control = open_control(&api, key, deadline).await?;
            control
                .call(
                    "SandboxTerminate",
                    ProtoWriter::new().string(1, sandbox),
                    call_timeout(deadline)?,
                )
                .await
                .map(drop)
        })
    }

    /// Starts `argv` on `task` with its stdout and stderr dropped or piped
    /// as `stdout` and `stderr` say, and answers its exec id. Modal kills the
    /// command at its own timeout, so a command a lost run left ends at the
    /// step's deadline.
    async fn start(
        &self,
        router: &mut ServiceConnection,
        task: &SandboxTask,
        argv: &[&str],
        stdout: u64,
        stderr: u64,
        deadline: Instant,
    ) -> oneiron::Result<String> {
        let exec = format!("oneiron-{}", self.execs.fetch_add(1, Ordering::Relaxed));
        let left = HTTP.remaining(deadline)?.as_secs().max(1);
        router
            .call(
                "TaskExecStart",
                ProtoWriter::new()
                    .string(1, &task.id)
                    .string(2, &exec)
                    .strings(3, argv)
                    .uint(4, stdout)
                    .uint(5, stderr)
                    .uint(6, left),
                call_timeout(deadline)?,
            )
            .await?;
        Ok(exec)
    }
}

impl VendorSandboxClient for ModalClient {
    fn vendor(&self) -> SandboxVendor {
        VENDOR
    }

    fn create(
        &self,
        spec: &VendorSandboxSpec<'_>,
        bound: VendorCallBound<'_>,
    ) -> oneiron::Result<VendorSandboxId> {
        let image = pinned_image(spec.guest_image)?;
        let key = self.key.read()?;
        let made = run_bounded(
            bound.deadline,
            Some(bound.cancel),
            self.make(&key, image, spec.budget, bound.deadline),
        );
        if made.is_err() {
            // No delete follows a failed create, so a sandbox Modal made
            // for it is terminated here.
            let left = self
                .made
                .lock()
                .ok()
                .and_then(|mut made| made.take())
                .map(|made| made.id);
            if let Some(sandbox) = left
                && let Err(cleanup) = self.terminate(&key, &sandbox)
            {
                tracing::warn!(error = %cleanup, %sandbox, "modal sandbox terminate failed");
            }
        }
        made
    }

    fn upload(
        &self,
        sandbox: &VendorSandboxId,
        path: &str,
        body: &SandboxProposalBody,
        bound: VendorCallBound<'_>,
    ) -> oneiron::Result<()> {
        let task = self.task(sandbox)?;
        let command = json!({ "WriteFile": { "path": path } }).to_string();
        run_bounded(bound.deadline, Some(bound.cancel), async {
            let mut router = open_router(&task).await?;
            let exec = self
                .start(
                    &mut router,
                    &task,
                    &[FS_TOOLS, &command],
                    OUTPUT_DROPPED,
                    OUTPUT_PIPED,
                    bound.deadline,
                )
                .await?;
            let mut reader = body.reader();
            let mut chunk = vec![0; STDIN_CHUNK];
            let mut offset = 0;
            loop {
                bound.cancel.check()?;
                let read = reader.read(&mut chunk)?;
                let eof = read == 0;
                write_stdin(
                    &mut router,
                    &task,
                    &exec,
                    offset,
                    &chunk[..read],
                    eof,
                    bound.deadline,
                )
                .await?;
                if eof {
                    break;
                }
                offset += read as u64;
            }
            match wait(&mut router, &task, &exec, bound.deadline).await? {
                0 => Ok(()),
                code => Err(tool_failed(
                    &mut router,
                    &task,
                    &exec,
                    "write the file",
                    code,
                    bound.deadline,
                )
                .await),
            }
        })
    }

    fn execute(
        &self,
        sandbox: &VendorSandboxId,
        argv: &[&str],
        bound: VendorCallBound<'_>,
    ) -> oneiron::Result<i32> {
        if argv.is_empty() {
            return Err(HTTP.failed("a modal command has no program"));
        }
        let task = self.task(sandbox)?;
        run_bounded(bound.deadline, Some(bound.cancel), async {
            let mut router = open_router(&task).await?;
            let exec = self
                .start(
                    &mut router,
                    &task,
                    argv,
                    OUTPUT_DROPPED,
                    OUTPUT_DROPPED,
                    bound.deadline,
                )
                .await?;
            // The command reads no input.
            write_stdin(&mut router, &task, &exec, 0, &[], true, bound.deadline).await?;
            wait(&mut router, &task, &exec, bound.deadline).await
        })
    }

    fn download(
        &self,
        sandbox: &VendorSandboxId,
        path: &str,
        sink: &mut dyn Write,
        bound: VendorCallBound<'_>,
    ) -> oneiron::Result<()> {
        let task = self.task(sandbox)?;
        let command = json!({ "ReadFile": { "path": path } }).to_string();
        run_bounded(bound.deadline, Some(bound.cancel), async {
            let mut router = open_router(&task).await?;
            let exec = self
                .start(
                    &mut router,
                    &task,
                    &[FS_TOOLS, &command],
                    OUTPUT_PIPED,
                    OUTPUT_PIPED,
                    bound.deadline,
                )
                .await?;
            let mut reply = router
                .stream(
                    "TaskExecStdioRead",
                    stdio_read(&task, &exec, STDOUT),
                    HTTP.remaining(bound.deadline)?,
                )
                .await?;
            while let Some(message) = router.next(&mut reply).await? {
                let data = ProtoMessage(&message).bytes(1).map_err(malformed)?;
                sink.write_all(data.unwrap_or_default())?;
            }
            match wait(&mut router, &task, &exec, bound.deadline).await? {
                0 => Ok(()),
                code => Err(tool_failed(
                    &mut router,
                    &task,
                    &exec,
                    "read the file",
                    code,
                    bound.deadline,
                )
                .await),
            }
        })
    }

    fn delete(&self, sandbox: &VendorSandboxId) -> oneiron::Result<()> {
        let key = self.key.read()?;
        self.terminate(&key, sandbox.as_str())
    }
}
