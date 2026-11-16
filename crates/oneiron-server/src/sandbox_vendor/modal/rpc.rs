//! Modal's gRPC services as one run uses them: a connection to the control
//! API or to the command router of the run's task, and each call the run
//! makes on one (the image build, the sandbox's task and router, a
//! command's stdin, its exit code and its output, and a file tool's failure
//! in its own words).

use std::time::{Duration, Instant};

use hyper::HeaderMap;
use hyper::header::{AUTHORIZATION, HeaderValue};
use zeroize::Zeroizing;

use super::{
    CLIENT_TYPE, CLIENT_VERSION, CONTROL, HTTP, LIBRARY_VERSION, POLL_PAUSE, ROUTER,
    STATUS_SUCCESS, STDERR, SandboxTask, TOOL_ERROR_BYTES, call_timeout, generic_end,
    generic_status, grpc_failed, malformed, poll_wait, required, secret_header,
};
use crate::sandbox_vendor::grpc::{
    DEADLINE_EXCEEDED, GrpcChannel, GrpcEndpoint, GrpcError, GrpcReply,
};
use crate::sandbox_vendor::protobuf::{ProtoMessage, ProtoWriter};
use crate::sandbox_vendor::vendor_http::quoted;

/// One connection to one of Modal's services, with the metadata of every
/// call on it and the secrets in that metadata.
pub(super) struct ServiceConnection {
    channel: GrpcChannel,
    service: &'static str,
    metadata: HeaderMap,
    secrets: Vec<Zeroizing<String>>,
}

impl ServiceConnection {
    fn failed(&self, error: GrpcError) -> oneiron::Error {
        grpc_failed(error, &self.secret_texts())
    }

    /// The start of a text Modal answered (a `GenericResult`'s exception),
    /// as an error quotes it: without any secret of this connection.
    fn quoted(&self, text: &str) -> String {
        quoted(text, &self.secret_texts())
    }

    fn secret_texts(&self) -> Vec<&str> {
        self.secrets.iter().map(|secret| secret.as_str()).collect()
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
    pub(super) async fn call(
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
    pub(super) async fn stream(
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
    pub(super) async fn next(&self, reply: &mut GrpcReply) -> oneiron::Result<Option<Vec<u8>>> {
        match reply.next_message().await {
            Ok(message) => Ok(message),
            Err(error) => Err(self.failed(error)),
        }
    }
}

/// A connection to the control API at `api` on the owner's `key`, with the
/// auth token the API answers for the key.
pub(super) async fn open_control(
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
pub(super) async fn open_router(task: &SandboxTask) -> oneiron::Result<ServiceConnection> {
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
pub(super) async fn build_image(
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
            control.quoted(&exception)
        ))),
        None => Err(HTTP.failed("modal ended the guest image's build with no result")),
    }
}

/// The task of `sandbox` once Modal ran it, and the router that serves it.
pub(super) async fn attach(
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
                control.quoted(&exception)
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
pub(super) async fn write_stdin(
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
pub(super) async fn wait(
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
pub(super) fn stdio_read(task: &SandboxTask, exec: &str, file_descriptor: u64) -> ProtoWriter {
    ProtoWriter::new()
        .string(1, &task.id)
        .string(2, exec)
        .uint(3, 0)
        .uint(4, file_descriptor)
}

/// The failure of a file tool's command `exec` that exited `code` while
/// it did `action`, in the tool's own words from its stderr.
pub(super) async fn tool_failed(
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
