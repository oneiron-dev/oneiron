//! A vault switched to Modal runs its finite Foreign guests on Modal's
//! sandboxes, on the owner's key in custody (L8-43). Two loopback stand-ins
//! speak gRPC over HTTP/2 in the clear: one answers Modal's control API, the
//! other the command router the control API names for the sandbox's task.
//! Each records every call, answers each message in small HTTP/2 frames,
//! and the router serves the guest transcript the test gives it.
//!
//! The run builds the guest image from its digest, makes one sandbox with
//! all network access blocked, its memory capped at the step's budget and a
//! lifetime of the step's own time; it sends the owner's key only to the
//! control API and the router's token only to the router; it waits on a
//! command past one wait's own deadline; and it terminates the sandbox at
//! the end. A refused create, a router not reached as the control API is,
//! a failed command wait and a failed image build never show a secret and
//! leave no sandbox behind.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server --all-features
//! --features oneiron/test-support --test sandbox_vendor_modal`.
#![cfg(all(oneiron_test_support, target_os = "linux"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "sandbox_vendor/fixture.rs"]
mod fixture;

use std::collections::VecDeque;
use std::convert::Infallible;
use std::future::poll_fn;
use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll};

use fixture::{Console, GUEST_IMAGE, STEP_SECONDS, VendorVault, contains, guest_frames};
use hyper::body::{Body, Bytes, Frame, Incoming};
use hyper::server::conn::http2;
use hyper::service::service_fn;
use hyper::{HeaderMap, Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use oneiron::Result;
use oneiron::code_sandbox::microvm::{MicroVmExit, MicroVmSandboxAdapter, SandboxBackends};
use oneiron::code_sandbox::{
    SandboxProposalKind, SandboxProposalWrite, SandboxProvider, SandboxVendor,
};
use oneiron_server::test_doors::sandbox_vendor::served_modal_backends;
use serde_json::json;

const KEY_NAME: &str = "modal.token";
const TOKEN_ID: &str = "ak-test-4f1c";
const TOKEN_SECRET: &str = "as-secret-9b2c7d";
const AUTH_TOKEN: &str = "modal-auth-7f3e01";
const ROUTER_TOKEN: &str = "router-jwt-5a8d2e";
const FS_TOOLS: &str = "/__modal/.bin/modal-sandbox-fs-tools";
const GUEST_BIN: &str = "/usr/local/bin/oneiron-guest";
/// gRPC's status codes the stand-ins answer.
const DEADLINE_EXCEEDED: u32 = 4;
const UNAVAILABLE: u32 = 14;
const UNAUTHENTICATED: u32 = 16;
/// The largest HTTP/2 data frame a stand-in sends, so the client puts its
/// messages back together.
const FRAME_BYTES: usize = 7;

/// A protobuf field's value, as the stand-ins read and write it.
#[derive(Clone, Debug, PartialEq)]
enum Field {
    Varint(u64),
    Bytes(Vec<u8>),
    Fixed32([u8; 4]),
}

fn read_varint(bytes: &mut &[u8]) -> u64 {
    let mut value = 0;
    let mut shift = 0;
    loop {
        let byte = bytes[0];
        *bytes = &bytes[1..];
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return value;
        }
        shift += 7;
    }
}

fn write_varint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push((value & 0x7f) as u8 | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

/// The fields of `message`, in wire order.
fn decode(mut message: &[u8]) -> Vec<(u32, Field)> {
    let mut fields = Vec::new();
    while !message.is_empty() {
        let key = read_varint(&mut message);
        let value = match key & 7 {
            0 => Field::Varint(read_varint(&mut message)),
            2 => {
                let length = usize::try_from(read_varint(&mut message)).unwrap();
                let value = message[..length].to_vec();
                message = &message[length..];
                Field::Bytes(value)
            }
            5 => {
                let value = message[..4].try_into().unwrap();
                message = &message[4..];
                Field::Fixed32(value)
            }
            kind => panic!("a field of wire type {kind}"),
        };
        fields.push((u32::try_from(key >> 3).unwrap(), value));
    }
    fields
}

fn last(message: &[u8], number: u32) -> Option<Field> {
    decode(message)
        .into_iter()
        .rev()
        .find(|(field, _)| *field == number)
        .map(|(_, value)| value)
}

fn bytes(message: &[u8], number: u32) -> Option<Vec<u8>> {
    match last(message, number)? {
        Field::Bytes(value) => Some(value),
        other => panic!("field {number} is {other:?}"),
    }
}

fn text(message: &[u8], number: u32) -> Option<String> {
    bytes(message, number).map(|value| String::from_utf8(value).unwrap())
}

fn texts(message: &[u8], number: u32) -> Vec<String> {
    decode(message)
        .into_iter()
        .filter(|(field, _)| *field == number)
        .map(|(_, value)| match value {
            Field::Bytes(value) => String::from_utf8(value).unwrap(),
            other => panic!("field {number} is {other:?}"),
        })
        .collect()
}

fn uint(message: &[u8], number: u32) -> Option<u64> {
    match last(message, number)? {
        Field::Varint(value) => Some(value),
        other => panic!("field {number} is {other:?}"),
    }
}

fn float(message: &[u8], number: u32) -> Option<f32> {
    match last(message, number)? {
        Field::Fixed32(value) => Some(f32::from_le_bytes(value)),
        other => panic!("field {number} is {other:?}"),
    }
}

/// A message of `fields`.
fn encode(fields: &[(u32, Field)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (number, value) in fields {
        match value {
            Field::Varint(value) => {
                write_varint(&mut out, u64::from(*number) << 3);
                write_varint(&mut out, *value);
            }
            Field::Bytes(value) => {
                write_varint(&mut out, (u64::from(*number) << 3) | 2);
                write_varint(&mut out, value.len() as u64);
                out.extend_from_slice(value);
            }
            Field::Fixed32(value) => {
                write_varint(&mut out, (u64::from(*number) << 3) | 5);
                out.extend_from_slice(value);
            }
        }
    }
    out
}

fn string_field(number: u32, value: &str) -> (u32, Field) {
    (number, Field::Bytes(value.as_bytes().to_vec()))
}

fn message_field(number: u32, fields: &[(u32, Field)]) -> (u32, Field) {
    (number, Field::Bytes(encode(fields)))
}

/// Which stand-in a call reached.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Service {
    Control,
    Router,
}

impl Service {
    fn path(self) -> &'static str {
        match self {
            Self::Control => "/modal.client.ModalClient/",
            Self::Router => "/modal.task_command_router.TaskCommandRouter/",
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Control => "control",
            Self::Router => "router",
        }
    }
}

/// How the stand-ins answer.
struct Script {
    /// Whether `SandboxCreate` is refused, with the secrets echoed in its
    /// message.
    refuse_create: bool,
    /// Whether the router address the control API names uses TLS while the
    /// control API does not.
    router_over_tls: bool,
    /// Whether the first command's wait fails, with the router's token in
    /// its message.
    fail_wait: bool,
    /// Whether the guest image's build fails, with the owner's token and
    /// the auth token in its exception.
    fail_build: bool,
    /// The guest frames the file tool reads off.
    transcript: Vec<u8>,
}

/// One call a stand-in saw.
struct Call {
    service: Service,
    method: String,
    headers: HeaderMap,
    message: Vec<u8>,
}

impl Call {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(name)
            .map(|value| value.to_str().expect("a text header"))
    }
}

#[derive(Clone)]
struct StandIn {
    script: Arc<Script>,
    calls: Arc<Mutex<Vec<Call>>>,
    router: Arc<OnceLock<String>>,
}

/// An answer: its messages then an OK status, or a status alone.
enum Answer {
    Messages(Vec<Vec<u8>>),
    Status(u32, String),
}

/// A response body of data frames then trailers.
struct Reply(VecDeque<Frame<Bytes>>);

impl Body for Reply {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<std::result::Result<Frame<Bytes>, Infallible>>> {
        Poll::Ready(self.0.pop_front().map(Ok))
    }

    fn is_end_stream(&self) -> bool {
        self.0.is_empty()
    }
}

fn response(answer: Answer) -> Response<Reply> {
    let builder = Response::builder().header("content-type", "application/grpc");
    match answer {
        Answer::Messages(messages) => {
            let mut framed = Vec::new();
            for message in &messages {
                framed.push(0);
                framed.extend_from_slice(&u32::try_from(message.len()).unwrap().to_be_bytes());
                framed.extend_from_slice(message);
            }
            let mut frames: VecDeque<Frame<Bytes>> = framed
                .chunks(FRAME_BYTES)
                .map(|chunk| Frame::data(Bytes::copy_from_slice(chunk)))
                .collect();
            let mut trailers = HeaderMap::new();
            trailers.insert("grpc-status", "0".parse().unwrap());
            frames.push_back(Frame::trailers(trailers));
            builder.body(Reply(frames)).unwrap()
        }
        Answer::Status(code, message) => builder
            .header("grpc-status", code.to_string())
            .header("grpc-message", message)
            .body(Reply(VecDeque::new()))
            .unwrap(),
    }
}

impl StandIn {
    fn calls_of(&self, method: &str) -> usize {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .filter(|call| call.method == method)
            .count()
    }

    /// The waits on the command `exec` so far.
    fn waits_of(&self, exec: &str) -> usize {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .filter(|call| {
                call.method == "TaskExecWait" && text(&call.message, 2).as_deref() == Some(exec)
            })
            .count()
    }

    /// The command the call `exec` started.
    fn command_of(&self, exec: &str) -> Vec<String> {
        let calls = self.calls.lock().unwrap();
        let start = calls
            .iter()
            .find(|call| {
                call.method == "TaskExecStart" && text(&call.message, 2).as_deref() == Some(exec)
            })
            .expect("the command was started");
        texts(&start.message, 3)
    }

    fn answer(&self, method: &str, message: &[u8]) -> Answer {
        let script = &self.script;
        let fields: Vec<(u32, Field)> = match method {
            "AuthTokenGet" => vec![string_field(1, AUTH_TOKEN)],
            "EnvironmentGetOrCreate" => vec![
                string_field(1, "en-1"),
                message_field(
                    2,
                    &[
                        string_field(1, "main"),
                        message_field(2, &[string_field(1, "2025.06")]),
                    ],
                ),
            ],
            "AppGetOrCreate" => vec![string_field(1, "ap-1")],
            // Not built yet: the client joins the build.
            "ImageGetOrCreate" => vec![string_field(1, "im-1")],
            // GenericResult: status 2 (failure), then the exception.
            "ImageJoinStreaming" if script.fail_build => {
                let exception =
                    format!("registry refused {TOKEN_ID}:{TOKEN_SECRET} ({AUTH_TOKEN})");
                return Answer::Messages(vec![encode(&[
                    message_field(1, &[(1, Field::Varint(2)), string_field(2, &exception)]),
                    string_field(3, "entry-1"),
                ])]);
            }
            "ImageJoinStreaming" => {
                return Answer::Messages(vec![
                    encode(&[string_field(3, "entry-1")]),
                    encode(&[
                        message_field(1, &[(1, Field::Varint(1))]),
                        string_field(3, "entry-2"),
                    ]),
                ]);
            }
            "SandboxCreate" if script.refuse_create => {
                return Answer::Status(
                    UNAUTHENTICATED,
                    format!("invalid token {TOKEN_SECRET} with {AUTH_TOKEN}"),
                );
            }
            "SandboxCreate" => vec![string_field(1, "sb-1")],
            // The first poll finds the sandbox not scheduled yet.
            "SandboxGetTaskId" if self.calls_of(method) == 0 => vec![],
            "SandboxGetTaskId" => vec![string_field(1, "ta-1")],
            "TaskGetCommandRouterAccess" => {
                let router = self.router.get().expect("the router's address");
                let router = if script.router_over_tls {
                    router.replace("http://", "https://")
                } else {
                    router.clone()
                };
                vec![string_field(1, ROUTER_TOKEN), string_field(2, &router)]
            }
            "SandboxTerminate" | "TaskExecStart" | "TaskExecStdinWrite" => vec![],
            "TaskExecWait" => {
                let exec = text(message, 2).expect("an exec id");
                if script.fail_wait {
                    return Answer::Status(
                        UNAVAILABLE,
                        format!("router lost, token {ROUTER_TOKEN}"),
                    );
                }
                let guest = self.command_of(&exec).first().map(String::as_str) == Some(GUEST_BIN);
                // The guest outlives its first wait's own deadline.
                if guest && self.waits_of(&exec) == 0 {
                    return Answer::Status(DEADLINE_EXCEEDED, "wait again".into());
                }
                vec![(1, Field::Varint(0))]
            }
            "TaskExecStdioRead" => {
                let exec = text(message, 2).expect("an exec id");
                let reads_a_file = self
                    .command_of(&exec)
                    .get(1)
                    .is_some_and(|command| command.contains("ReadFile"));
                if uint(message, 4).unwrap_or_default() == 0 && reads_a_file {
                    let (head, tail) = script.transcript.split_at(script.transcript.len() / 2);
                    return Answer::Messages(vec![
                        encode(&[(1, Field::Bytes(head.to_vec()))]),
                        encode(&[(1, Field::Bytes(tail.to_vec()))]),
                    ]);
                }
                return Answer::Messages(vec![]);
            }
            other => panic!("no stand-in answers {other}"),
        };
        Answer::Messages(vec![encode(&fields)])
    }
}

async fn serve(
    stand_in: StandIn,
    service: Service,
    request: Request<Incoming>,
) -> std::result::Result<Response<Reply>, Infallible> {
    let (parts, mut body) = request.into_parts();
    let mut framed = Vec::new();
    while let Some(frame) = poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await {
        if let Ok(data) = frame.expect("a request frame").into_data() {
            framed.extend_from_slice(&data);
        }
    }
    assert_eq!(framed[0], 0, "an uncompressed message");
    let length = usize::try_from(u32::from_be_bytes(framed[1..5].try_into().unwrap())).unwrap();
    assert_eq!(framed.len(), 5 + length, "one message");
    let message = framed[5..].to_vec();
    let method = parts
        .uri
        .path()
        .strip_prefix(service.path())
        .unwrap_or_else(|| panic!("{} called {}", service.name(), parts.uri.path()))
        .to_owned();
    let answer = stand_in.answer(&method, &message);
    stand_in.calls.lock().unwrap().push(Call {
        service,
        method,
        headers: parts.headers,
        message,
    });
    Ok(response(answer))
}

/// Serves `service` over HTTP/2 in the clear on a loopback port, on its own
/// runtime thread, and answers its base URL.
fn start_service(stand_in: StandIn, service: Service) -> String {
    let (bound, address) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("the stand-in's runtime");
        runtime.block_on(async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind the stand-in");
            bound
                .send(listener.local_addr().expect("the stand-in's address"))
                .unwrap();
            loop {
                let (stream, _) = listener.accept().await.expect("accept a client");
                let stand_in = stand_in.clone();
                tokio::spawn(async move {
                    // A client that hangs up ends its own connection.
                    let _ = http2::Builder::new(TokioExecutor::new())
                        .serve_connection(
                            TokioIo::new(stream),
                            service_fn(move |request| serve(stand_in.clone(), service, request)),
                        )
                        .await;
                });
            }
        });
    });
    format!("http://{}", address.recv().expect("the stand-in bound"))
}

struct Fixture {
    vault: VendorVault,
    stand_in: StandIn,
    backends: Arc<dyn SandboxBackends>,
}

impl Fixture {
    /// A vault whose owner stored a Modal token in custody, bound to
    /// `sandbox:modal` and switched to it, and stand-ins that answer as
    /// `script` says.
    fn new(script: Script) -> Self {
        let vault = VendorVault::new(
            SandboxVendor::Modal,
            KEY_NAME,
            &format!("{TOKEN_ID}:{TOKEN_SECRET}"),
        );
        let stand_in = StandIn {
            script: Arc::new(script),
            calls: Arc::new(Mutex::new(Vec::new())),
            router: Arc::new(OnceLock::new()),
        };
        let router = start_service(stand_in.clone(), Service::Router);
        stand_in.router.set(router).unwrap();
        let api = start_service(stand_in.clone(), Service::Control);
        let backends = served_modal_backends(&vault.vault, &api, vault.dir.path().join("vm"));
        vault
            .switch(
                SandboxProvider::Vendor(SandboxVendor::Modal),
                Some(KEY_NAME),
            )
            .expect("the owner switches to Modal with a key");
        Self {
            vault,
            stand_in,
            backends,
        }
    }

    fn run(&self, console: &mut Console) -> Result<(MicroVmSandboxAdapter, MicroVmExit)> {
        self.vault.run(&*self.backends, console)
    }

    fn calls(&self) -> Vec<String> {
        self.stand_in
            .calls
            .lock()
            .unwrap()
            .iter()
            .map(|call| format!("{} {}", call.service.name(), call.method))
            .collect()
    }

    /// The messages of every call of `method`.
    fn messages(&self, method: &str) -> Vec<Vec<u8>> {
        self.stand_in
            .calls
            .lock()
            .unwrap()
            .iter()
            .filter(|call| call.method == method)
            .map(|call| call.message.clone())
            .collect()
    }
}

/// The control calls of a create up to the sandbox's router access.
const CREATE_CALLS: [&str; 9] = [
    "control AuthTokenGet",
    "control EnvironmentGetOrCreate",
    "control AppGetOrCreate",
    "control ImageGetOrCreate",
    "control ImageJoinStreaming",
    "control SandboxCreate",
    "control SandboxGetTaskId",
    "control SandboxGetTaskId",
    "control TaskGetCommandRouterAccess",
];
const TERMINATE_CALLS: [&str; 2] = ["control AuthTokenGet", "control SandboxTerminate"];

fn script() -> Script {
    Script {
        refuse_create: false,
        router_over_tls: false,
        fail_wait: false,
        fail_build: false,
        transcript: guest_frames(),
    }
}

#[test]
fn a_switched_run_goes_to_modal_with_each_secret_at_its_own_service() {
    let fixture = Fixture::new(script());
    let mut console = Console::default();
    let (mut adapter, exit) = fixture.run(&mut console).expect("the Modal run");
    assert_eq!(exit.status, 0);
    assert_eq!(exit.result_json.as_deref(), Some("{\"ok\":true}"));
    assert_eq!(console.0, ["logged"]);

    let proposals = adapter.collect_overlay_proposals().expect("proposals");
    assert_eq!(proposals.len(), 1);
    assert_eq!(proposals[0].kind(), SandboxProposalKind::FileEdit);
    let SandboxProposalWrite::FileEdit(edit) = proposals[0].write() else {
        panic!("a file edit");
    };
    assert_eq!(edit.path.as_str(), "/mnt/workspace/new.txt");
    let manifest = adapter.session_manifest().expect("manifest");
    assert_eq!(manifest.backend, "vendor:modal");
    assert!(manifest.fence_unproven);

    let mut expected: Vec<&str> = CREATE_CALLS.to_vec();
    expected.extend([
        // mkdir
        "router TaskExecStart",
        "router TaskExecStdinWrite",
        "router TaskExecWait",
        // the host's frames, through the file tool's stdin
        "router TaskExecStart",
        "router TaskExecStdinWrite",
        "router TaskExecStdinWrite",
        "router TaskExecWait",
        // the guest, waited on past one wait's deadline
        "router TaskExecStart",
        "router TaskExecStdinWrite",
        "router TaskExecWait",
        "router TaskExecWait",
        // the guest's frames, off the file tool's stdout
        "router TaskExecStart",
        "router TaskExecStdioRead",
        "router TaskExecWait",
    ]);
    expected.extend(TERMINATE_CALLS);
    assert_eq!(fixture.calls(), expected);

    let calls = fixture.stand_in.calls.lock().unwrap();
    for call in calls.iter() {
        let what = format!("{} {}", call.service.name(), call.method);
        assert_eq!(
            call.header("content-type"),
            Some("application/grpc"),
            "{what}"
        );
        assert_eq!(call.header("te"), Some("trailers"), "{what}");
        let timeout = call
            .header("grpc-timeout")
            .expect("each call has a deadline");
        let millis: u64 = timeout
            .strip_suffix('m')
            .expect("milliseconds")
            .parse()
            .unwrap();
        assert!(millis > 0 && millis <= 60_000, "{what}: {timeout}");
        match call.service {
            Service::Control => {
                assert_eq!(call.header("x-modal-token-id"), Some(TOKEN_ID), "{what}");
                assert_eq!(
                    call.header("x-modal-token-secret"),
                    Some(TOKEN_SECRET),
                    "{what}"
                );
                assert_eq!(call.header("x-modal-client-type"), Some("9"), "{what}");
                assert_eq!(
                    call.header("x-modal-client-version"),
                    Some("1.0.0"),
                    "{what}"
                );
                assert_eq!(call.header("x-modal-host"), Some("127.0.0.1"), "{what}");
                let auth = (call.method != "AuthTokenGet").then_some(AUTH_TOKEN);
                assert_eq!(call.header("x-modal-auth-token"), auth, "{what}");
                assert_eq!(call.header("authorization"), None, "{what}");
            }
            Service::Router => {
                let bearer = format!("Bearer {ROUTER_TOKEN}");
                assert_eq!(
                    call.header("authorization"),
                    Some(bearer.as_str()),
                    "{what}"
                );
                assert_eq!(call.header("x-modal-token-id"), None, "{what}");
                assert_eq!(call.header("x-modal-token-secret"), None, "{what}");
                assert_eq!(call.header("x-modal-auth-token"), None, "{what}");
            }
        }
        for secret in [TOKEN_ID, TOKEN_SECRET, AUTH_TOKEN, ROUTER_TOKEN] {
            assert!(!contains(&call.message, secret.as_bytes()), "{what}");
        }
    }
    drop(calls);

    let app = &fixture.messages("AppGetOrCreate")[0];
    assert_eq!(text(app, 1).as_deref(), Some("oneiron-batch"));
    assert_eq!(uint(app, 3), Some(1), "made when missing");

    let image = &fixture.messages("ImageGetOrCreate")[0];
    let recipe = bytes(image, 2).expect("an image recipe");
    assert_eq!(texts(&recipe, 6), [format!("FROM {GUEST_IMAGE}")]);
    assert_eq!(text(image, 4).as_deref(), Some("ap-1"));
    assert_eq!(text(image, 9).as_deref(), Some("2025.06"));
    let join = &fixture.messages("ImageJoinStreaming")[0];
    assert_eq!(text(join, 1).as_deref(), Some("im-1"));
    assert!(float(join, 2).expect("a wait") > 0.0);

    let create = &fixture.messages("SandboxCreate")[0];
    assert_eq!(text(create, 1).as_deref(), Some("ap-1"));
    let definition = bytes(create, 2).expect("a sandbox definition");
    assert_eq!(text(&definition, 3).as_deref(), Some("im-1"));
    assert!(texts(&definition, 1).is_empty(), "Modal's own entrypoint");
    let lifetime = uint(&definition, 7).expect("a lifetime in seconds");
    assert!(
        lifetime > 0 && lifetime <= STEP_SECONDS + 60,
        "the sandbox lives the step's time and a margin: {lifetime}"
    );
    let resources = bytes(&definition, 5).expect("resources");
    assert_eq!(uint(&resources, 2), Some(128), "the smallest memory asked");
    assert_eq!(
        uint(&resources, 5),
        Some(512),
        "the step's memory is the cap"
    );
    let network = bytes(&definition, 22).expect("network access");
    assert_eq!(uint(&network, 1), Some(2), "all network access blocked");
    assert_eq!(last(&definition, 20), None, "no open port");

    for poll in fixture.messages("SandboxGetTaskId") {
        assert_eq!(text(&poll, 1).as_deref(), Some("sb-1"));
        assert_eq!(uint(&poll, 3), Some(1), "waits until the sandbox is ready");
        assert!(float(&poll, 2).expect("a wait") > 0.0);
    }

    let starts = fixture.messages("TaskExecStart");
    let commands: Vec<Vec<String>> = starts.iter().map(|start| texts(start, 3)).collect();
    let write = json!({ "WriteFile": { "path": "/tmp/oneiron-batch/host-frames" } }).to_string();
    let read = json!({ "ReadFile": { "path": "/tmp/oneiron-batch/guest-frames" } }).to_string();
    assert_eq!(
        commands,
        [
            vec![
                "mkdir",
                "-m",
                "0700",
                "/tmp/oneiron-batch",
                "/tmp/oneiron-batch/workspace"
            ],
            vec![FS_TOOLS, write.as_str()],
            vec![
                GUEST_BIN,
                "--batch",
                "/tmp/oneiron-batch/host-frames",
                "/tmp/oneiron-batch/guest-frames",
                "/tmp/oneiron-batch/workspace",
            ],
            vec![FS_TOOLS, read.as_str()],
        ]
    );
    let outputs: Vec<(u64, u64)> = starts
        .iter()
        .map(|start| (uint(start, 4).unwrap_or(0), uint(start, 5).unwrap_or(0)))
        .collect();
    assert_eq!(
        outputs,
        [(0, 0), (0, 1), (0, 0), (1, 1)],
        "output piped only to read"
    );
    let mut execs: Vec<String> = starts.iter().map(|start| text(start, 2).unwrap()).collect();
    for start in &starts {
        assert_eq!(text(start, 1).as_deref(), Some("ta-1"));
        let timeout = uint(start, 6).expect("the command dies at the step's deadline");
        assert!(timeout > 0 && timeout <= STEP_SECONDS);
    }
    execs.sort();
    execs.dedup();
    assert_eq!(execs.len(), 4, "each command has its own exec id");

    let writes = fixture.messages("TaskExecStdinWrite");
    let upload = &writes[1];
    assert!(
        contains(
            &bytes(upload, 4).expect("the frames"),
            b"\"type\":\"start\""
        ),
        "the upload is the host's opening"
    );
    assert_eq!(uint(upload, 3), Some(0), "from the file's start");
    assert_eq!(uint(&writes[2], 5), Some(1), "then the file's end");
    for closed in [&writes[0], &writes[3]] {
        assert_eq!(uint(closed, 5), Some(1), "a command reads no input");
    }

    let terminate = &fixture.messages("SandboxTerminate")[0];
    assert_eq!(text(terminate, 1).as_deref(), Some("sb-1"));
}

#[test]
fn a_refused_create_never_shows_a_secret() {
    let fixture = Fixture::new(Script {
        refuse_create: true,
        ..script()
    });
    let Err(error) = fixture.run(&mut Console::default()) else {
        panic!("a refused create ran");
    };
    let text = error.to_string();
    assert!(text.contains("modal answered UNAUTHENTICATED"), "{text}");
    assert!(!text.contains(TOKEN_SECRET), "the key is scrubbed: {text}");
    assert!(
        !text.contains(AUTH_TOKEN),
        "the auth token is scrubbed: {text}"
    );
    assert_eq!(fixture.calls(), &CREATE_CALLS[..6]);
}

#[test]
fn a_failed_image_build_never_shows_a_secret() {
    let fixture = Fixture::new(Script {
        fail_build: true,
        ..script()
    });
    let Err(error) = fixture.run(&mut Console::default()) else {
        panic!("a failed image build ran");
    };
    let text = error.to_string();
    assert!(
        text.contains("modal could not build the guest image: failure: registry refused"),
        "{text}"
    );
    for secret in [TOKEN_ID, TOKEN_SECRET, AUTH_TOKEN] {
        assert!(!text.contains(secret), "a secret is scrubbed: {text}");
    }
    assert_eq!(fixture.calls(), &CREATE_CALLS[..5]);
}

#[test]
fn a_router_not_reached_as_the_api_is_is_refused_and_the_sandbox_terminated() {
    let fixture = Fixture::new(Script {
        router_over_tls: true,
        ..script()
    });
    let Err(error) = fixture.run(&mut Console::default()) else {
        panic!("a run with a router reached otherwise ran");
    };
    let text = error.to_string();
    assert!(
        text.contains("a router not reached as its control API is"),
        "{text}"
    );
    assert!(
        !text.contains(ROUTER_TOKEN),
        "the router token is scrubbed: {text}"
    );
    let mut expected: Vec<&str> = CREATE_CALLS.to_vec();
    expected.extend(TERMINATE_CALLS);
    assert_eq!(fixture.calls(), expected);
}

#[test]
fn a_failed_command_wait_terminates_the_sandbox_and_hides_the_token() {
    let fixture = Fixture::new(Script {
        fail_wait: true,
        ..script()
    });
    let Err(error) = fixture.run(&mut Console::default()) else {
        panic!("a failed command wait ran");
    };
    let text = error.to_string();
    assert!(text.contains("modal answered UNAVAILABLE"), "{text}");
    assert!(
        !text.contains(ROUTER_TOKEN),
        "the token is scrubbed: {text}"
    );
    let mut expected: Vec<&str> = CREATE_CALLS.to_vec();
    expected.extend([
        "router TaskExecStart",
        "router TaskExecStdinWrite",
        "router TaskExecWait",
    ]);
    expected.extend(TERMINATE_CALLS);
    assert_eq!(fixture.calls(), expected);
}
