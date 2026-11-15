//! A vault switched to E2B runs its finite Foreign guests on E2B's
//! sandboxes, on the owner's key in custody (L8-43). A loopback stand-in
//! answers E2B's control API and the sandbox's daemon (envd), records each
//! call, streams each command's events in Connect's envelope framing, and
//! serves the guest transcript the test gives it.
//!
//! The run makes one sandbox from the template of the pinned guest image,
//! with no internet access and a lifetime of the step's own time; it sends
//! the owner's key only to the control API and the sandbox's access token
//! only to the daemon; and it kills the sandbox at the end. A refused
//! create, a sandbox with no access token and a failed command stream never
//! show a secret and leave no sandbox behind.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server --all-features
//! --features oneiron/test-support --test sandbox_vendor_e2b`.
#![cfg(all(oneiron_test_support, target_os = "linux"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "sandbox_vendor/fixture.rs"]
mod fixture;

use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use fixture::{
    Console, GUEST_IMAGE_NAME, STEP_SECONDS, VendorVault, contains, guest_frames, start_stand_in,
};
use oneiron::Result;
use oneiron::code_sandbox::microvm::{MicroVmExit, MicroVmSandboxAdapter, SandboxBackends};
use oneiron::code_sandbox::{
    SandboxProposalKind, SandboxProposalWrite, SandboxProvider, SandboxVendor,
};
use oneiron_server::test_doors::sandbox_vendor::served_e2b_backends;
use serde_json::{Value, json};

const KEY_NAME: &str = "e2b.api_key";
const KEY_VALUE: &str = "e2b_test_key_7c2d91";
const ACCESS_TOKEN: &str = "envd-token-41a9e6";
/// `user:` in HTTP basic form: the daemon's name for the sandbox user.
const SANDBOX_USER: &str = "Basic dXNlcjo=";

/// How a command's stream ends.
#[derive(Clone, Copy)]
enum StreamEnd {
    /// The process's end event, exit code 0, then a clean end of stream.
    Exited,
    /// No end event: the end of stream carries an error naming the token.
    Failed,
}

/// How the stand-in answers.
struct Script {
    /// Whether the create call is refused, with the key echoed in its body.
    refuse_create: bool,
    /// Whether the create answer carries the daemon's access token.
    access_token: bool,
    stream_end: StreamEnd,
    /// The guest frames the download answers.
    transcript: Vec<u8>,
}

/// One call the stand-in saw.
struct Call {
    method: String,
    path: String,
    query: String,
    /// The `X-API-Key` header, if any.
    api_key: Option<String>,
    /// The `X-Access-Token` header, if any.
    access_token: Option<String>,
    content_type: Option<String>,
    authorization: Option<String>,
    /// The `E2b-Sandbox-Id` routing header, if any.
    routed_to: Option<String>,
    /// The `Connect-Timeout-Ms` header, if any.
    timeout_ms: Option<String>,
    body: Vec<u8>,
}

#[derive(Clone)]
struct StandIn {
    script: Arc<Script>,
    calls: Arc<Mutex<Vec<Call>>>,
}

fn header(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

/// One Connect envelope: `flags`, the message's length, its JSON.
fn envelope(flags: u8, message: &Value) -> Vec<u8> {
    let body = serde_json::to_vec(message).unwrap();
    let mut framed = vec![flags];
    framed.extend_from_slice(&u32::try_from(body.len()).unwrap().to_be_bytes());
    framed.extend_from_slice(&body);
    framed
}

/// The messages of a request body in envelopes.
fn unframed(mut body: &[u8]) -> Vec<Value> {
    let mut messages = Vec::new();
    while !body.is_empty() {
        assert_eq!(body[0], 0, "a plain envelope");
        let length = usize::try_from(u32::from_be_bytes(body[1..5].try_into().unwrap())).unwrap();
        messages.push(serde_json::from_slice(&body[5..5 + length]).expect("envelope JSON"));
        body = &body[5 + length..];
    }
    messages
}

/// A command's stream: its start, some output, a keepalive, then its end
/// as `end` says. JSON leaves out a zero exit code.
fn command_stream(end: StreamEnd) -> Vec<u8> {
    let mut stream = Vec::new();
    stream.extend(envelope(0, &json!({ "event": { "start": { "pid": 7 } } })));
    stream.extend(envelope(
        0,
        &json!({ "event": { "data": { "stdout": "b2s=" } } }),
    ));
    stream.extend(envelope(0, &json!({ "event": { "keepalive": {} } })));
    match end {
        StreamEnd::Exited => {
            stream.extend(envelope(
                0,
                &json!({ "event": { "end": { "exited": true, "status": "exit status 0" } } }),
            ));
            stream.extend(envelope(0x02, &json!({})));
        }
        StreamEnd::Failed => stream.extend(envelope(
            0x02,
            &json!({ "error": {
                "code": "unavailable",
                "message": format!("daemon lost, token {ACCESS_TOKEN}"),
            } }),
        )),
    }
    stream
}

async fn answer(
    State(stand_in): State<StandIn>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let path = uri.path().to_owned();
    stand_in.calls.lock().unwrap().push(Call {
        method: method.to_string(),
        path: path.clone(),
        query: uri.query().unwrap_or_default().to_owned(),
        api_key: header(&headers, "x-api-key"),
        access_token: header(&headers, "x-access-token"),
        content_type: header(&headers, "content-type"),
        authorization: header(&headers, "authorization"),
        routed_to: header(&headers, "e2b-sandbox-id"),
        timeout_ms: header(&headers, "connect-timeout-ms"),
        body: body.to_vec(),
    });
    let script = &stand_in.script;
    match (method.as_str(), path.as_str()) {
        ("POST", "/v2/sandboxes") if script.refuse_create => (
            StatusCode::UNAUTHORIZED,
            format!("{{\"code\":401,\"message\":\"invalid key {KEY_VALUE}\"}}"),
        )
            .into_response(),
        ("POST", "/v2/sandboxes") => {
            let mut made = json!({
                "templateID": GUEST_IMAGE_NAME,
                "sandboxID": "sb1",
                "clientID": "client",
                "envdVersion": "0.6.10",
                "domain": "elsewhere.example",
            });
            if script.access_token {
                made["envdAccessToken"] = json!(ACCESS_TOKEN);
            }
            (StatusCode::CREATED, axum::Json(made)).into_response()
        }
        ("DELETE", "/sandboxes/sb1") => StatusCode::NO_CONTENT.into_response(),
        ("POST", "/envd/sb1/process.Process/Start") => (
            [("content-type", "application/connect+json")],
            command_stream(script.stream_end),
        )
            .into_response(),
        ("POST", "/envd/sb1/files") => axum::Json(json!([{
            "path": "/tmp/oneiron-batch/host-frames",
            "name": "host-frames",
            "type": "file",
        }]))
        .into_response(),
        ("GET", "/envd/sb1/files") => script.transcript.clone().into_response(),
        _ => StatusCode::NOT_FOUND.into_response(),
    }
}

struct Fixture {
    vault: VendorVault,
    calls: Arc<Mutex<Vec<Call>>>,
    backends: Arc<dyn SandboxBackends>,
}

impl Fixture {
    /// A vault whose owner stored an E2B key in custody, bound to
    /// `sandbox:e2b` and switched to it, and a stand-in that answers as
    /// `script` says.
    fn new(script: Script) -> Self {
        let vault = VendorVault::new(SandboxVendor::E2b, KEY_NAME, KEY_VALUE);
        let calls = Arc::new(Mutex::new(Vec::new()));
        let base = start_stand_in(Router::new().fallback(answer).with_state(StandIn {
            script: Arc::new(script),
            calls: Arc::clone(&calls),
        }));
        let backends = served_e2b_backends(
            &vault.vault,
            &base,
            &format!("{base}/envd/{{sandbox}}"),
            vault.dir.path().join("vm"),
        );
        vault
            .switch(SandboxProvider::Vendor(SandboxVendor::E2b), Some(KEY_NAME))
            .expect("the owner switches to E2B with a key");
        Self {
            vault,
            calls,
            backends,
        }
    }

    fn run(&self, console: &mut Console) -> Result<(MicroVmSandboxAdapter, MicroVmExit)> {
        self.vault.run(&*self.backends, console)
    }

    fn calls(&self) -> Vec<String> {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .map(|call| format!("{} {}", call.method, call.path))
            .collect()
    }
}

#[test]
fn a_switched_run_goes_to_e2b_with_each_secret_at_its_own_base() {
    let fixture = Fixture::new(Script {
        refuse_create: false,
        access_token: true,
        stream_end: StreamEnd::Exited,
        transcript: guest_frames(),
    });
    let mut console = Console::default();
    let (mut adapter, exit) = fixture.run(&mut console).expect("the E2B run");
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
    assert_eq!(manifest.backend, "vendor:e2b");
    assert!(manifest.fence_unproven);

    assert_eq!(
        fixture.calls(),
        [
            "POST /v2/sandboxes",
            "POST /envd/sb1/process.Process/Start",
            "POST /envd/sb1/files",
            "POST /envd/sb1/process.Process/Start",
            "GET /envd/sb1/files",
            "DELETE /sandboxes/sb1",
        ]
    );
    let calls = fixture.calls.lock().unwrap();
    for call in calls.iter() {
        let control = !call.path.starts_with("/envd/");
        if control {
            assert_eq!(call.api_key.as_deref(), Some(KEY_VALUE), "{}", call.path);
            assert_eq!(call.access_token, None, "{}", call.path);
        } else {
            assert_eq!(
                call.access_token.as_deref(),
                Some(ACCESS_TOKEN),
                "{}",
                call.path
            );
            assert_eq!(call.api_key, None, "{}", call.path);
            assert_eq!(call.routed_to.as_deref(), Some("sb1"), "{}", call.path);
        }
        assert!(!contains(&call.body, KEY_VALUE.as_bytes()), "{}", call.path);
        assert!(
            !contains(&call.body, ACCESS_TOKEN.as_bytes()),
            "{}",
            call.path
        );
    }

    let created: Value = serde_json::from_slice(&calls[0].body).expect("create body");
    assert_eq!(created["templateID"], GUEST_IMAGE_NAME);
    assert_eq!(created["allow_internet_access"], false);
    assert_eq!(created["network"]["allowPublicTraffic"], false);
    assert_eq!(created["autoPause"], false);
    let lifetime = created["timeout"].as_u64().expect("a lifetime in seconds");
    assert!(
        lifetime > 0 && lifetime <= STEP_SECONDS + 60,
        "the sandbox lives the step's time and a margin: {lifetime}"
    );

    let starts: Vec<&Call> = calls
        .iter()
        .filter(|call| call.path.ends_with("/process.Process/Start"))
        .collect();
    for start in &starts {
        assert_eq!(
            start.content_type.as_deref(),
            Some("application/connect+json")
        );
        assert_eq!(start.authorization.as_deref(), Some(SANDBOX_USER));
        let timeout_ms: u64 = start
            .timeout_ms
            .as_deref()
            .expect("the command dies at the step's deadline")
            .parse()
            .expect("milliseconds");
        assert!(timeout_ms > 0 && timeout_ms <= STEP_SECONDS * 1000);
    }
    let commands: Vec<Value> = starts
        .iter()
        .flat_map(|start| unframed(&start.body))
        .collect();
    assert_eq!(
        commands,
        [
            json!({
                "process": {
                    "cmd": "mkdir",
                    "args": ["-m", "0700", "/tmp/oneiron-batch", "/tmp/oneiron-batch/workspace"],
                    "envs": {},
                },
                "stdin": false,
            }),
            json!({
                "process": {
                    "cmd": "/usr/local/bin/oneiron-guest",
                    "args": [
                        "--batch",
                        "/tmp/oneiron-batch/host-frames",
                        "/tmp/oneiron-batch/guest-frames",
                        "/tmp/oneiron-batch/workspace",
                    ],
                    "envs": {},
                },
                "stdin": false,
            }),
        ]
    );
    let upload = &calls[2];
    assert_eq!(
        upload.query,
        "path=%2Ftmp%2Foneiron-batch%2Fhost-frames&username=user"
    );
    assert_eq!(
        upload.content_type.as_deref(),
        Some("application/octet-stream"),
        "a raw body"
    );
    assert!(
        contains(&upload.body, b"\"type\":\"start\""),
        "the upload is the host's opening"
    );
    assert_eq!(
        calls[4].query,
        "path=%2Ftmp%2Foneiron-batch%2Fguest-frames&username=user"
    );
}

#[test]
fn a_refused_create_never_shows_the_key() {
    let fixture = Fixture::new(Script {
        refuse_create: true,
        access_token: true,
        stream_end: StreamEnd::Exited,
        transcript: guest_frames(),
    });
    let Err(error) = fixture.run(&mut Console::default()) else {
        panic!("a refused create ran");
    };
    let text = error.to_string();
    assert!(text.contains("e2b answered 401"), "{text}");
    assert!(!text.contains(KEY_VALUE), "the key is scrubbed: {text}");
    assert_eq!(fixture.calls(), ["POST /v2/sandboxes"]);
}

#[test]
fn a_sandbox_with_no_access_token_is_killed_unused() {
    let fixture = Fixture::new(Script {
        refuse_create: false,
        access_token: false,
        stream_end: StreamEnd::Exited,
        transcript: guest_frames(),
    });
    let Err(error) = fixture.run(&mut Console::default()) else {
        panic!("a sandbox with no access token ran");
    };
    let text = error.to_string();
    assert!(text.contains("no access token"), "{text}");
    assert_eq!(
        fixture.calls(),
        ["POST /v2/sandboxes", "DELETE /sandboxes/sb1"]
    );
}

#[test]
fn a_failed_command_stream_kills_the_sandbox_and_hides_the_token() {
    let fixture = Fixture::new(Script {
        refuse_create: false,
        access_token: true,
        stream_end: StreamEnd::Failed,
        transcript: guest_frames(),
    });
    let Err(error) = fixture.run(&mut Console::default()) else {
        panic!("a failed command stream ran");
    };
    let text = error.to_string();
    assert!(
        text.contains("e2b ended the command with unavailable"),
        "{text}"
    );
    assert!(
        !text.contains(ACCESS_TOKEN),
        "the token is scrubbed: {text}"
    );
    assert_eq!(
        fixture.calls(),
        [
            "POST /v2/sandboxes",
            "POST /envd/sb1/process.Process/Start",
            "DELETE /sandboxes/sb1",
        ]
    );
}
