//! A vault switched to InstaBox runs its finite Foreign guests on InstaBox
//! machines, on the owner's key in custody (L8-43). A loopback stand-in
//! answers InstaBox's v1 API, records each call, answers the create's
//! operation as running at its first poll and done at its second, answers
//! each command's exit status file as missing at its first poll and
//! written at its second, and serves the guest transcript the test gives it
//! in the file the client copies the guest's frames to, and nowhere else.
//!
//! The run makes one machine from the owner's saved snapshot of the pinned
//! guest image, with none of the account's Secrets and a life of the step's
//! own time; it first makes the client's own directory as the machine's
//! user; it starts every command of the run detached, in a network
//! namespace of its own, as a user and group of its own with no
//! supplementary group and no new privilege; it stages the upload in the
//! client's directory and copies it into place as the guest's file, and
//! copies the guest's frames out as the guest before it reads them; it
//! sends the owner's key only to the API; and it deletes the machine at the
//! end, with a key of its own and confirming its id. A refused create, a
//! machine that fails to start, a confinement that cannot be made and a
//! machine that stops mid-run never show a secret and leave no machine
//! behind.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server --all-features
//! --features oneiron/test-support --test sandbox_vendor_instabox`.
#![cfg(all(oneiron_test_support, target_os = "linux"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "sandbox_vendor/fixture.rs"]
mod fixture;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use fixture::{
    Console, GUEST_IMAGE_NAME, STEP_SECONDS, VendorVault, contains, guest_frames, start_stand_in,
};
use oneiron::Result;
use oneiron::code_sandbox::microvm::{MicroVmExit, MicroVmSandboxAdapter, SandboxBackends};
use oneiron::code_sandbox::{
    SandboxProposalKind, SandboxProposalWrite, SandboxProvider, SandboxVendor,
};
use oneiron_server::test_doors::sandbox_vendor::served_instabox_backends;
use serde_json::{Value, json};

const KEY_NAME: &str = "instabox.api_key";
const KEY_VALUE: &str = "ibk_test_key_4d1f83";
/// The machine the stand-in makes, and its create operation.
const MACHINE: &str = "m_k7m2p9qr";
const OPERATION: &str = "op_c3x8";
const GUEST_FRAMES: &str = "/tmp/oneiron-batch/guest-frames";

/// What every command of the run starts under.
const CONFINEMENT: [&str; 13] = [
    "sudo",
    "-n",
    "unshare",
    "--net",
    "--",
    "setpriv",
    "--reuid",
    "70000",
    "--regid",
    "70000",
    "--clear-groups",
    "--no-new-privs",
    "--",
];

/// `argv`, confined and started detached by the machine's user, who writes
/// its exit status to `status_file`.
fn detached(status_file: &str, argv: &[&str]) -> Value {
    let mut detached = vec![
        "setsid",
        "-f",
        "sh",
        "-c",
        r#"exec </dev/null >/dev/null 2>&1; "$@"; echo "$?" >"$0.part" && mv -f "$0.part" "$0""#,
        status_file,
    ];
    detached.extend_from_slice(&CONFINEMENT);
    detached.extend_from_slice(argv);
    json!(detached)
}

/// The guest's frames, read as the guest into the client's file `copy`.
fn copied_out(copy: &str) -> Value {
    let mut copied = vec!["sh", "-c", r#"exec "$@" >"$0""#, copy];
    copied.extend_from_slice(&CONFINEMENT);
    copied.extend_from_slice(&["cat", "--", GUEST_FRAMES]);
    json!(copied)
}

/// How the stand-in answers.
struct Script {
    /// Whether the create call is refused, with the key echoed in its body.
    refuse_create: bool,
    /// Whether the create's operation fails at its second poll.
    fail_start: bool,
    /// Whether sudo refuses every confined command, which then exits 1.
    refuse_confinement: bool,
    /// Whether the machine stops at the guest's (the second command's)
    /// second exit status poll.
    stop_at_guest: bool,
    /// The guest frames the download answers.
    transcript: Vec<u8>,
}

impl Script {
    fn well() -> Self {
        Self {
            refuse_create: false,
            fail_start: false,
            refuse_confinement: false,
            stop_at_guest: false,
            transcript: guest_frames(),
        }
    }
}

/// One call the stand-in saw.
struct Call {
    method: String,
    path: String,
    query: HashMap<String, String>,
    api_key: Option<String>,
    authorization: Option<String>,
    idempotency_key: Option<String>,
    confirm_delete: Option<String>,
    content_type: Option<String>,
    body: Vec<u8>,
}

#[derive(Clone)]
struct StandIn {
    script: Arc<Script>,
    calls: Arc<Mutex<Vec<Call>>>,
    /// The polls of the create's operation so far.
    operation_polls: Arc<Mutex<u32>>,
    /// Each started command's number (from 1), by its exit status file.
    commands: Arc<Mutex<HashMap<String, u32>>>,
    /// The polls of each exit status file so far.
    status_polls: Arc<Mutex<HashMap<String, u32>>>,
    /// The files the guest's frames were copied to.
    copies: Arc<Mutex<Vec<String>>>,
}

fn header(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

fn error(status: StatusCode, code: &str, message: &str) -> Response {
    (
        status,
        Json(json!({
            "error": {
                "code": code, "message": message, "requestId": "req_1", "retryable": false,
            },
        })),
    )
        .into_response()
}

fn operation(state: &str, error: Value) -> Value {
    json!({
        "id": OPERATION, "machineId": MACHINE, "type": "create", "state": state,
        "phase": "booting", "error": error,
        "createdAt": "2026-11-15T06:00:00Z", "updatedAt": "2026-11-15T06:00:01Z",
    })
}

/// A waited command's result: every one the client waits for exits 0 here.
fn exec_result() -> Response {
    Json(json!({
        "stdout": "", "stderr": "", "exitCode": 0, "timedOut": false, "truncated": false,
    }))
    .into_response()
}

impl StandIn {
    fn exec(&self, body: &[u8]) -> Response {
        let request: Value = serde_json::from_slice(body).expect("an exec body");
        let argv: Vec<&str> = request["argv"]
            .as_array()
            .expect("an argv")
            .iter()
            .map(|arg| arg.as_str().expect("a string argument"))
            .collect();
        match argv[0] {
            "setsid" => {
                let mut commands = self.commands.lock().unwrap();
                let number = u32::try_from(commands.len()).unwrap() + 1;
                commands.insert(argv[5].to_owned(), number);
            }
            "sh" => self.copies.lock().unwrap().push(argv[3].to_owned()),
            _ => {}
        }
        exec_result()
    }

    fn content(&self, path: &str) -> Response {
        if self.copies.lock().unwrap().iter().any(|copy| copy == path) {
            return self.script.transcript.clone().into_response();
        }
        let Some(&command) = self.commands.lock().unwrap().get(path) else {
            return error(StatusCode::NOT_FOUND, "not_found", "no such file");
        };
        let poll = {
            let mut polls = self.status_polls.lock().unwrap();
            let poll = polls.entry(path.to_owned()).or_insert(0);
            *poll += 1;
            *poll
        };
        if poll == 1 {
            return error(StatusCode::NOT_FOUND, "not_found", "no such file");
        }
        if self.script.stop_at_guest && command == 2 {
            return error(
                StatusCode::CONFLICT,
                "machine_not_running",
                "the sandbox is stopped",
            );
        }
        if self.script.refuse_confinement {
            return "1\n".into_response();
        }
        "0\n".into_response()
    }
}

async fn answer(
    State(stand_in): State<StandIn>,
    method: Method,
    uri: Uri,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let path = uri.path().to_owned();
    stand_in.calls.lock().unwrap().push(Call {
        method: method.to_string(),
        path: path.clone(),
        query: query.clone(),
        api_key: header(&headers, "x-api-key"),
        authorization: header(&headers, "authorization"),
        idempotency_key: header(&headers, "idempotency-key"),
        confirm_delete: header(&headers, "x-confirm-delete"),
        content_type: header(&headers, "content-type"),
        body: body.to_vec(),
    });
    let script = &stand_in.script;
    let machine = format!("/machines/{MACHINE}");
    match (method.as_str(), path.as_str()) {
        ("POST", "/machines") if script.refuse_create => error(
            StatusCode::UNAUTHORIZED,
            "invalid_key",
            &format!("invalid key {KEY_VALUE}"),
        ),
        ("POST", "/machines") => {
            (StatusCode::ACCEPTED, Json(operation("queued", Value::Null))).into_response()
        }
        ("GET", path) if path == format!("/operations/{OPERATION}") => {
            let poll = {
                let mut polls = stand_in.operation_polls.lock().unwrap();
                *polls += 1;
                *polls
            };
            let answered = match (poll, script.fail_start) {
                (1, _) => operation("running", Value::Null),
                (_, true) => operation(
                    "failed",
                    json!({
                        "code": "no_capacity", "message": "no host had room",
                        "requestId": "req_2", "retryable": true,
                    }),
                ),
                (_, false) => operation("succeeded", Value::Null),
            };
            Json(answered).into_response()
        }
        ("POST", path) if path == format!("{machine}/exec") => stand_in.exec(&body),
        ("PUT", path) if path == format!("{machine}/files") => Json(json!({
            "path": query.get("path"), "size": body.len(), "mode": "0600",
        }))
        .into_response(),
        ("GET", path) if path == format!("{machine}/files/content") => {
            stand_in.content(query.get("path").map_or("", String::as_str))
        }
        ("DELETE", path) if path == machine => (
            StatusCode::ACCEPTED,
            Json(json!({
                "id": "op_d1", "machineId": MACHINE, "type": "delete", "state": "queued",
                "error": null, "createdAt": "2026-11-15T06:00:09Z",
                "updatedAt": "2026-11-15T06:00:09Z",
            })),
        )
            .into_response(),
        _ => error(StatusCode::NOT_FOUND, "not_found", "no such route"),
    }
}

struct Fixture {
    vault: VendorVault,
    calls: Arc<Mutex<Vec<Call>>>,
    backends: Arc<dyn SandboxBackends>,
}

impl Fixture {
    /// A vault whose owner stored an InstaBox key in custody, bound to
    /// `sandbox:instabox` and switched to it, and a stand-in that answers as
    /// `script` says.
    fn new(script: Script) -> Self {
        let vault = VendorVault::new(SandboxVendor::Instabox, KEY_NAME, KEY_VALUE);
        let calls = Arc::new(Mutex::new(Vec::new()));
        let base = start_stand_in(Router::new().fallback(answer).with_state(StandIn {
            script: Arc::new(script),
            calls: Arc::clone(&calls),
            operation_polls: Arc::new(Mutex::new(0)),
            commands: Arc::new(Mutex::new(HashMap::new())),
            status_polls: Arc::new(Mutex::new(HashMap::new())),
            copies: Arc::new(Mutex::new(Vec::new())),
        }));
        let backends = served_instabox_backends(&vault.vault, &base, vault.dir.path().join("vm"));
        vault
            .switch(
                SandboxProvider::Vendor(SandboxVendor::Instabox),
                Some(KEY_NAME),
            )
            .expect("the owner switches to InstaBox with a key");
        Self {
            vault,
            calls,
            backends,
        }
    }

    fn run(&self, console: &mut Console) -> Result<(MicroVmSandboxAdapter, MicroVmExit)> {
        self.vault.run(&*self.backends, console)
    }

    /// Each call as its method and path, and the file a file route names.
    fn calls(&self) -> Vec<String> {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .map(|call| match call.query.get("path") {
                Some(file) => format!("{} {} {file}", call.method, call.path),
                None => format!("{} {}", call.method, call.path),
            })
            .collect()
    }

    /// The JSON body of each call to `path`.
    fn bodies(&self, path: &str) -> Vec<Value> {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .filter(|call| call.path == path)
            .map(|call| serde_json::from_slice(&call.body).expect("a JSON body"))
            .collect()
    }
}

#[test]
fn a_switched_run_goes_to_instabox_with_the_key_only_at_its_api() {
    let fixture = Fixture::new(Script::well());
    let mut console = Console::default();
    let (mut adapter, exit) = fixture.run(&mut console).expect("the InstaBox run");
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
    assert_eq!(manifest.backend, "vendor:instabox");
    assert!(manifest.fence_unproven);

    let machine = format!("/machines/{MACHINE}");
    let operation = format!("GET /operations/{OPERATION}");
    let content = format!("GET {machine}/files/content");
    assert_eq!(
        fixture.calls(),
        [
            "POST /machines".to_owned(),
            operation.clone(),
            operation,
            format!("POST {machine}/exec"),
            format!("POST {machine}/exec"),
            format!("{content} /tmp/oneiron-client/status-0"),
            format!("{content} /tmp/oneiron-client/status-0"),
            format!("PUT {machine}/files /tmp/oneiron-client/upload-1"),
            format!("POST {machine}/exec"),
            format!("POST {machine}/exec"),
            format!("{content} /tmp/oneiron-client/status-2"),
            format!("{content} /tmp/oneiron-client/status-2"),
            format!("POST {machine}/exec"),
            format!("{content} /tmp/oneiron-client/download-3"),
            format!("DELETE {machine}"),
        ]
    );
    {
        let calls = fixture.calls.lock().unwrap();
        for call in calls.iter() {
            assert_eq!(call.api_key.as_deref(), Some(KEY_VALUE), "{}", call.path);
            assert_eq!(call.authorization, None, "{}", call.path);
            assert!(!contains(&call.body, KEY_VALUE.as_bytes()), "{}", call.path);
            let lifecycle = call.path == "/machines" || call.method == "DELETE";
            assert_eq!(
                call.idempotency_key.is_some(),
                lifecycle,
                "an Idempotency-Key on a create and a delete only: {}",
                call.path
            );
        }
        let create = calls.first().expect("the create");
        let delete = calls.last().expect("the delete");
        let (Some(created), Some(deleted)) = (&create.idempotency_key, &delete.idempotency_key)
        else {
            panic!("each lifecycle call has its key");
        };
        assert!(
            created.starts_with("oneiron-") && created.len() == 40,
            "{created}"
        );
        assert_ne!(created, deleted, "each call takes a key of its own");
        assert_eq!(
            delete.confirm_delete.as_deref(),
            Some(MACHINE),
            "the delete names its machine"
        );
        let upload = calls
            .iter()
            .find(|call| call.method == "PUT")
            .expect("the upload");
        assert_eq!(
            upload.query.get("mode").map(String::as_str),
            Some("0600"),
            "only the machine's user reads the staged file"
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
    }

    let created = &fixture.bodies("/machines")[0];
    let mut fields: Vec<&str> = created
        .as_object()
        .expect("a create body")
        .keys()
        .map(String::as_str)
        .collect();
    fields.sort_unstable();
    assert_eq!(
        fields,
        [
            "deleteAfterSeconds",
            "envSecrets",
            "metadata",
            "secrets",
            "snapshotId",
            "vault"
        ],
        "only fields InstaBox documents"
    );
    assert_eq!(created["snapshotId"], GUEST_IMAGE_NAME);
    assert_eq!(created["secrets"], json!([]));
    assert_eq!(created["envSecrets"], json!([]));
    assert_eq!(created["vault"], false);
    assert_eq!(created["metadata"]["oneiron"], "batch-run");
    let lifetime = created["deleteAfterSeconds"]
        .as_u64()
        .expect("a lifetime in seconds");
    assert!(
        (60..=STEP_SECONDS + 60).contains(&lifetime),
        "the machine lives the step's time and a margin: {lifetime}"
    );

    let commands = fixture.bodies(&format!("{machine}/exec"));
    let argvs: Vec<&Value> = commands.iter().map(|command| &command["argv"]).collect();
    assert_eq!(
        argvs,
        [
            &json!(["mkdir", "-m", "0700", "/tmp/oneiron-client"]),
            &detached(
                "/tmp/oneiron-client/status-0",
                &[
                    "mkdir",
                    "-m",
                    "0700",
                    "/tmp/oneiron-batch",
                    "/tmp/oneiron-batch/workspace",
                ],
            ),
            &json!([
                "sudo",
                "-n",
                "install",
                "-o",
                "70000",
                "-g",
                "70000",
                "-m",
                "0600",
                "-T",
                "--",
                "/tmp/oneiron-client/upload-1",
                "/tmp/oneiron-batch/host-frames",
            ]),
            &detached(
                "/tmp/oneiron-client/status-2",
                &[
                    "/usr/local/bin/oneiron-guest",
                    "--batch",
                    "/tmp/oneiron-batch/host-frames",
                    GUEST_FRAMES,
                    "/tmp/oneiron-batch/workspace",
                ],
            ),
            &copied_out("/tmp/oneiron-client/download-3"),
        ]
    );
    for command in &commands {
        let seconds = command["timeoutSeconds"]
            .as_u64()
            .expect("a command time cap");
        assert!(
            (1..=60).contains(&seconds),
            "a waited command is bounded: {seconds}"
        );
    }
}

#[test]
fn a_refused_create_never_shows_the_key() {
    let fixture = Fixture::new(Script {
        refuse_create: true,
        ..Script::well()
    });
    let Err(error) = fixture.run(&mut Console::default()) else {
        panic!("a refused create ran");
    };
    let text = error.to_string();
    assert!(text.contains("instabox answered 401"), "{text}");
    assert!(!text.contains(KEY_VALUE), "the key is scrubbed: {text}");
    assert_eq!(fixture.calls(), ["POST /machines"]);
}

#[test]
fn a_machine_that_fails_to_start_is_deleted_unused() {
    let fixture = Fixture::new(Script {
        fail_start: true,
        ..Script::well()
    });
    let Err(error) = fixture.run(&mut Console::default()) else {
        panic!("a machine that failed to start ran");
    };
    let text = error.to_string();
    assert!(
        text.contains("the InstaBox machine did not start: no_capacity: no host had room"),
        "{text}"
    );
    let operation = format!("GET /operations/{OPERATION}");
    assert_eq!(
        fixture.calls(),
        [
            "POST /machines".to_owned(),
            operation.clone(),
            operation,
            format!("DELETE /machines/{MACHINE}"),
        ]
    );
}

#[test]
fn a_confinement_that_cannot_be_made_runs_nothing() {
    let fixture = Fixture::new(Script {
        refuse_confinement: true,
        ..Script::well()
    });
    let Err(error) = fixture.run(&mut Console::default()) else {
        panic!("an unconfined machine ran");
    };
    let text = error.to_string();
    assert!(
        text.contains("could not make its batch directory (exit 1)"),
        "{text}"
    );
    let machine = format!("/machines/{MACHINE}");
    let operation = format!("GET /operations/{OPERATION}");
    let status = format!("GET {machine}/files/content /tmp/oneiron-client/status-0");
    assert_eq!(
        fixture.calls(),
        [
            "POST /machines".to_owned(),
            operation.clone(),
            operation,
            format!("POST {machine}/exec"),
            format!("POST {machine}/exec"),
            status.clone(),
            status,
            format!("DELETE {machine}"),
        ]
    );
}

#[test]
fn a_machine_that_stops_mid_run_is_deleted() {
    let fixture = Fixture::new(Script {
        stop_at_guest: true,
        ..Script::well()
    });
    let Err(error) = fixture.run(&mut Console::default()) else {
        panic!("a stopped machine ran");
    };
    let text = error.to_string();
    assert!(text.contains("instabox answered 409"), "{text}");
    assert!(!text.contains(KEY_VALUE), "the key is scrubbed: {text}");
    let calls = fixture.calls();
    assert!(
        !calls
            .iter()
            .any(|call| call.contains("/tmp/oneiron-client/download-")),
        "nothing is downloaded: {calls:?}"
    );
    assert_eq!(
        calls.last().map(String::as_str),
        Some(format!("DELETE /machines/{MACHINE}").as_str())
    );
}
