//! A vault switched to boat runs its finite Foreign guests on boat VMs, on
//! the owner's key in custody (L8-43). A loopback stand-in answers boat's v1
//! API and the signed file URLs a VM serves, records each call, answers each
//! detached command as running at its first poll and ended at its second,
//! and serves the guest transcript the test gives it.
//!
//! The run makes one VM from the owner's saved snapshot of the pinned guest
//! image, with none of the account's secrets, no disk snapshot and a
//! lifetime of the step's own time; it starts every command in a network
//! namespace of its own, as the VM's user with no supplementary group and
//! no new privilege; it sends the owner's key only to the API and moves
//! each file through a signed URL with no key of ours; and it deletes the
//! VM at the end, confirming its id. A refused
//! create, a VM that fails to start, a lost command and a signed URL off the
//! API's scheme never show a secret and leave no VM behind.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server --all-features
//! --features oneiron/test-support --test sandbox_vendor_boat`.
#![cfg(all(oneiron_test_support, target_os = "linux"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "sandbox_vendor/fixture.rs"]
mod fixture;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::extract::State;
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
use oneiron_server::test_doors::sandbox_vendor::served_boat_backends;
use serde_json::{Value, json};

const KEY_NAME: &str = "boat.api_key";
const KEY_VALUE: &str = "boat_test_key_5e8b27";
/// The VM the stand-in makes.
const VM: &str = "bx_k7m2p9qr";
/// The secret part of each signed file URL the stand-in answers.
const UPLOAD_TOKEN: &str = "upload-7f3a9c";
const DOWNLOAD_TOKEN: &str = "download-2c9e41";
/// What every command starts under.
const CONFINED_PREFIX: &str = "sudo -n unshare --net -- \
    setpriv --reuid=user --regid=user --clear-groups --no-new-privs --";

/// How the stand-in answers.
struct Script {
    /// Whether the create call is refused, with the key echoed in its body.
    refuse_create: bool,
    /// The VM's state at its first poll, and the reason it names.
    started_state: &'static str,
    started_error: Option<&'static str>,
    /// Whether the guest's command (the second) is lost at its second poll.
    lose_guest: bool,
    /// Whether the upload URL is on another scheme than the API's.
    foreign_upload_url: bool,
    /// The guest frames the signed download answers.
    transcript: Vec<u8>,
}

impl Script {
    fn well() -> Self {
        Self {
            refuse_create: false,
            started_state: "ready",
            started_error: None,
            lose_guest: false,
            foreign_upload_url: false,
            transcript: guest_frames(),
        }
    }
}

/// One call the stand-in saw.
struct Call {
    method: String,
    path: String,
    query: String,
    authorization: Option<String>,
    /// The `X-Ascii-Confirm-Delete` header, if any.
    confirm_delete: Option<String>,
    content_type: Option<String>,
    body: Vec<u8>,
}

#[derive(Clone)]
struct StandIn {
    script: Arc<Script>,
    calls: Arc<Mutex<Vec<Call>>>,
    /// The processes started so far.
    started: Arc<Mutex<u64>>,
    /// The status polls of each process so far.
    polls: Arc<Mutex<HashMap<u64, u32>>>,
}

fn header(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

/// The status of `process` at its `poll`-th poll.
fn command_status(script: &Script, process: u64, poll: u32) -> Value {
    if poll == 1 {
        return json!({
            "ok": true, "type": "command.status", "success": true, "processId": process,
            "status": "running", "running": true, "exitCode": null, "stdout": "", "stderr": "",
        });
    }
    if script.lose_guest && process == 2 {
        return json!({
            "ok": true, "type": "command.status", "success": false, "processId": process,
            "status": "lost", "running": false, "exitCode": null, "stdout": "", "stderr": "",
        });
    }
    json!({
        "ok": true, "type": "command.status", "success": true, "processId": process,
        "status": "exited", "running": false, "exitCode": 0, "signal": null,
        "stdout": "", "stderr": "",
    })
}

/// A signed file URL's answer.
fn signed(kind: &str, url: String, path: &str) -> Response {
    Json(json!({
        "ok": true, "type": format!("file.{kind}"), "url": url,
        "method": if kind == "upload_url" { "PUT" } else { "GET" },
        "path": path, "expiresAt": "2026-11-15T07:00:00Z",
    }))
    .into_response()
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
        authorization: header(&headers, "authorization"),
        confirm_delete: header(&headers, "x-ascii-confirm-delete"),
        content_type: header(&headers, "content-type"),
        body: body.to_vec(),
    });
    let script = &stand_in.script;
    let host = header(&headers, "host").expect("a host header");
    let vm = format!("/sandboxes/{VM}");
    let commands = format!("{vm}/commands");
    let process = path
        .strip_prefix(&format!("{commands}/"))
        .and_then(|process| process.parse::<u64>().ok());
    match (method.as_str(), path.as_str(), process) {
        ("POST", "/sandboxes", _) if script.refuse_create => (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "ok": false, "type": "sandbox.error", "status": 401, "code": "unauthorized",
                "message": format!("invalid key {KEY_VALUE}"), "requestId": "req_1",
            })),
        )
            .into_response(),
        ("POST", "/sandboxes", _) => (
            StatusCode::ACCEPTED,
            Json(json!({
                "ok": true, "type": "sandbox.created", "status": "provisioning",
                "sandbox": {
                    "id": VM, "name": "oneiron", "state": "provisioning",
                    "desktopAvailable": false, "snapshotAvailable": false,
                },
            })),
        )
            .into_response(),
        ("GET", path, None) if path == vm => Json(json!({
            "ok": true, "type": "sandbox.info",
            "sandbox": {
                "id": VM, "state": script.started_state, "error": script.started_error,
                "desktopAvailable": false, "snapshotAvailable": false,
            },
        }))
        .into_response(),
        ("DELETE", path, None) if path == vm => (
            StatusCode::ACCEPTED,
            Json(json!({
                "ok": true, "type": "deletion.operation",
                "operation": { "id": "bdop_1", "kind": "sandbox", "targetId": VM, "status": "pending" },
            })),
        )
            .into_response(),
        ("POST", path, None) if path == commands => {
            let mut started = stand_in.started.lock().unwrap();
            *started += 1;
            Json(json!({
                "ok": true, "type": "command.started", "success": true,
                "commandId": format!("cmd_{started}"), "processId": *started, "pid": 4000 + *started,
            }))
            .into_response()
        }
        ("GET", _, Some(process)) => {
            let poll = {
                let mut polls = stand_in.polls.lock().unwrap();
                let poll = polls.entry(process).or_insert(0);
                *poll += 1;
                *poll
            };
            Json(command_status(script, process, poll)).into_response()
        }
        ("POST", path, None) if path == format!("{vm}/files/upload-url") => {
            let url = if script.foreign_upload_url {
                format!("https://elsewhere.example/signed/{UPLOAD_TOKEN}")
            } else {
                format!("http://{host}/signed/{UPLOAD_TOKEN}")
            };
            signed("upload_url", url, "/tmp/oneiron-batch/host-frames")
        }
        ("POST", path, None) if path == format!("{vm}/files/download-url") => signed(
            "download_url",
            format!("http://{host}/signed/{DOWNLOAD_TOKEN}"),
            "/tmp/oneiron-batch/guest-frames",
        ),
        ("PUT", path, None) if path == format!("/signed/{UPLOAD_TOKEN}") => {
            StatusCode::OK.into_response()
        }
        ("GET", path, None) if path == format!("/signed/{DOWNLOAD_TOKEN}") => {
            script.transcript.clone().into_response()
        }
        _ => StatusCode::NOT_FOUND.into_response(),
    }
}

struct Fixture {
    vault: VendorVault,
    calls: Arc<Mutex<Vec<Call>>>,
    backends: Arc<dyn SandboxBackends>,
}

impl Fixture {
    /// A vault whose owner stored a boat key in custody, bound to
    /// `sandbox:boat` and switched to it, and a stand-in that answers as
    /// `script` says.
    fn new(script: Script) -> Self {
        let vault = VendorVault::new(SandboxVendor::Boat, KEY_NAME, KEY_VALUE);
        let calls = Arc::new(Mutex::new(Vec::new()));
        let base = start_stand_in(Router::new().fallback(answer).with_state(StandIn {
            script: Arc::new(script),
            calls: Arc::clone(&calls),
            started: Arc::new(Mutex::new(0)),
            polls: Arc::new(Mutex::new(HashMap::new())),
        }));
        let backends = served_boat_backends(&vault.vault, &base, vault.dir.path().join("vm"));
        vault
            .switch(SandboxProvider::Vendor(SandboxVendor::Boat), Some(KEY_NAME))
            .expect("the owner switches to boat with a key");
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
fn a_switched_run_goes_to_boat_with_the_key_only_at_its_api() {
    let fixture = Fixture::new(Script::well());
    let mut console = Console::default();
    let (mut adapter, exit) = fixture.run(&mut console).expect("the boat run");
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
    assert_eq!(manifest.backend, "vendor:boat");
    assert!(manifest.fence_unproven);

    let vm = format!("/sandboxes/{VM}");
    assert_eq!(
        fixture.calls(),
        [
            "POST /sandboxes".to_owned(),
            format!("GET {vm}"),
            format!("POST {vm}/commands"),
            format!("GET {vm}/commands/1"),
            format!("GET {vm}/commands/1"),
            format!("POST {vm}/files/upload-url"),
            format!("PUT /signed/{UPLOAD_TOKEN}"),
            format!("POST {vm}/commands"),
            format!("GET {vm}/commands/2"),
            format!("GET {vm}/commands/2"),
            format!("POST {vm}/files/download-url"),
            format!("GET /signed/{DOWNLOAD_TOKEN}"),
            format!("DELETE {vm}"),
        ]
    );
    {
        let calls = fixture.calls.lock().unwrap();
        for call in calls.iter() {
            if call.path.starts_with("/signed/") {
                assert_eq!(call.authorization, None, "{}", call.path);
            } else {
                assert_eq!(
                    call.authorization.as_deref(),
                    Some(format!("Bearer {KEY_VALUE}").as_str()),
                    "{}",
                    call.path
                );
            }
            assert!(!contains(&call.body, KEY_VALUE.as_bytes()), "{}", call.path);
            if call.path.starts_with(&format!("{vm}/commands/")) {
                assert_eq!(call.query, "tailBytes=1", "one byte of each log");
            }
        }
        let upload = calls
            .iter()
            .find(|call| call.method == "PUT")
            .expect("the upload");
        assert_eq!(
            upload.content_type.as_deref(),
            Some("application/octet-stream"),
            "a raw body"
        );
        assert!(
            contains(&upload.body, b"\"type\":\"start\""),
            "the upload is the host's opening"
        );
        let delete = calls.last().expect("the delete");
        assert_eq!(
            delete.confirm_delete.as_deref(),
            Some(VM),
            "the delete names its VM"
        );
    }

    let created = &fixture.bodies("/sandboxes")[0];
    assert_eq!(created["from"], GUEST_IMAGE_NAME);
    assert_eq!(created["type"], "small");
    assert_eq!(created["noEnv"], true);
    assert_eq!(created["snapshots"], false);
    assert_eq!(created["visibility"], "private");
    assert_eq!(created["labels"]["oneiron"], "batch-run");
    let lifetime = created["ttlSeconds"]
        .as_u64()
        .expect("a lifetime in seconds");
    assert!(
        lifetime > 0 && lifetime <= STEP_SECONDS + 60,
        "the VM lives the step's time and a margin: {lifetime}"
    );

    assert_eq!(
        fixture.bodies(&format!("{vm}/commands")),
        [
            json!({
                "command": format!(
                    "{CONFINED_PREFIX} mkdir -m 0700 /tmp/oneiron-batch /tmp/oneiron-batch/workspace"
                ),
                "detached": true,
            }),
            json!({
                "command": format!(
                    "{CONFINED_PREFIX} /usr/local/bin/oneiron-guest --batch \
                     /tmp/oneiron-batch/host-frames /tmp/oneiron-batch/guest-frames \
                     /tmp/oneiron-batch/workspace"
                ),
                "detached": true,
            }),
        ]
    );
    for (kind, path) in [
        ("upload-url", "/tmp/oneiron-batch/host-frames"),
        ("download-url", "/tmp/oneiron-batch/guest-frames"),
    ] {
        let asked = &fixture.bodies(&format!("{vm}/files/{kind}"))[0];
        assert_eq!(asked["path"], path);
        let seconds = asked["ttlSeconds"].as_u64().expect("a URL lifetime");
        assert!(
            seconds > 0 && seconds <= STEP_SECONDS,
            "a signed URL lives the step's time left: {seconds}"
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
    assert!(text.contains("boat answered 401"), "{text}");
    assert!(!text.contains(KEY_VALUE), "the key is scrubbed: {text}");
    assert_eq!(fixture.calls(), ["POST /sandboxes"]);
}

#[test]
fn a_vm_that_fails_to_start_is_deleted_unused() {
    let fixture = Fixture::new(Script {
        started_state: "error",
        started_error: Some("no machine took it"),
        ..Script::well()
    });
    let Err(error) = fixture.run(&mut Console::default()) else {
        panic!("a VM that failed to start ran");
    };
    let text = error.to_string();
    assert!(
        text.contains("the boat VM ended in error: no machine took it"),
        "{text}"
    );
    let vm = format!("/sandboxes/{VM}");
    assert_eq!(
        fixture.calls(),
        [
            "POST /sandboxes".to_owned(),
            format!("GET {vm}"),
            format!("DELETE {vm}"),
        ]
    );
}

#[test]
fn a_lost_command_deletes_the_vm() {
    let fixture = Fixture::new(Script {
        lose_guest: true,
        ..Script::well()
    });
    let Err(error) = fixture.run(&mut Console::default()) else {
        panic!("a lost command ran");
    };
    let text = error.to_string();
    assert!(text.contains("boat lost the command"), "{text}");
    let calls = fixture.calls();
    assert!(
        !calls.iter().any(|call| call.contains("download")),
        "nothing is downloaded: {calls:?}"
    );
    assert_eq!(
        calls.last().map(String::as_str),
        Some(format!("DELETE /sandboxes/{VM}").as_str())
    );
}

#[test]
fn a_signed_url_off_the_api_scheme_gets_nothing() {
    let fixture = Fixture::new(Script {
        foreign_upload_url: true,
        ..Script::well()
    });
    let Err(error) = fixture.run(&mut Console::default()) else {
        panic!("a run with a signed URL off the API's scheme ran");
    };
    let text = error.to_string();
    assert!(text.contains("off its API's scheme"), "{text}");
    assert!(!text.contains(UPLOAD_TOKEN), "the URL is not shown: {text}");
    let vm = format!("/sandboxes/{VM}");
    assert_eq!(
        fixture.calls(),
        [
            "POST /sandboxes".to_owned(),
            format!("GET {vm}"),
            format!("POST {vm}/commands"),
            format!("GET {vm}/commands/1"),
            format!("GET {vm}/commands/1"),
            format!("POST {vm}/files/upload-url"),
            format!("DELETE {vm}"),
        ]
    );
}
