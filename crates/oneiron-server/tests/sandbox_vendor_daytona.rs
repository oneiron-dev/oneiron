//! A vault switched to Daytona runs its finite Foreign guests on Daytona's
//! sandboxes, on the owner's key in custody (L8-43). A loopback stand-in
//! answers Daytona's control API and toolbox proxy, records each call, and
//! serves the guest transcript the test gives it.
//!
//! The run makes one sandbox from the snapshot of the pinned guest image,
//! with no network, sends every call with the owner's key and nowhere else,
//! and deletes the sandbox at the end. A switch with no key is refused as the
//! vendor unavailable; a refused or failed start never shows the key and
//! leaves no sandbox behind.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server --all-features
//! --features oneiron/test-support --test sandbox_vendor_daytona`.
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
use fixture::{Console, GUEST_IMAGE_NAME, VendorVault, contains, guest_frames, start_stand_in};
use oneiron::code_sandbox::microvm::{MicroVmExit, MicroVmSandboxAdapter, SandboxBackends};
use oneiron::code_sandbox::{
    SandboxProposalKind, SandboxProposalWrite, SandboxProvider, SandboxVendor,
};
use oneiron::{ErrorKind, Result};
use oneiron_server::test_doors::sandbox_vendor::served_backends;
use serde_json::{Value, json};

const KEY_NAME: &str = "daytona.api_key";
const KEY_VALUE: &str = "dtn-test-key-5f1c0a";

/// How the stand-in answers.
struct Script {
    /// The state every poll of the sandbox answers.
    start_state: &'static str,
    /// Whether the create call is refused, with the key echoed in its body.
    refuse_create: bool,
    /// The guest frames the download answers.
    transcript: Vec<u8>,
}

/// One call the stand-in saw.
struct Call {
    method: String,
    path: String,
    query: String,
    /// The call carried `Authorization: Bearer <the owner's key>`.
    keyed: bool,
    body: Vec<u8>,
}

#[derive(Clone)]
struct StandIn {
    script: Arc<Script>,
    calls: Arc<Mutex<Vec<Call>>>,
}

async fn answer(
    State(stand_in): State<StandIn>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let path = uri.path().to_owned();
    let keyed = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        == Some(format!("Bearer {KEY_VALUE}").as_str());
    let execs = {
        let mut calls = stand_in.calls.lock().unwrap();
        calls.push(Call {
            method: method.to_string(),
            path: path.clone(),
            query: uri.query().unwrap_or_default().to_owned(),
            keyed,
            body: body.to_vec(),
        });
        calls
            .iter()
            .filter(|call| call.path.ends_with("/exec"))
            .count()
    };
    let script = &stand_in.script;
    match (method.as_str(), path.as_str()) {
        ("POST", "/sandbox") if script.refuse_create => (
            StatusCode::UNAUTHORIZED,
            format!("{{\"message\":\"invalid key {KEY_VALUE}\"}}"),
        )
            .into_response(),
        ("POST", "/sandbox") => {
            axum::Json(json!({ "id": "sb-1", "state": "creating" })).into_response()
        }
        ("GET", "/sandbox/sb-1") => axum::Json(json!({
            "id": "sb-1",
            "state": script.start_state,
            "errorReason": "no capacity",
        }))
        .into_response(),
        ("DELETE", "/sandbox/sb-1") => {
            axum::Json(json!({ "id": "sb-1", "state": "destroying" })).into_response()
        }
        ("POST", "/toolbox/sb-1/process/session") => {
            (StatusCode::CREATED, axum::Json(json!({}))).into_response()
        }
        ("POST", "/toolbox/sb-1/process/session/oneiron-batch/exec") => (
            StatusCode::ACCEPTED,
            axum::Json(json!({ "cmdId": format!("cmd-{execs}") })),
        )
            .into_response(),
        ("GET", command)
            if command.starts_with("/toolbox/sb-1/process/session/oneiron-batch/command/") =>
        {
            axum::Json(json!({ "exitCode": 0 })).into_response()
        }
        ("POST", "/toolbox/sb-1/files/upload") => StatusCode::OK.into_response(),
        ("GET", "/toolbox/sb-1/files/download") => script.transcript.clone().into_response(),
        _ => StatusCode::NOT_FOUND.into_response(),
    }
}

struct Fixture {
    vault: VendorVault,
    calls: Arc<Mutex<Vec<Call>>>,
    backends: Arc<dyn SandboxBackends>,
}

impl Fixture {
    /// A vault whose owner stored a Daytona key in custody, bound to
    /// `sandbox:daytona`, and a stand-in that answers as `script` says.
    fn new(script: Script) -> Self {
        let vault = VendorVault::new(SandboxVendor::Daytona, KEY_NAME, KEY_VALUE);
        let calls = Arc::new(Mutex::new(Vec::new()));
        let base = start_stand_in(Router::new().fallback(answer).with_state(StandIn {
            script: Arc::new(script),
            calls: Arc::clone(&calls),
        }));
        let backends = served_backends(
            &vault.vault,
            &base,
            &format!("{base}/toolbox"),
            vault.dir.path().join("vm"),
        );
        Self {
            vault,
            calls,
            backends,
        }
    }

    fn switch(&self, provider: SandboxProvider, vendor_key: Option<&str>) -> Result<()> {
        self.vault.switch(provider, vendor_key)
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
fn a_switched_run_goes_to_daytona_on_the_owners_key() {
    let fixture = Fixture::new(Script {
        start_state: "started",
        refuse_create: false,
        transcript: guest_frames(),
    });
    fixture
        .switch(
            SandboxProvider::Vendor(SandboxVendor::Daytona),
            Some(KEY_NAME),
        )
        .expect("the owner switches to Daytona with a key");
    let mut console = Console::default();
    let (mut adapter, exit) = fixture.run(&mut console).expect("the Daytona run");
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
    assert_eq!(manifest.backend, "vendor:daytona");
    assert!(manifest.fence_unproven);

    assert_eq!(
        fixture.calls(),
        [
            "POST /sandbox",
            "GET /sandbox/sb-1",
            "POST /toolbox/sb-1/process/session",
            "POST /toolbox/sb-1/process/session/oneiron-batch/exec",
            "GET /toolbox/sb-1/process/session/oneiron-batch/command/cmd-1",
            "POST /toolbox/sb-1/files/upload",
            "POST /toolbox/sb-1/process/session/oneiron-batch/exec",
            "GET /toolbox/sb-1/process/session/oneiron-batch/command/cmd-2",
            "GET /toolbox/sb-1/files/download",
            "DELETE /sandbox/sb-1",
        ]
    );
    let calls = fixture.calls.lock().unwrap();
    assert!(
        calls.iter().all(|call| call.keyed),
        "every call carries the owner's key"
    );
    let created: Value = serde_json::from_slice(&calls[0].body).expect("create body");
    assert_eq!(created["snapshot"], GUEST_IMAGE_NAME);
    assert_eq!(created["networkBlockAll"], true);
    assert_eq!(created["autoDeleteInterval"], 0);
    let commands: Vec<Value> = calls
        .iter()
        .filter(|call| call.path.ends_with("/exec"))
        .map(|call| serde_json::from_slice(&call.body).expect("exec body"))
        .collect();
    assert_eq!(
        commands,
        [
            json!({
                "command": "mkdir -m 0700 /tmp/oneiron-batch /tmp/oneiron-batch/workspace",
                "runAsync": true,
            }),
            json!({
                "command": "/usr/local/bin/oneiron-guest --batch /tmp/oneiron-batch/host-frames /tmp/oneiron-batch/guest-frames /tmp/oneiron-batch/workspace",
                "runAsync": true,
            }),
        ]
    );
    let upload = &calls[5];
    assert_eq!(upload.query, "path=%2Ftmp%2Foneiron-batch%2Fhost-frames");
    assert!(
        contains(&upload.body, b"name=\"file\""),
        "one part named file"
    );
    assert!(
        contains(&upload.body, b"\"type\":\"start\""),
        "the upload is the host's opening"
    );
    assert!(!contains(&upload.body, KEY_VALUE.as_bytes()));
    assert_eq!(calls[8].query, "path=%2Ftmp%2Foneiron-batch%2Fguest-frames");
}

#[test]
fn a_switch_without_a_key_refuses_the_vendor() {
    let fixture = Fixture::new(Script {
        start_state: "started",
        refuse_create: false,
        transcript: guest_frames(),
    });
    fixture
        .switch(SandboxProvider::Vendor(SandboxVendor::Daytona), None)
        .expect("a switch with no key is stored");
    let Err(error) = fixture.run(&mut Console::default()) else {
        panic!("a vendor with no key ran");
    };
    assert_eq!(error.kind(), ErrorKind::SandboxVendorUnavailable, "{error}");
    assert!(fixture.calls().is_empty(), "nothing reached Daytona");

    let error = fixture
        .switch(SandboxProvider::Ours, Some(KEY_NAME))
        .expect_err("a vendor key beside our own provider");
    assert_eq!(error.kind(), ErrorKind::InvalidConfig, "{error}");
    assert_eq!(
        fixture
            .vault
            .vault
            .sandbox_provider_setting()
            .expect("the switch")
            .vendor_key,
        None,
        "the refused switch stored nothing"
    );
}

#[test]
fn a_refused_create_never_shows_the_key() {
    let fixture = Fixture::new(Script {
        start_state: "started",
        refuse_create: true,
        transcript: guest_frames(),
    });
    fixture
        .switch(
            SandboxProvider::Vendor(SandboxVendor::Daytona),
            Some(KEY_NAME),
        )
        .expect("the switch");
    let Err(error) = fixture.run(&mut Console::default()) else {
        panic!("a refused create ran");
    };
    let text = error.to_string();
    assert!(text.contains("daytona answered 401"), "{text}");
    assert!(!text.contains(KEY_VALUE), "the key is scrubbed: {text}");
    assert_eq!(fixture.calls(), ["POST /sandbox"]);
}

#[test]
fn a_failed_start_deletes_its_sandbox() {
    let fixture = Fixture::new(Script {
        start_state: "error",
        refuse_create: false,
        transcript: guest_frames(),
    });
    fixture
        .switch(
            SandboxProvider::Vendor(SandboxVendor::Daytona),
            Some(KEY_NAME),
        )
        .expect("the switch");
    let Err(error) = fixture.run(&mut Console::default()) else {
        panic!("a failed start ran");
    };
    let text = error.to_string();
    assert!(text.contains("ended in error: no capacity"), "{text}");
    assert_eq!(
        fixture.calls(),
        ["POST /sandbox", "GET /sandbox/sb-1", "DELETE /sandbox/sb-1"]
    );
}
