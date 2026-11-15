//! A run on a vendor's sandbox (L8-43, VENDOR-BOUNDARY = A: a batch
//! boundary). A scripted vendor client stands in for the vendor's API: it
//! records each call and answers the guest transcript the test gives it.
//! The host's exchange checks that transcript as it checks a container
//! guest's frames, so a proposal outside the workspace, a transcript that
//! diverges from the host's answers, and a failed vendor call each refuse
//! the run, and the vendor's sandbox is deleted on every path.
//!
//! `cargo test --locked -p oneiron-agent-runtime --all-features --test vendor_batch_backend`.
#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::io::{Cursor, Read, Write};
use std::sync::{Arc, Mutex};

use oneiron::code_sandbox::{
    SandboxCredentialHandle, SandboxGuestTier, SandboxMountTable, SandboxProposalKind,
    SandboxProposalWrite, SandboxVendor,
};
use oneiron::engine_executor::{JsCodeModeStream, StepCancellation};
use oneiron::{ErrorKind, Result};
use oneiron_agent_runtime::code_sandbox::microvm::{
    CredentialAllowlist, CredentialDestination, CredentialResolver, ExecutionBudget, GuestImage,
    MicroVmBackend, MicroVmExit, MicroVmOutputSink, MicroVmSandboxAdapter, VENDOR_BATCH_DIR,
    VENDOR_GUEST_BIN, VendorBatchBackend, VendorCallBound, VendorSandboxClient, VendorSandboxId,
    VendorSandboxSpec,
};
use serde_json::{Value, json};

const GUEST_IMAGE: &str =
    "ghcr.io/example/guest@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// A resolver no read reaches: a vendor run has no credential broker.
struct NoResolver;

impl CredentialResolver for NoResolver {
    fn resolve_for(
        &self,
        _handle: &SandboxCredentialHandle,
        _dest: &CredentialDestination,
    ) -> Result<Vec<u8>> {
        panic!("a vendor run resolves no credential")
    }
}

/// Every call the scripted vendor saw.
#[derive(Default)]
struct Calls {
    created: Vec<String>,
    executed: Vec<Vec<String>>,
    uploaded: Vec<(String, Vec<u8>)>,
    downloaded: Vec<String>,
    deleted: Vec<String>,
}

/// The vendor's API: one sandbox per run, the given guest frames as its
/// transcript, and a guest command that fails when asked to.
struct ScriptedVendor {
    transcript: Vec<u8>,
    fail_guest: bool,
    calls: Mutex<Calls>,
}

impl VendorSandboxClient for ScriptedVendor {
    fn vendor(&self) -> SandboxVendor {
        SandboxVendor::Daytona
    }

    fn create(
        &self,
        spec: &VendorSandboxSpec<'_>,
        bound: VendorCallBound<'_>,
    ) -> Result<VendorSandboxId> {
        bound.cancel.check()?;
        self.calls
            .lock()
            .unwrap()
            .created
            .push(spec.guest_image.to_owned());
        VendorSandboxId::new("sandbox-1")
    }

    fn upload(
        &self,
        sandbox: &VendorSandboxId,
        path: &str,
        body: &mut dyn Read,
        len: u64,
        _bound: VendorCallBound<'_>,
    ) -> Result<()> {
        assert_eq!(sandbox.as_str(), "sandbox-1");
        let mut bytes = Vec::new();
        body.read_to_end(&mut bytes)?;
        assert_eq!(bytes.len() as u64, len, "the upload is the whole opening");
        self.calls
            .lock()
            .unwrap()
            .uploaded
            .push((path.to_owned(), bytes));
        Ok(())
    }

    fn execute(
        &self,
        _sandbox: &VendorSandboxId,
        argv: &[&str],
        _bound: VendorCallBound<'_>,
    ) -> Result<i32> {
        self.calls
            .lock()
            .unwrap()
            .executed
            .push(argv.iter().map(|arg| (*arg).to_owned()).collect());
        if self.fail_guest && argv.first() == Some(&VENDOR_GUEST_BIN) {
            return Err(std::io::Error::other("vendor API refused the command").into());
        }
        Ok(0)
    }

    fn download(
        &self,
        _sandbox: &VendorSandboxId,
        path: &str,
        sink: &mut dyn Write,
        _bound: VendorCallBound<'_>,
    ) -> Result<()> {
        self.calls.lock().unwrap().downloaded.push(path.to_owned());
        sink.write_all(&self.transcript)?;
        Ok(())
    }

    fn delete(&self, sandbox: &VendorSandboxId) -> Result<()> {
        self.calls
            .lock()
            .unwrap()
            .deleted
            .push(sandbox.as_str().to_owned());
        Ok(())
    }
}

/// The console text the run streamed.
#[derive(Default)]
struct Console(Vec<String>);

impl MicroVmOutputSink for Console {
    fn write_output_frame(&mut self, stream: JsCodeModeStream<'_>, frame: Vec<u8>) -> Result<()> {
        assert!(matches!(stream, JsCodeModeStream::Console), "console only");
        self.0.push(String::from_utf8(frame).expect("console text"));
        Ok(())
    }
}

fn transcript(frames: &[Value]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for frame in frames {
        let body = serde_json::to_vec(frame).expect("encode guest frame");
        bytes.extend_from_slice(&u32::try_from(body.len()).unwrap().to_be_bytes());
        bytes.extend_from_slice(&body);
    }
    bytes
}

fn frames(bytes: &[u8]) -> Vec<Value> {
    let mut cursor = Cursor::new(bytes);
    let mut out = Vec::new();
    while cursor.position() < bytes.len() as u64 {
        let mut header = [0; 4];
        cursor.read_exact(&mut header).expect("frame header");
        let mut body = vec![0; u32::from_be_bytes(header) as usize];
        cursor.read_exact(&mut body).expect("frame bytes");
        out.push(serde_json::from_slice(&body).expect("frame JSON"));
    }
    out
}

fn hello() -> Value {
    json!({ "type": "hello", "version": oneiron_sandbox_contract::GUEST_PROTOCOL_VERSION })
}

struct Fixture {
    _dir: tempfile::TempDir,
    vendor: Arc<ScriptedVendor>,
    adapter: MicroVmSandboxAdapter,
    image: GuestImage,
}

impl Fixture {
    fn new(guest_frames: &[Value], fail_guest: bool) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let base = dir.path().join("base");
        for mount in ["workspace", "uploads", "outputs", "skills"] {
            fs::create_dir_all(base.join(mount)).expect("mount root");
        }
        fs::write(base.join("workspace/notes.txt"), b"base notes\n").expect("stage base file");
        let component = dir.path().join("component.wasm");
        fs::write(&component, b"\0asm\x0d\0\x01\0scripted").expect("component");
        let image = GuestImage::new("", "", component)
            .with_oci(GUEST_IMAGE)
            .expect("pinned guest image")
            .with_source("export default 1;");
        let vendor = Arc::new(ScriptedVendor {
            transcript: transcript(guest_frames),
            fail_guest,
            calls: Mutex::new(Calls::default()),
        });
        let client: Arc<dyn VendorSandboxClient> = Arc::<ScriptedVendor>::clone(&vendor);
        let backend: Box<dyn MicroVmBackend> =
            Box::new(VendorBatchBackend::new(client, dir.path().join("vm")));
        let adapter = MicroVmSandboxAdapter::new(
            SandboxGuestTier::Foreign,
            SandboxMountTable::new(
                base.join("workspace"),
                base.join("uploads"),
                base.join("outputs"),
                base.join("skills"),
            ),
            backend,
            Arc::new(NoResolver),
            CredentialAllowlist::new(),
        )
        .expect("adapter");
        Self {
            _dir: dir,
            vendor,
            adapter,
            image,
        }
    }

    fn run(&mut self, cancel: &StepCancellation, console: &mut Console) -> Result<MicroVmExit> {
        self.adapter.run_cancellable(
            &self.image,
            ExecutionBudget::new(30, 512, 64),
            cancel,
            console,
        )
    }

    fn deleted(&self) -> Vec<String> {
        self.vendor.calls.lock().unwrap().deleted.clone()
    }
}

#[test]
fn a_vendor_run_replays_its_transcript_through_the_host_checks() {
    let mut fixture = Fixture::new(
        &[
            hello(),
            json!({ "type": "write_open", "path": "/mnt/workspace/new.txt" }),
            json!({ "type": "write_chunk", "bytes": b"hi\n".to_vec() }),
            json!({ "type": "write_close" }),
            json!({ "type": "output_text", "target": "console", "start": true, "frame": "logged" }),
            json!({ "type": "step_result", "result_json": "{\"ok\":true}" }),
            json!({ "type": "finish", "status": 0 }),
        ],
        false,
    );
    let mut console = Console::default();
    let exit = fixture
        .run(&StepCancellation::new(), &mut console)
        .expect("the vendor run");
    assert_eq!(exit.status, 0);
    assert_eq!(exit.result_json.as_deref(), Some("{\"ok\":true}"));
    assert_eq!(exit.guest_error, None);
    assert_eq!(console.0, ["logged"], "the console frame reached the sink");

    let proposals = fixture
        .adapter
        .collect_overlay_proposals()
        .expect("proposals");
    assert_eq!(proposals.len(), 1);
    assert_eq!(proposals[0].kind(), SandboxProposalKind::FileEdit);
    let SandboxProposalWrite::FileEdit(edit) = proposals[0].write() else {
        panic!("a file edit");
    };
    assert_eq!(edit.path.as_str(), "/mnt/workspace/new.txt");

    let manifest = fixture.adapter.session_manifest().expect("manifest");
    assert_eq!(manifest.backend, "vendor:daytona");
    assert_eq!(manifest.runtime, "daytona");
    assert_eq!(manifest.image, GUEST_IMAGE);
    assert!(manifest.fence_unproven, "a vendor's isolation is unproven");
    assert!(manifest.fence_proof.is_none());

    let calls = fixture.vendor.calls.lock().unwrap();
    assert_eq!(calls.created, [GUEST_IMAGE]);
    let batch = VENDOR_BATCH_DIR;
    assert_eq!(
        calls.executed,
        [
            vec![
                "mkdir".to_owned(),
                "-m".into(),
                "0700".into(),
                batch.into(),
                format!("{batch}/workspace"),
            ],
            vec![
                VENDOR_GUEST_BIN.to_owned(),
                "--batch".into(),
                format!("{batch}/host-frames"),
                format!("{batch}/guest-frames"),
                format!("{batch}/workspace"),
            ],
        ]
    );
    assert_eq!(calls.downloaded, [format!("{batch}/guest-frames")]);
    assert_eq!(calls.deleted, ["sandbox-1"]);

    let [(path, opening)] = calls.uploaded.as_slice() else {
        panic!("one upload");
    };
    assert_eq!(path, &format!("{batch}/host-frames"));
    let opening = frames(opening);
    let kinds: Vec<&str> = opening
        .iter()
        .map(|frame| frame["type"].as_str().unwrap())
        .collect();
    assert_eq!(
        kinds,
        [
            "start",
            "component",
            "file_open",
            "file_chunk",
            "file_close",
            "ready"
        ],
        "the opening is the host's frames up to its ready, with no hello"
    );
    assert_eq!(opening[0]["tier"], "foreign");
    assert_eq!(opening[0]["source"], "export default 1;");
    assert_eq!(opening[2]["path"], "/mnt/workspace/notes.txt");
}

#[test]
fn a_vendor_proposal_outside_the_workspace_refuses_the_run() {
    let mut fixture = Fixture::new(
        &[
            hello(),
            json!({ "type": "write_open", "path": "/mnt/uploads/planted.txt" }),
            json!({ "type": "write_chunk", "bytes": b"x".to_vec() }),
            json!({ "type": "write_close" }),
            json!({ "type": "step_result", "result_json": "{}" }),
            json!({ "type": "finish", "status": 0 }),
        ],
        false,
    );
    let error = fixture
        .run(&StepCancellation::new(), &mut Console::default())
        .expect_err("a proposal outside the workspace");
    assert!(
        error.to_string().contains("guest proposal path"),
        "the host's own check refused it: {error}"
    );
    assert!(fixture.adapter.collect_overlay_proposals().is_err());
    assert_eq!(fixture.deleted(), ["sandbox-1"]);
}

#[test]
fn a_vendor_transcript_that_diverges_refuses_the_run() {
    for (guest_frames, refusal) in [
        (
            vec![
                json!({ "type": "hello", "version": 2 }),
                json!({ "type": "step_result", "result_json": "{}" }),
                json!({ "type": "finish", "status": 0 }),
            ],
            "guest protocol version",
        ),
        (
            vec![
                hello(),
                json!({ "type": "step_result", "result_json": "{}" }),
            ],
            "ends before its finish",
        ),
        (
            vec![
                hello(),
                json!({ "type": "step_result", "result_json": "{}" }),
                json!({ "type": "finish", "status": 0 }),
                json!({ "type": "output_text", "target": "console", "start": true, "frame": "late" }),
            ],
            "frames after its finish",
        ),
    ] {
        let mut fixture = Fixture::new(&guest_frames, false);
        let error = fixture
            .run(&StepCancellation::new(), &mut Console::default())
            .expect_err(refusal);
        assert!(error.to_string().contains(refusal), "{refusal}: {error}");
        assert!(fixture.adapter.collect_overlay_proposals().is_err());
        assert_eq!(fixture.deleted(), ["sandbox-1"], "{refusal}");
    }
}

#[test]
fn a_vendor_credential_read_is_refused_on_both_sides() {
    let mut fixture = Fixture::new(
        &[
            hello(),
            json!({
                "type": "credential_read",
                "handle": "github",
                "operation": "repos.get",
                "scheme": "https",
                "host": "api.github.com",
            }),
            json!({ "type": "step_result", "result_json": "{\"read\":false}" }),
            json!({ "type": "finish", "status": 0 }),
        ],
        false,
    );
    let exit = fixture
        .run(&StepCancellation::new(), &mut Console::default())
        .expect("the host refused the read as the guest's channel did");
    assert_eq!(exit.status, 0);
    assert_eq!(exit.result_json.as_deref(), Some("{\"read\":false}"));
    assert!(
        fixture.adapter.credential_injections().is_empty(),
        "no credential was injected"
    );
}

#[test]
fn a_failed_vendor_program_keeps_its_error() {
    let mut fixture = Fixture::new(
        &[
            hello(),
            json!({ "type": "write_open", "path": "/mnt/workspace/dropped.txt" }),
            json!({ "type": "step_error", "message": "Error: boom" }),
            json!({ "type": "finish", "status": 1 }),
        ],
        false,
    );
    let exit = fixture
        .run(&StepCancellation::new(), &mut Console::default())
        .expect("a failed program is a run");
    assert_eq!(exit.status, 1);
    assert_eq!(exit.guest_error.as_deref(), Some("Error: boom"));
    assert!(
        fixture.adapter.collect_overlay_proposals().is_err(),
        "a failed program proposes nothing"
    );
    assert_eq!(fixture.deleted(), ["sandbox-1"]);
}

#[test]
fn a_failed_vendor_call_still_deletes_its_sandbox() {
    let mut fixture = Fixture::new(&[hello()], true);
    let error = fixture
        .run(&StepCancellation::new(), &mut Console::default())
        .expect_err("the vendor refused the guest command");
    assert!(
        error.to_string().contains("vendor API refused the command"),
        "the vendor's own error: {error}"
    );
    assert_eq!(fixture.deleted(), ["sandbox-1"]);
    assert!(fixture.vendor.calls.lock().unwrap().downloaded.is_empty());
}

#[test]
fn a_cancelled_step_makes_no_vendor_sandbox() {
    let mut fixture = Fixture::new(&[hello()], false);
    let cancel = StepCancellation::new();
    cancel.cancel();
    let error = fixture
        .run(&cancel, &mut Console::default())
        .expect_err("a cancelled step");
    assert_eq!(error.kind(), ErrorKind::CodeStepCancelled, "{error}");
    let calls = fixture.vendor.calls.lock().unwrap();
    assert!(calls.created.is_empty(), "no sandbox was made");
    assert!(calls.deleted.is_empty());
}
