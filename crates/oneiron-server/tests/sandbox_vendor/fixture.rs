//! What the vendor sandbox tests share (L8-43): a vault whose owner stored
//! a vendor key in custody, the owner's switch, one Foreign run of a
//! scripted guest on the backend the switch selects, the guest transcript
//! that run replays, and a loopback stand-in for the vendor's API.
#![allow(dead_code)]

use std::fs;
use std::sync::Arc;

use axum::Router;
use oneiron::code_sandbox::microvm::{
    CredentialAllowlist, CredentialDestination, CredentialResolver, ExecutionBudget, GuestImage,
    MicroVmExit, MicroVmOutputSink, MicroVmSandboxAdapter, SandboxBackends,
    select_backend_for_tier,
};
use oneiron::code_sandbox::{
    SandboxCredentialHandle, SandboxGuestTier, SandboxMountTable, SandboxProvider, SandboxVendor,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::engine_executor::{JsCodeModeStream, StepCancellation};
use oneiron::secret_custody::{
    CustodyClass, CustodyTier, OwnerSecretRegistration, RequestedBinding,
};
use oneiron::settings::sandbox_provider::SandboxProviderSetting;
use oneiron::store::GateDecisionId;
use oneiron::{Result, Vault, VaultConfig};
use serde_json::{Value, json};

pub(crate) const GUEST_IMAGE: &str =
    "ghcr.io/example/guest@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
/// The vendor's name for its copy of [`GUEST_IMAGE`].
pub(crate) const GUEST_IMAGE_NAME: &str = "oneiron-guest-0123456789ab";
const STORED_AT: u64 = 1_800_000_000;
/// `oneiron_sandbox_contract::GUEST_PROTOCOL_VERSION`; the server does not
/// depend on that crate.
const GUEST_PROTOCOL_VERSION: u32 = 3;
/// The step's wall clock, in seconds.
pub(crate) const STEP_SECONDS: u64 = 30;

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

/// The console text the run streamed.
#[derive(Default)]
pub(crate) struct Console(pub(crate) Vec<String>);

impl MicroVmOutputSink for Console {
    fn write_output_frame(&mut self, stream: JsCodeModeStream<'_>, frame: Vec<u8>) -> Result<()> {
        assert!(matches!(stream, JsCodeModeStream::Console), "console only");
        self.0.push(String::from_utf8(frame).expect("console text"));
        Ok(())
    }
}

/// `frames` as the guest writes them: each one's length, then its JSON.
pub(crate) fn transcript(frames: &[Value]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for frame in frames {
        let body = serde_json::to_vec(frame).expect("encode guest frame");
        bytes.extend_from_slice(&u32::try_from(body.len()).unwrap().to_be_bytes());
        bytes.extend_from_slice(&body);
    }
    bytes
}

fn hello() -> Value {
    json!({ "type": "hello", "version": GUEST_PROTOCOL_VERSION })
}

/// A guest that writes one new file, logs one line and ends well.
pub(crate) fn guest_frames() -> Vec<u8> {
    transcript(&[
        hello(),
        json!({ "type": "write_open", "path": "/mnt/workspace/new.txt" }),
        json!({ "type": "write_chunk", "bytes": b"hi\n".to_vec() }),
        json!({ "type": "write_close" }),
        json!({ "type": "output_text", "target": "console", "start": true, "frame": "logged" }),
        json!({ "type": "step_result", "result_json": "{\"ok\":true}" }),
        json!({ "type": "finish", "status": 0 }),
    ])
}

pub(crate) fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// Serves `app` on a loopback port, on its own runtime thread, and answers
/// its base URL.
pub(crate) fn start_stand_in(app: Router) -> String {
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
            axum::serve(listener, app)
                .await
                .expect("serve the stand-in");
        });
    });
    format!("http://{}", address.recv().expect("the stand-in bound"))
}

/// A vault whose owner stored a key for one vendor in custody, bound to the
/// vendor's effector.
pub(crate) struct VendorVault {
    pub(crate) dir: tempfile::TempDir,
    pub(crate) vault: Arc<Vault>,
    owner: AuthenticatedOwner,
}

impl VendorVault {
    pub(crate) fn new(vendor: SandboxVendor, key_name: &str, key_value: &str) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = dir.path().join("vault");
        fs::create_dir(&vault_dir).expect("vault dir");
        let vault = Vault::open(&vault_dir, VaultConfig::device()).expect("vault");
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
        vault.prepare_install_signing().expect("install signing");
        let actor = vault.ensure_embedded_owner_actor().expect("owner actor");
        let owner = vault
            .authenticate_owner(actor, &actor.to_hex(), true, GateDecisionId::now())
            .expect("owner");
        vault
            .register_secret_as_owner(
                &owner,
                &OwnerSecretRegistration {
                    name: key_name,
                    class: CustodyClass::CustodyDeviceBound,
                    device_only: true,
                    rung: CustodyTier::T0Doored,
                    bindings: vec![RequestedBinding {
                        effector: vendor.effector().to_owned(),
                        tier_ceiling: None,
                        scopes: vec!["read".to_owned()],
                    }],
                    manifest: None,
                    value: key_value.as_bytes(),
                },
                STORED_AT,
            )
            .expect("the owner's vendor key in custody");
        Self {
            dir,
            vault: Arc::new(vault),
            owner,
        }
    }

    pub(crate) fn switch(&self, provider: SandboxProvider, vendor_key: Option<&str>) -> Result<()> {
        self.vault
            .replace_sandbox_provider_setting_as_owner(
                &self.owner,
                SandboxProviderSetting {
                    provider,
                    vendor_key: vendor_key.map(str::to_owned),
                },
            )
            .map(drop)
    }

    /// One Foreign run of a scripted guest on the backend of `backends` the
    /// switch selects.
    pub(crate) fn run(
        &self,
        backends: &dyn SandboxBackends,
        console: &mut Console,
    ) -> Result<(MicroVmSandboxAdapter, MicroVmExit)> {
        self.run_cancellable(backends, console, &StepCancellation::new())
    }

    /// [`Self::run`], as a step `cancel` cancels.
    pub(crate) fn run_cancellable(
        &self,
        backends: &dyn SandboxBackends,
        console: &mut Console,
        cancel: &StepCancellation,
    ) -> Result<(MicroVmSandboxAdapter, MicroVmExit)> {
        let base = self.dir.path().join("base");
        for mount in ["workspace", "uploads", "outputs", "skills"] {
            fs::create_dir_all(base.join(mount)).expect("mount root");
        }
        fs::write(base.join("workspace/notes.txt"), b"base notes\n").expect("stage base file");
        let component = self.dir.path().join("component.wasm");
        fs::write(&component, b"\0asm\x0d\0\x01\0scripted").expect("component");
        let image = GuestImage::new("", "", component)
            .with_oci(GUEST_IMAGE)
            .expect("pinned guest image")
            .with_source("export default 1;");
        let backend = select_backend_for_tier(
            backends,
            self.vault.sandbox_provider()?,
            SandboxGuestTier::Foreign,
        )?
        .expect("an isolating backend");
        let mut adapter = MicroVmSandboxAdapter::new(
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
        )?;
        let exit = adapter.run_cancellable(
            &image,
            ExecutionBudget::new(STEP_SECONDS, 512, 64),
            cancel,
            console,
        )?;
        Ok((adapter, exit))
    }
}
