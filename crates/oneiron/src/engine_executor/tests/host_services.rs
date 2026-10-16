//! F12 (H129): generated executor code reaches the host through `self.*` and
//! its own recorded outputs alone. The executor took the full first-party
//! contract, so a file or credential service a host attached to the runtime
//! answered the model's code too.
use crate::code_run::{CodeRunDeterminism, SelfCall};
use crate::code_sandbox::quickjs::QuickJsRuntimeFactory;
use crate::code_sandbox::wasmtime_runtime::ComponentBudget;
use crate::code_sandbox::{
    FakeSandboxAdapter, SandboxBoundaryContract, SandboxGuestTier, SandboxMountTable,
    SandboxVirtualPath,
};
use crate::engine_executor::{
    JsCodeModeHost, JsCodeModeRuntime, JsCodeModeStep, SelfDispatchResponse,
};
use crate::{EntityId, Error, Result};
use sha2::{Digest, Sha256};

struct NoSelfCalls;

impl JsCodeModeHost for NoSelfCalls {
    fn dispatch_self(&mut self, _call: SelfCall) -> Result<SelfDispatchResponse> {
        Err(Error::InvalidConfig("this step makes no self call".into()))
    }
}

const PROBE: &str = "let read = 'refused'; \
    try { read = String.fromCharCode(...(await sandbox.fs.read_file('/mnt/workspace/secret.txt'))); } catch (_) {} \
    let credential = 'refused'; \
    try { await sandbox.credential.call({operation: 'list', credentialHandle: 'handle-1', args: {}}); credential = 'served'; } catch (_) {} \
    finish({read, credential});";

#[test]
fn executor_code_reaches_no_file_or_credential_service_a_host_attached() -> Result<()> {
    let directory = std::env::var_os("ONEIRON_QUICKJS_ARTIFACT_DIR").map_or_else(
        || {
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../components/code-run-quickjs/artifacts")
        },
        std::path::PathBuf::from,
    );
    let bytes = std::fs::read(directory.join("quickjs-first-party.wasm")).expect("pinned QuickJS");
    let pin: [u8; 32] = Sha256::digest(&bytes).into();
    let factory = QuickJsRuntimeFactory::from_component(&bytes, pin, ComponentBudget::default())?;
    let mounts = tempfile::tempdir().expect("tempdir");
    let run = |boundary: SandboxBoundaryContract| -> Result<serde_json::Value> {
        let mut adapter = FakeSandboxAdapter::new(
            SandboxGuestTier::FirstPartyDreamer,
            SandboxMountTable::new(
                mounts.path().join("workspace"),
                mounts.path().join("uploads"),
                mounts.path().join("outputs"),
                mounts.path().join("skills"),
            ),
        );
        adapter.stage_file(
            SandboxVirtualPath::try_new("/mnt/workspace/secret.txt")?,
            b"host file".to_vec(),
        );
        let mut runtime = factory.runtime()?.with_adapter(Box::new(adapter));
        let outcome = runtime.run_step(
            JsCodeModeStep {
                run_id: EntityId::from_bytes([1; 16])?,
                seq: 0,
                script: PROBE,
                boundary,
                determinism: CodeRunDeterminism::new(1_700_000_000_000, [7; 32]),
            },
            &mut NoSelfCalls,
        )?;
        assert!(outcome.done, "{}", outcome.observation);
        Ok(serde_json::from_str(&outcome.observation).expect("probe answers JSON"))
    };

    // The attached adapter answers a contract that links host services...
    assert_eq!(
        run(SandboxBoundaryContract::for_tier(
            SandboxGuestTier::FirstPartyDreamer
        ))?,
        serde_json::json!({"read": "host file", "credential": "served"})
    );
    // ...and never the executor's.
    let executor = super::super::host::executor_boundary_contract().expect("executor contract");
    assert_eq!(
        run(executor)?,
        serde_json::json!({"read": "refused", "credential": "refused"})
    );
    Ok(())
}
