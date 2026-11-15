//! The vault's sandbox provider switch (L8-43; provider-adapter-architecture-v1
//! #default-switch-off; Engine rulings 14 Nov 03:02, L8-43-SWITCH = A).
//!
//! Ours is the default: unset, the switch reads as ours and a Foreign or
//! Untrusted run takes our backend. The owner alone switches to a vendor,
//! under the owner's proof, through `vault.settings.sandbox_provider.replace`.
//! Then every finite Foreign and Untrusted run takes that vendor's backend,
//! and first-party code still runs in-process. A vendor this host cannot
//! serve refuses the run, typed (`SandboxVendorUnavailable`): the owner
//! switched ours off, so ours never runs in its place. An agent never flips
//! the switch.
//!
//! Every switch change goes through its verb name, and every selection
//! through the public `select_backend_for_tier` with the vault's own reader
//! of the switch, so this file does not build on a tree without the switch.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --no-fail-fast --test sandbox_vendor_switch`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;
use std::sync::Arc;

use oneiron::code_sandbox::microvm::{
    CredentialResolver, ExecutionBudget, GuestImage, MicroVmBackend, MicroVmExit, MicroVmHandle,
    SandboxBackends, backend_error, select_backend_for_tier,
};
use oneiron::code_sandbox::{
    SandboxBoundaryContract, SandboxGuestTier, SandboxMountTable, SandboxProposalWrite,
    SandboxProvider, SandboxVendor,
};
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MemoryResult};
use oneiron::task_verb::sdk::invoke;
use oneiron::test_doors::coach::define_agent;
use oneiron::{EdgeActorClass, EntityId, ErrorKind, Vault, VaultConfig};
use serde_json::{Value, json};

const READ: &str = "vault.settings.sandbox_provider";
const REPLACE: &str = "vault.settings.sandbox_provider.replace";

/// A backend that only answers its name: the selection is under test, never
/// a run.
struct LabelledBackend(&'static str);

impl MicroVmBackend for LabelledBackend {
    fn name(&self) -> &'static str {
        self.0
    }

    fn prepare(
        &self,
        _contract: &SandboxBoundaryContract,
        _mounts: &SandboxMountTable,
    ) -> oneiron::Result<MicroVmHandle> {
        Err(backend_error(self.0, "a labelled backend runs nothing"))
    }

    fn run(
        &self,
        _vm: &MicroVmHandle,
        _image: &GuestImage,
        _budget: ExecutionBudget,
    ) -> oneiron::Result<MicroVmExit> {
        Err(backend_error(self.0, "a labelled backend runs nothing"))
    }

    fn collect_overlay_delta(
        &self,
        _vm: &MicroVmHandle,
    ) -> oneiron::Result<Vec<SandboxProposalWrite>> {
        Ok(Vec::new())
    }

    fn cleanup(&self, _vm: &MicroVmHandle) {}

    fn proxy_credentials(
        &self,
        _vm: &MicroVmHandle,
        _resolver: &dyn CredentialResolver,
    ) -> oneiron::Result<()> {
        Err(backend_error(self.0, "a labelled backend binds nothing"))
    }
}

/// The backends of a host with no KVM microVM, our OCI fenced container, and
/// a Daytona adapter: every other vendor is one this host cannot serve.
struct NamedBackends;

impl SandboxBackends for NamedBackends {
    fn firecracker(&self) -> Option<Box<dyn MicroVmBackend>> {
        None
    }

    fn container(&self) -> Option<Box<dyn MicroVmBackend>> {
        Some(Box::new(LabelledBackend("container")))
    }

    fn session_container(
        &self,
        _runtime: PathBuf,
        _image: &str,
    ) -> Option<oneiron::Result<Box<dyn MicroVmBackend>>> {
        Some(Ok(Box::new(LabelledBackend("container"))))
    }

    fn vendor(&self, vendor: SandboxVendor) -> Option<Box<dyn MicroVmBackend>> {
        (vendor == SandboxVendor::Daytona)
            .then(|| Box::new(LabelledBackend("vendor:daytona")) as Box<dyn MicroVmBackend>)
    }
}

/// A vault this process owns (the writer lease), so the owner's handle
/// carries the owner's proof, with the named backends installed.
struct Fixture {
    vault: Vault,
    owner: EntityId,
    _dir: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = Vault::open_owned(dir.path(), VaultConfig::device()).expect("an owned vault");
        oneiron::test_support::provision_engine_machines(&vault);
        let owner = vault.ensure_embedded_owner_actor().expect("the owner");
        assert!(
            vault
                .install_sandbox_backends(Arc::new(NamedBackends))
                .is_ok(),
            "a fresh vault takes its host's backends"
        );
        Self {
            vault,
            owner,
            _dir: dir,
        }
    }

    fn call(
        &self,
        actor: EntityId,
        class: EdgeActorClass,
        verb: &str,
        input: Value,
    ) -> MemoryResult<Value> {
        invoke(&self.vault.memory(actor, class), verb, input)
    }

    fn read(&self) -> Value {
        self.call(self.owner, EdgeActorClass::Human, READ, json!({}))
            .expect("the owner reads the switch")
    }

    fn replace(&self, provider: Value) -> Value {
        self.call(
            self.owner,
            EdgeActorClass::Human,
            REPLACE,
            json!({ "provider": provider }),
        )
        .expect("the owner replaces the switch")
    }

    /// What the vault's selection gives `tier` under its own switch:
    /// `backend <name>`, `in-process`, or `refused <kind>`.
    fn select(&self, tier: SandboxGuestTier) -> String {
        let provider = self.vault.sandbox_provider().expect("the switch reads");
        match select_backend_for_tier(&*self.vault.runtime().sandbox_backends(), provider, tier) {
            Ok(Some(backend)) => format!("backend {}", backend.name()),
            Ok(None) => "in-process".to_owned(),
            Err(error) => format!("refused {:?}", error.kind()),
        }
    }
}

#[test]
fn unset_switch_keeps_ours() {
    let f = Fixture::new();
    assert_eq!(
        f.read(),
        json!({ "provider": "ours", "sessions": "ours" }),
        "an unset switch reads as ours"
    );
    assert_eq!(f.vault.sandbox_provider().unwrap(), SandboxProvider::Ours);
    assert_eq!(f.select(SandboxGuestTier::Foreign), "backend container");
    assert_eq!(f.select(SandboxGuestTier::Untrusted), "backend container");
    assert_eq!(f.select(SandboxGuestTier::FirstPartyDreamer), "in-process");
}

#[test]
fn owner_switch_routes_foreign_runs_to_the_named_vendor() {
    let f = Fixture::new();
    let answer = f.replace(json!({ "vendor": "daytona" }));
    assert_eq!(
        answer,
        json!({ "provider": { "vendor": "daytona" }, "sessions": "ours" }),
        "the replace answers the switch it stored; sessions stay on ours"
    );
    assert_eq!(f.read(), answer, "the read answers the stored switch");
    assert_eq!(
        f.vault.sandbox_provider().unwrap(),
        SandboxProvider::Vendor(SandboxVendor::Daytona)
    );
    assert_eq!(
        f.select(SandboxGuestTier::Foreign),
        "backend vendor:daytona"
    );
    assert_eq!(
        f.select(SandboxGuestTier::Untrusted),
        "backend vendor:daytona"
    );
    // A run's gate knows each vendor's backend by its name, and none of ours.
    for vendor in SandboxVendor::ALL {
        assert_eq!(
            SandboxVendor::from_backend_name(vendor.backend_name()),
            Some(vendor)
        );
    }
    for ours in ["firecracker", "landlock-container", "dev-process-isolation"] {
        assert_eq!(SandboxVendor::from_backend_name(ours), None, "{ours}");
    }
    assert_eq!(
        f.select(SandboxGuestTier::FirstPartyDreamer),
        "in-process",
        "first-party code stays in-process whatever the switch"
    );

    f.replace(json!("ours"));
    assert_eq!(f.read(), json!({ "provider": "ours", "sessions": "ours" }));
    assert_eq!(
        f.select(SandboxGuestTier::Foreign),
        "backend container",
        "switching back to ours takes our backend again"
    );
}

#[test]
fn switched_vendor_without_a_backend_refuses_typed() {
    let f = Fixture::new();
    f.replace(json!({ "vendor": "e2b" }));
    let refused = format!("refused {:?}", ErrorKind::SandboxVendorUnavailable);
    assert_eq!(
        f.select(SandboxGuestTier::Foreign),
        refused,
        "a vendor this host cannot serve refuses; ours never runs in its place"
    );
    assert_eq!(f.select(SandboxGuestTier::Untrusted), refused);
    assert_eq!(f.select(SandboxGuestTier::FirstPartyDreamer), "in-process");

    let error = select_backend_for_tier(
        &*f.vault.runtime().sandbox_backends(),
        SandboxProvider::Vendor(SandboxVendor::E2b),
        SandboxGuestTier::Foreign,
    )
    .err()
    .expect("refused");
    assert!(
        error.to_string().contains("`e2b`"),
        "the refusal names the vendor: {error}"
    );

    for vendor in SandboxVendor::ALL {
        let outcome = match select_backend_for_tier(
            &NamedBackends,
            SandboxProvider::Vendor(vendor),
            SandboxGuestTier::Foreign,
        ) {
            Ok(Some(backend)) => format!("backend {}", backend.name()),
            Ok(None) => "in-process".to_owned(),
            Err(error) => format!("refused {:?}", error.kind()),
        };
        let expected = if vendor == SandboxVendor::Daytona {
            "backend vendor:daytona".to_owned()
        } else {
            refused.clone()
        };
        assert_eq!(outcome, expected, "{}", vendor.as_str());
    }
}

#[test]
fn agent_cannot_flip_the_switch() {
    let f = Fixture::new();
    let agent = define_agent(&f.vault).expect("an agent");
    let refusal = f
        .call(
            agent,
            EdgeActorClass::Agent,
            REPLACE,
            json!({ "provider": { "vendor": "daytona" } }),
        )
        .expect_err("an agent never flips the owner's switch");
    assert_eq!(refusal.code, MEMORY_CODE_FORBIDDEN, "{refusal:?}");
    let refusal = f
        .call(agent, EdgeActorClass::Agent, READ, json!({}))
        .expect_err("an agent never reads the owner's door");
    assert_eq!(refusal.code, MEMORY_CODE_FORBIDDEN, "{refusal:?}");

    assert_eq!(f.read(), json!({ "provider": "ours", "sessions": "ours" }));
    assert_eq!(f.vault.sandbox_provider().unwrap(), SandboxProvider::Ours);
    assert_eq!(f.select(SandboxGuestTier::Foreign), "backend container");
}
