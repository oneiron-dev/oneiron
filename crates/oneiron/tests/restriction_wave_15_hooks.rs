//! Restriction wave 15, row C111: the owner's cap on the body budget a hook selector may
//! name (`runtime_hooks.hook.max_budget_ms`). Default = today: a pack hook naming more than
//! 60,000 ms is refused until the owner raises the key, and a budget of 0 is never a value.
//!
//! - the owner raises the cap to 120,000, then a local pack whose HOOK.md names
//!   budget_ms 90,000 installs and binds;
//! - with the cap unset the same pack is refused, and a pack naming 60,000 installs;
//! - the owner setting the cap to 0 is refused.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test restriction_wave_15_hooks`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::authority::{HostSlipIssuer, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::Memory;
use oneiron::skill_hub::HubFile;
use oneiron::skill_hub::pack_catalog::PackInstallDisposition;
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_store::ports::manual_clock::ManualClock;
use serde_json::{Value, json};

const SET: &str = "vault.settings.set";
const KEY: &str = "runtime_hooks.hook.max_budget_ms";
const T0: u64 = 1_790_000_000;

/// The pack the owner puts: an author-scoped name, as a hub pack has.
const PACK: &str = "example.hookbudget";
/// Its one hook.
const HOOK: &str = "fact-note";

const PACK_MD: &str = "---
name: example.hookbudget
description: One fact hook under the owner's budget cap.
version: 1.0.0
kind: capability
hooks: [\"fact-note\"]
---
A pack whose one fact hook names its body budget.
";

const BODY_JS: &str = "return {
  kind: \"propose\",
  claim: {
    subject: input.claim.subject,
    predicate: \"example.hookbudget.note\",
    confidence: 1,
    value: { note: input.claim.value }
  }
};
";

/// The pack's HOOK.md, naming `budget_ms`.
fn hook_md(budget_ms: u32) -> String {
    format!(
        "---\nname: fact-note\nversion: 1.0.0\nverbs: [\"claim.landed:example.hookbudget.input\"]\nactors: [\"human\"]\nphase: fact\nbudget_ms: {budget_ms}\noutcomes: [\"propose\"]\n---\nPropose one note per landed input claim.\n"
    )
}

struct Fixture {
    vault: Vault,
    _clock: Arc<ManualClock>,
    _dir: tempfile::TempDir,
    _issuer: HostSlipIssuer,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
}

impl Fixture {
    /// A rooted vault with its install enrolled and its embedded owner bound, opened owned: the
    /// writer lease is what lets the owner's handle call the owner verbs by name.
    fn rooted() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let clock = ManualClock::new(T0);
        let keystore = Arc::new(MemoryKeystore::new());
        let mut config = VaultConfig::device();
        config.store_clock = clock.bundle();
        let vault = Vault::open_owned(dir.path(), config).expect("owned vault");
        vault.install_device_keystore(Arc::<MemoryKeystore>::clone(&keystore));
        vault.prepare_install_signing().expect("install signing");
        let issuer = vault.bootstrap_host_slip_issuer().expect("host issuer");
        vault.ensure_host_root_slip(&issuer).expect("host root");
        vault
            .provision_engine_machine_identities(&issuer)
            .expect("engine machine identities");
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("serving install profile");
        let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
        let owner_proof = vault
            .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
            .expect("owner proof");
        Self {
            vault,
            _clock: clock,
            _dir: dir,
            _issuer: issuer,
            owner,
            owner_proof,
        }
    }

    fn as_owner(&self) -> Memory<'_> {
        self.vault.memory(self.owner, EdgeActorClass::Human)
    }

    /// The owner's put of the pack whose hook names `budget_ms`; answers the binding's id.
    fn put_pack(&self, budget_ms: u32) -> Result<EntityId, String> {
        let files = vec![
            HubFile::new("PACK.md", PACK_MD),
            HubFile::new(format!("hooks/{HOOK}/HOOK.md"), hook_md(budget_ms)),
            HubFile::new(format!("hooks/{HOOK}/body.js"), BODY_JS),
        ];
        match self.vault.put_pack(&self.owner_proof, files) {
            Ok(PackInstallDisposition::Installed(receipt)) => {
                assert_eq!(receipt.pack_name, PACK);
            }
            other => return Err(format!("{other:?}")),
        }
        let bindings: Vec<(EntityId, _)> = self
            .vault
            .pack_hook_bindings()
            .map_err(|error| format!("{error:?}"))?
            .into_iter()
            .filter(|(_, binding)| binding.pack == PACK)
            .collect();
        assert_eq!(bindings.len(), 1, "one binding: {bindings:?}");
        Ok(bindings[0].0)
    }
}

/// The owner's set of `value` on the vault row of `key`.
fn set(memory: &Memory<'_>, key: &str, value: Value) -> Value {
    invoke(
        memory,
        SET,
        json!({ "key": key, "scope": { "kind": "vault" }, "value": value }),
    )
    .unwrap_or_else(|error| panic!("{SET} answers: {error:?}"))
}

#[test]
fn a_pack_hook_naming_ninety_seconds_installs_once_the_owner_raises_the_cap() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();
    let applied = set(&me, KEY, json!(120_000));
    assert_eq!(applied["status"], json!("applied"), "{applied}");
    let id = fx
        .put_pack(90_000)
        .expect("the owner's put installs the ninety-second hook");
    let bindings = fx.vault.pack_hook_bindings().expect("read bindings");
    let binding = bindings
        .iter()
        .find(|(bound, _)| *bound == id)
        .map(|(_, binding)| binding)
        .expect("the binding is listed");
    assert_eq!(binding.hook, HOOK);
    assert_eq!(binding.selector.budget_ms, 90_000);
    assert!(binding.enabled);
}

#[test]
fn with_the_cap_unset_a_pack_hook_naming_ninety_seconds_is_refused() {
    let fx = Fixture::rooted();
    let refused = fx
        .put_pack(90_000)
        .expect_err("ninety seconds without the cap is refused");
    assert!(
        refused.contains("hook budget_ms is out of bounds"),
        "{refused}"
    );
    fx.put_pack(60_000)
        .expect("sixty seconds installs on the default");
}

#[test]
fn a_cap_of_zero_is_refused() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();
    let refused = invoke(
        &me,
        SET,
        json!({ "key": KEY, "scope": { "kind": "vault" }, "value": 0 }),
    )
    .expect_err("a cap of zero is refused");
    assert!(
        format!("{refused:?}").contains("at least one millisecond"),
        "{refused:?}"
    );
}
