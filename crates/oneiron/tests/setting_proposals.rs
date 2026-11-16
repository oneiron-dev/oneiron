//! DESIGN 15-setting-primitive, stage 7b-3: the owner's setting proposals (section 1.6,
//! "Receipts"). An owner act a machine that is not his carried without his key's proof waits:
//! it changes nothing, and his list shows it with its row and the value it would leave. One tap
//! on an install that holds his key applies it as his own change and ends the ask; on an install
//! that cannot prove his act the tap is refused and the proposal keeps asking.
//!
//! The listing is new in 7b-3, so this file has no red run at 7b-2 (`88379fbb6fe9`): the same
//! behaviour's red run is `tests/setting_read_on_proofs.rs`, which reads the waiting act as
//! `Pending` and the refusing door. Green at the 7b-3 head.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test
//! setting_proposals`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{ActAuthority, ActSurface, HostSlipIssuer, MachineOwnership, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::setting::{
    SetSetting, SetSettingOutcome, SettingCaller, SettingMode, SettingProposal, SettingScope,
    SettingStanding,
};
use oneiron::store::GateDecisionId;
use oneiron::test_doors::owner_key_release::release_owner_keys;
use oneiron::test_doors::setting::{
    EnrolledMachine, enroll_machine_with_key, land_setting_act_from, ordered_cap_read,
    setting_frontier,
};
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_store::ports::manual_clock::ManualClock;
use serde_json::json;

/// A cap whose rows meet: lower is stricter, its default is 10.
const CAP: &str = "test.ordered_cap";
const T0: u64 = 1_790_000_000;

struct Fixture {
    vault: Vault,
    _clock: Arc<ManualClock>,
    _dir: tempfile::TempDir,
    issuer: HostSlipIssuer,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
}

impl Fixture {
    /// A vault with an authority root, the owner's key enrolled on this install, the owner's
    /// cap at 6, and a work machine of his (not his own) that carried his change of the cap to 3
    /// without his key's proof. The work machine's MACHINE id.
    fn with_a_proposal() -> (Self, EntityId) {
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
        let fx = Self {
            vault,
            _clock: clock,
            _dir: dir,
            issuer,
            owner,
            owner_proof,
        };
        fx.owner_sets(json!(6));
        let (signer, machine) = fx.work_machine(0x81);
        fx.vault
            .enrol_device_owner_signing_key(
                &ActAuthority::Owner(fx.owner_proof.clone(), ActSurface::ThisInstall),
                &fx.issuer,
            )
            .expect("the owner key is enrolled");
        let now = setting_frontier(
            &fx.vault,
            CAP,
            None,
            SettingMode::Value,
            SettingScope::Vault,
        )
        .expect("frontier");
        land_setting_act_from(
            &fx.vault,
            &signer,
            fx.owner,
            &now,
            (CAP, None, SettingMode::Value, SettingScope::Vault),
            Some(json!(3)),
            T0,
        )
        .expect("the act is stored");
        (fx, machine)
    }

    /// Enrols a machine of the owner's whose install key is derived from `seed`, then answers
    /// it a work machine: not his own, so its owner acts need his key's proof.
    fn work_machine(&self, seed: u8) -> (EnrolledMachine, EntityId) {
        let machines = |vault: &Vault| -> BTreeSet<EntityId> {
            vault
                .authority_fold()
                .expect("the fold")
                .machines
                .keys()
                .copied()
                .collect()
        };
        let before = machines(&self.vault);
        let signer =
            enroll_machine_with_key(&self.vault, &self.owner_proof, seed).expect("enrolled");
        let added: Vec<EntityId> = machines(&self.vault).difference(&before).copied().collect();
        let [machine] = added.as_slice() else {
            panic!("one machine enrolled: {added:?}");
        };
        self.vault
            .set_machine_role(
                &self.owner_proof,
                ActSurface::ThisInstall,
                *machine,
                MachineRole::Owned(MachineOwnership::WorkSchool),
                None,
            )
            .expect("the owner answers a work machine");
        (signer, *machine)
    }

    fn owner_sets(&self, value: serde_json::Value) {
        let outcome = self
            .vault
            .set_setting(
                SettingCaller::Owner(&self.owner_proof),
                SetSetting::vault_value(CAP, value),
            )
            .expect("the owner's change");
        assert!(
            matches!(outcome, SetSettingOutcome::Applied { .. }),
            "the owner's change applied: {outcome:?}"
        );
    }

    fn cap(&self) -> (u64, SettingStanding) {
        let read = ordered_cap_read(&self.vault, &[]).expect("the read");
        (read.value, read.standing)
    }

    fn proposals(&self) -> Vec<SettingProposal> {
        self.vault.setting_proposals().expect("the proposals")
    }
}

#[test]
fn a_proposal_is_listed_with_its_row_and_value_and_one_tap_applies_it() {
    let (fx, carrier) = Fixture::with_a_proposal();
    let proposals = fx.proposals();
    let [proposal] = proposals.as_slice() else {
        panic!("one proposal: {proposals:?}");
    };
    assert_eq!(
        (
            proposal.key.as_str(),
            proposal.item.as_deref(),
            proposal.mode,
            &proposal.scope,
            proposal.value.clone(),
            proposal.carrier,
        ),
        (
            CAP,
            None,
            SettingMode::Value,
            &SettingScope::Vault,
            Some(json!(3)),
            carrier,
        ),
        "the list shows the row, the value it would leave and its carrier"
    );
    assert!(
        fx.vault
            .authority_fold()
            .expect("the fold")
            .waiting_owner_choices()
            .contains(&proposal.entry),
        "the proposal is one of the owner choices that wait for his proof"
    );
    assert_eq!(fx.cap(), (6, SettingStanding::Pending));

    let entry = proposal.entry;
    let applied = fx
        .vault
        .apply_setting_proposal(&fx.owner_proof, entry)
        .expect("one tap on an install that holds his key");
    assert!(
        matches!(applied, SetSettingOutcome::Applied { .. }),
        "{applied:?}"
    );
    assert_eq!(fx.cap(), (3, SettingStanding::Settled), "his change lands");
    assert!(fx.proposals().is_empty(), "and ends the ask");

    let again = fx.vault.apply_setting_proposal(&fx.owner_proof, entry);
    assert!(
        format!("{again:?}").contains("ConcurrentWrite"),
        "a tap on an answered proposal names it stale: {again:?}"
    );
}

#[test]
fn an_install_that_cannot_prove_the_owners_act_refuses_the_tap_and_the_proposal_keeps_asking() {
    let (fx, _) = Fixture::with_a_proposal();
    let entry = fx.proposals()[0].entry;
    release_owner_keys(&fx.vault);

    let refused = fx.vault.apply_setting_proposal(&fx.owner_proof, entry);
    assert!(
        format!("{refused:?}").contains("OwnerKeyRequired"),
        "this install holds no key of his and is not his machine: {refused:?}"
    );
    assert_eq!(fx.proposals().len(), 1, "the proposal keeps asking");
    assert_eq!(fx.cap(), (6, SettingStanding::Pending));
}
