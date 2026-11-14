//! The Owner doors' apply-shape check-in tests' shared fixture (P2.5 2k2:
//! `check_in_erase_effects.rs`, `check_in_history_erase_effects.rs`; 2k3:
//! `check_in_key_recovery_effects.rs`): a rooted vault, the decision of an
//! Owner's own act, and an agent's approved ask opened through the check-in
//! test doors.

use std::sync::Arc;

use oneiron::authority::MachineRole;
use oneiron::check_in::{
    ActClass, CheckInDecision, CheckInMode, CheckInScope, HolderAnswer, HolderKind,
    OpenPendingCheckIn, Rung, RungHolder, RungMembers, WaitReason,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::check_in::{FixedChain, answer, open};
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;

pub(crate) fn proof(vault: &Vault, person: EntityId) -> AuthenticatedOwner {
    vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("a person proof")
}

/// A rooted vault as a host starts one: the owner bound, this install
/// profiled. Its directory, the vault, its owner and the owner's proof.
pub(crate) fn rooted() -> (tempfile::TempDir, Vault, EntityId, AuthenticatedOwner) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("open vault");
    vault.install_device_keystore(Arc::new(MemoryKeystore::default()));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    oneiron::test_support::bind_host_owner(&vault, &issuer, owner).expect("the owner's binding");
    let owner_proof = proof(&vault, owner);
    (dir, vault, owner, owner_proof)
}

/// The decision of an Owner's own `act` on their own proof, applying
/// `check_in` asked by `requester` when given.
pub(crate) fn owner_decision(
    act: ActClass,
    check_in: Option<EntityId>,
    requester: Option<EntityId>,
) -> CheckInDecision {
    CheckInDecision {
        act_class: act.as_str().to_owned(),
        role: "owner".to_owned(),
        mode: None,
        basis: "own_proof".to_owned(),
        check_in: check_in.map(|id| id.to_hex()),
        requester: requester.map(|id| id.to_hex()),
    }
}

/// An agent's ask for `verb`'s `act` over `digest`, on a chain whose Owner
/// rung is `owner`, approved by the owner: its id and its asker.
pub(crate) fn approved(
    vault: &Vault,
    owner: EntityId,
    owner_proof: &AuthenticatedOwner,
    verb: &str,
    act: ActClass,
    digest: &[u8; 32],
) -> (EntityId, EntityId) {
    let asker = EntityId::now();
    let chain = FixedChain::default().with(
        Rung::Owner,
        RungMembers::Holders(vec![RungHolder {
            principal: owner,
            kind: HolderKind::Person,
        }]),
    );
    let ask = OpenPendingCheckIn {
        asker,
        grant_ref: "grant:deputy".to_owned(),
        verb: verb.to_owned(),
        act,
        scope: CheckInScope::default(),
        effect_digest: *digest,
        mode: CheckInMode::AlwaysAsk,
        reason: WaitReason::AlwaysAsk,
        asker_wait_secs: None,
        until: None,
        undo_plan: None,
        delay_window: None,
    };
    let id = open(vault, ask, &chain).expect("the agent asks").id;
    answer(vault, owner_proof, &id, digest, HolderAnswer::Approve).expect("the owner approves");
    (id, asker)
}

/// Whether check-in `id` is spent.
pub(crate) fn spent(vault: &Vault, id: &EntityId) -> bool {
    vault
        .pending_check_in(id)
        .expect("read the check-in")
        .expect("stored")
        .consumed_at
        .is_some()
}
