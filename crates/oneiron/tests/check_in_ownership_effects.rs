//! ROLES-CHECKIN P2.5, piece 2k1 (ARCH-0082 #role-defaults and
//! #catastrophe-floor; Engine ruling P25-SHAPE Q1, Q4 and Q5 = A, 14 Nov
//! 13:39): the ownership changes of a shared vault through check-in.
//!
//! - An Owner's own transfer, add of an Owner and removal of an Owner go at
//!   once on the Owner's own proof, and each act records that decision (the
//!   Owner's own acts are never gated; ARCH-0082 #owner-own-acts).
//! - A Deputy house whose Grant names the act opens a check-in for it
//!   (`vault.check_in.open`, over the act's effect digest); it always asks,
//!   as the catastrophe floor says. Once the Owner approves, the Owner starts
//!   the act on their own proof naming it as `check_in_ref`: the start spends
//!   it in its writer and the act names the house as requester (the 2j
//!   apply shape, P25-SHAPE Q1). An unapproved ref, another act's check-in or
//!   another effect starts nothing.
//! - The add and the removal of an Owner carry the act class
//!   `ownership_transfer` (Q4): a Deputy's ask for them waits on the Owner.
//! - The handover rule still runs: an approved transfer to the Owner
//!   themselves starts nothing and leaves the check-in unspent.
//!
//! On the base (the stack top 14d48cd3e3b) this file does not build: the
//! `*_with_check_in` starts, the three effect digests and the requests'
//! `check_in_ref` do not exist.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test check_in_ownership_effects`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{ActSurface, MachineRole};
use oneiron::check_in::{
    CheckInDecision, owner_add_effect_digest, owner_remove_effect_digest,
    ownership_transfer_effect_digest,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{FederationGrantRole as Role, Scope, ScopeAxis};
use oneiron::registry::{ENTITY_TYPE_ORG, ENTITY_TYPE_PERSON};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
use oneiron::verbs::{
    AgentGrantMintRequest, SharedTransferRequest, mint_agent_grant_as, propose_shared_transfer,
};
use oneiron::workspace_roster::{WorkCompanionPolicy, WorkspaceRosterPreset};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use serde_json::json;

const SHARED: u64 = 47;
const TRANSFER: &str = "vault.shared.propose_transfer";
const ADD_OWNER: &str = "vault.shared.propose_add_owner";
const REMOVE_OWNER: &str = "vault.shared.propose_remove_owner";
const WORKSPACE: &str = "check-in-ownership-workspace";

fn live_person(vault: &Vault) -> EntityId {
    let id = EntityId::now();
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"human",
        )
        .expect("a live person");
    id
}

fn proof(vault: &Vault, person: EntityId) -> AuthenticatedOwner {
    vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("a person proof")
}

fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The decision an Owner's ownership change records: the Owner's own proof,
/// and the check-in it applied with its requester, when it applied one.
fn owner_change(check_in: Option<String>, requester: Option<String>) -> Option<CheckInDecision> {
    Some(CheckInDecision {
        act_class: "ownership_transfer".to_owned(),
        role: "owner".to_owned(),
        mode: None,
        basis: "own_proof".to_owned(),
        check_in,
        requester,
    })
}

/// The shared vault with its workspace house bound at Deputy, and the
/// owner's Grant to the house naming the three ownership changes.
struct DeputyHouse {
    _dir: tempfile::TempDir,
    vault: Vault,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
    house: EntityId,
}

impl DeputyHouse {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = Vault::open(dir.path(), VaultConfig::device()).expect("open vault");
        vault.install_device_keystore(Arc::new(MemoryKeystore::default()));
        let issuer = oneiron::test_support::provision_engine_machines(&vault);
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("this install's live machine profile");
        let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
        oneiron::test_support::bind_host_owner(&vault, &issuer, owner)
            .expect("the owner's binding");
        let owner_proof = proof(&vault, owner);
        let signer = vault
            .owner_project_signer(&issuer)
            .expect("the owner's project signer");
        let root = vault.root_project().expect("the root project");
        vault
            .sign_owner_project(&owner_proof, &signer, root)
            .expect("the root's first signature");
        let org = EntityId::now();
        vault
            .put_entity(
                &org,
                ENTITY_TYPE_ORG,
                TimeRange { start: 1, end: 1 },
                1,
                b"check-in ownership org",
            )
            .expect("org row");
        vault
            .initialize_shared_vault(&owner_proof, SHARED, None, &[], vault.now_recorded_at())
            .expect("the owner initializes the shared vault");
        let (house, _) = vault
            .get_seeded_agent_definition_by_logical_id("sys.default")
            .expect("read the seeded agents")
            .expect("sys.default is seeded on open");
        let preset = WorkspaceRosterPreset {
            workspace_ref: WORKSPACE.to_owned(),
            workspace_vault_id: SHARED,
            org_ref: org,
            venture_name: "Garden Works".to_owned(),
            house_display_name: None,
            house_actor_ref: house,
            house_identity_ref: None,
        };
        vault
            .establish_workspace_preset(&preset, WorkCompanionPolicy::Choose, &owner_proof)
            .expect("the owner stores the workspace");
        vault
            .bind_workspace_house_leader(WORKSPACE, Role::Deputy, &owner_proof, &signer)
            .expect("the owner binds the house at deputy");
        let mut scope = Scope::top();
        scope.verbs = ScopeAxis::Some(
            ["read", TRANSFER, ADD_OWNER, REMOVE_OWNER]
                .map(str::to_owned)
                .into_iter()
                .collect::<BTreeSet<_>>(),
        );
        let minted = mint_agent_grant_as(
            &vault,
            &owner_proof,
            ActSurface::ThisInstall,
            AgentGrantMintRequest {
                agent: house,
                authority_scope: scope,
                expires_at: None,
                repo_bounds: None,
                verb_classes: BTreeSet::new(),
                wallet_ref: None,
                working_view_bounds: None,
            },
        )
        .expect("the owner mints the house a Grant");
        assert!(minted.grant.confers, "the Grant confers");
        Self {
            _dir: dir,
            vault,
            owner,
            owner_proof,
            house,
        }
    }

    /// The house opens a check-in for `verb`'s act over `digest`; its id.
    fn open(&self, verb: &str, digest: &[u8; 32]) -> String {
        let opened = invoke(
            &self.vault.memory(self.house, EdgeActorClass::Agent),
            "vault.check_in.open",
            json!({ "verb": verb, "effect_digest": hex(digest) }),
        )
        .expect("the house opens its check-in");
        assert_eq!(
            (opened["outcome"].as_str(), opened["reason"].as_str()),
            (Some("wait"), Some("always_ask")),
            "a Deputy always asks the Owner on an ownership change: {opened}"
        );
        opened["handle"]["handle"]
            .as_str()
            .expect("a handle")
            .to_owned()
    }

    /// The owner approves check-in `id` over `digest`.
    fn approve(&self, id: &str, digest: &[u8; 32]) {
        let settled = invoke(
            &self.vault.memory(self.owner, EdgeActorClass::Human),
            "vault.check_in.answer",
            json!({ "handle": id, "answer": "approve", "effect_digest": hex(digest) }),
        )
        .expect("the owner answers");
        assert_eq!(settled["eligible"].as_str(), Some("approved"), "{settled}");
    }

    /// Whether check-in `id` is spent.
    fn spent(&self, id: &EntityId) -> bool {
        self.vault
            .pending_check_in(id)
            .expect("read the check-in")
            .expect("stored")
            .consumed_at
            .is_some()
    }
}

fn id_of(hex: &str) -> EntityId {
    EntityId::from_hex(hex).expect("a check-in id")
}

#[test]
fn an_owners_own_ownership_changes_go_on_their_own_proof() {
    let fx = DeputyHouse::new();
    let (to, added, successor) = (
        live_person(&fx.vault),
        live_person(&fx.vault),
        live_person(&fx.vault),
    );
    let transfer = fx
        .vault
        .propose_transfer_ownership(&fx.owner_proof, SHARED, to, Some(Role::Admin))
        .expect("the owner starts the transfer");
    let add = fx
        .vault
        .propose_add_owner(&fx.owner_proof, SHARED, added)
        .expect("the owner starts the add");
    let removal = fx
        .vault
        .propose_remove_owner(
            &fx.owner_proof,
            SHARED,
            fx.owner,
            Some(successor),
            None,
            false,
        )
        .expect("the owner starts their own removal");
    for act in [&transfer, &add, &removal] {
        assert_eq!(
            act.check_in,
            owner_change(None, None),
            "{}: the act records that the Owner went on their own proof",
            act.act
        );
        assert_eq!(
            act.starter,
            fx.owner.to_hex(),
            "{}: the owner starts it",
            act.act
        );
    }
}

#[test]
fn the_owner_applies_a_deputys_approved_transfer_on_their_own_proof() {
    let fx = DeputyHouse::new();
    let to = live_person(&fx.vault);
    let digest = ownership_transfer_effect_digest(SHARED, &fx.owner, &to, Some(Role::Admin));
    let transfer = fx.open(TRANSFER, &digest);
    let transfer_id = id_of(&transfer);

    let early = fx.vault.propose_transfer_ownership_with_check_in(
        &fx.owner_proof,
        SHARED,
        to,
        Some(Role::Admin),
        Some(transfer_id),
    );
    assert!(
        early.is_err(),
        "the owner has not answered: the ref starts nothing: {early:?}"
    );

    fx.approve(&transfer, &digest);
    // Another effect: the asker named the owner keeping Admin.
    let other_effect = fx.vault.propose_transfer_ownership_with_check_in(
        &fx.owner_proof,
        SHARED,
        to,
        None,
        Some(transfer_id),
    );
    assert!(
        other_effect.is_err(),
        "an approval of another effect starts nothing: {other_effect:?}"
    );
    assert!(!fx.spent(&transfer_id), "a refused start spends nothing");

    // The verb's own input names the approved check-in.
    let input: SharedTransferRequest = serde_json::from_value(json!({
        "vault_id": SHARED.to_string(),
        "to": to.to_hex(),
        "from_keeps": "admin",
        "check_in_ref": transfer,
    }))
    .expect("the transfer input names its check-in");
    let act = propose_shared_transfer(&fx.vault, &fx.owner_proof, input)
        .expect("the owner applies the approved transfer");
    assert_eq!(
        act.check_in,
        owner_change(Some(transfer.clone()), Some(fx.house.to_hex())),
        "the act names the check-in it applied and the house that asked"
    );
    assert_eq!(act.starter, fx.owner.to_hex(), "the owner starts the act");
    assert!(fx.spent(&transfer_id), "the start spent the check-in");
    let again = fx.vault.propose_transfer_ownership_with_check_in(
        &fx.owner_proof,
        SHARED,
        to,
        Some(Role::Admin),
        Some(transfer_id),
    );
    assert!(again.is_err(), "a spent check-in applies once: {again:?}");
}

#[test]
fn the_owner_applies_a_deputys_approved_owner_add_and_removal() {
    let fx = DeputyHouse::new();
    let (added, successor) = (live_person(&fx.vault), live_person(&fx.vault));
    let add_digest = owner_add_effect_digest(SHARED, &added);
    let add = fx.open(ADD_OWNER, &add_digest);
    let remove_digest = owner_remove_effect_digest(SHARED, &fx.owner, Some(&successor), None, true);
    let removal = fx.open(REMOVE_OWNER, &remove_digest);
    fx.approve(&add, &add_digest);
    fx.approve(&removal, &remove_digest);

    let crossed = fx.vault.propose_remove_owner_with_check_in(
        &fx.owner_proof,
        SHARED,
        fx.owner,
        Some(successor),
        None,
        true,
        Some(id_of(&add)),
    );
    assert!(
        crossed.is_err(),
        "the add's check-in starts no removal: {crossed:?}"
    );
    assert!(!fx.spent(&id_of(&add)), "a refused start spends nothing");

    let added_act = fx
        .vault
        .propose_add_owner_with_check_in(&fx.owner_proof, SHARED, added, Some(id_of(&add)))
        .expect("the owner applies the approved add");
    assert_eq!(
        added_act.check_in,
        owner_change(Some(add.clone()), Some(fx.house.to_hex())),
        "the add names its check-in and the house"
    );
    let removed_act = fx
        .vault
        .propose_remove_owner_with_check_in(
            &fx.owner_proof,
            SHARED,
            fx.owner,
            Some(successor),
            None,
            true,
            Some(id_of(&removal)),
        )
        .expect("the owner applies the approved removal");
    assert_eq!(
        removed_act.check_in,
        owner_change(Some(removal.clone()), Some(fx.house.to_hex())),
        "the removal names its check-in and the house"
    );
    assert!(
        fx.spent(&id_of(&add)) && fx.spent(&id_of(&removal)),
        "each start spent its own check-in"
    );
}

#[test]
fn an_approved_transfer_still_meets_the_handover_rule() {
    let fx = DeputyHouse::new();
    // The house asks to hand the owner's ownership to the owner.
    let digest = ownership_transfer_effect_digest(SHARED, &fx.owner, &fx.owner, None);
    let transfer = fx.open(TRANSFER, &digest);
    fx.approve(&transfer, &digest);
    let refused = fx.vault.propose_transfer_ownership_with_check_in(
        &fx.owner_proof,
        SHARED,
        fx.owner,
        None,
        Some(id_of(&transfer)),
    );
    assert!(
        refused.is_err(),
        "an approval is no proof of its own: the handover rule refuses: {refused:?}"
    );
    assert!(
        !fx.spent(&id_of(&transfer)),
        "the refused start leaves the approval unspent"
    );
}
