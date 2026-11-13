//! ROLES-CHECKIN P2.4c, piece 2j (ARCH-0082 #role-defaults and #composing;
//! Engine ruling P24-SHAPE Q7, Q8 and Q9 = A, 13 Nov 19:32): the vault
//! delete and the erase ask.
//!
//! - Any person whose role reads the record may ask for its erase (Q8;
//!   ARCH-0082: "Any actor, in any role, may open an erase proposal"): a
//!   Viewer requests and a Steward proposes. The ask erases nothing; only an
//!   Owner erases.
//! - An Owner's start of the vault delete records its check-in decision: the
//!   Owner acts on their own proof (Q9).
//! - A Deputy house whose Grant names the delete opens a check-in for it
//!   (`vault.check_in.open`, over `vault_delete_effect_digest`); it waits for
//!   the Owner. Once the Owner approves, the Owner starts the delete on their
//!   own proof naming it as `check_in_ref`: the start spends it in its writer
//!   and the act names the house as requester (Q7). An unapproved ref, or a
//!   check-in for another act, starts nothing. The act keeps its policy row's
//!   wait and Owner executors.
//! - The Owner applies a Deputy house's approved erase the same way: the
//!   confirm names it as `check_in_ref` (over `record_erase_effect_digest`),
//!   erases on the Owner's own proof and its outcome names the house as
//!   requester (Q7, Q9). With two Owners the erase waits out its veto
//!   window, and its `erase` act records the decision (Q9; review of P2.4c).
//!
//! On the base (P2.4b) this file does not build: `PendingAuthorityAct` has no
//! `check_in` field, and `propose_delete_vault_with_check_in` and
//! `vault_delete_effect_digest` do not exist. Its erase-ask case alone fails
//! there at run time: the Viewer's ask is refused.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test check_in_destructive_effects`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{ActSurface, MachineRole};
use oneiron::check_in::{CheckInDecision, record_erase_effect_digest, vault_delete_effect_digest};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{
    EraseAskKind, FederationGrantRole as Role, InitialSharedMember, Scope, ScopeAxis,
};
use oneiron::memory::{BlobArtifactInput, Memory};
use oneiron::registry::{ENTITY_TYPE_ORG, ENTITY_TYPE_PERSON};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
use oneiron::verbs::{
    AgentGrantMintRequest, RecordEraseConfirmRequest, RecordEraseOutcome, RecordEraseRequest,
    confirm_record_erase, mint_agent_grant_as, preview_record_erase,
};
use oneiron::workspace_roster::{WorkCompanionPolicy, WorkspaceRosterPreset};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use serde_json::json;

const SHARED: u64 = 43;
const VAULT_DELETE: &str = "vault.shared.propose_delete";
const ERASE: &str = "vault.records.erase_confirm";
const WORKSPACE: &str = "check-in-destructive-workspace";

fn person(vault: &Vault, id: EntityId) {
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"human",
        )
        .expect("a live person");
}

fn proof(vault: &Vault, person: EntityId) -> AuthenticatedOwner {
    vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("a person proof")
}

fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A rooted vault as a host starts one: the owner bound, the root signed,
/// this install profiled to carry the owner's Grant acts. Its owner, the
/// owner's proof and the host issuer.
fn rooted(
    dir: &tempfile::TempDir,
) -> (
    Vault,
    EntityId,
    AuthenticatedOwner,
    oneiron::authority::HostSlipIssuer,
) {
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("open vault");
    vault.install_device_keystore(Arc::new(MemoryKeystore::default()));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    oneiron::test_support::bind_host_owner(&vault, &issuer, owner).expect("the owner's binding");
    let owner_proof = proof(&vault, owner);
    (vault, owner, owner_proof, issuer)
}

#[test]
fn a_viewer_requests_and_a_steward_proposes_an_erase() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (vault, owner, owner_proof, _issuer) = rooted(&dir);
    let [viewer, steward, record] = std::array::from_fn(|_| EntityId::now());
    for id in [viewer, steward, record] {
        person(&vault, id);
    }
    let member = |member_ref, role| InitialSharedMember {
        member_ref,
        role: Some(role),
    };
    vault
        .initialize_shared_vault(
            &owner_proof,
            SHARED,
            None,
            &[
                member(owner, Role::Owner),
                member(viewer, Role::Viewer),
                member(steward, Role::Steward),
            ],
            1,
        )
        .expect("a shared vault with a Viewer and a Steward");
    for (id, role) in [(viewer, Role::Viewer), (steward, Role::Steward)] {
        let member_proof = proof(&vault, id);
        let invitation = vault
            .shared_invitations(&member_proof, SHARED)
            .expect("invitations")
            .into_iter()
            .find(|open| open.role == role)
            .expect("the founding invitation");
        vault
            .accept_shared_invitation(&member_proof, SHARED, &invitation.id)
            .expect("the member accepts");
    }
    let requested = vault
        .ask_shared_erase(&proof(&vault, viewer), SHARED, record)
        .expect("a Viewer may ask for an erase");
    assert_eq!(requested.kind, EraseAskKind::Request, "a Viewer requests");
    let proposed = vault
        .ask_shared_erase(&proof(&vault, steward), SHARED, record)
        .expect("a Steward may ask for an erase");
    assert_eq!(proposed.kind, EraseAskKind::Proposal, "a Steward proposes");
    assert!(
        vault.get(&record).expect("read the record").is_some(),
        "an ask erases nothing"
    );
}

/// An artifact the owner `memory` writes: the record the erase cases erase.
fn artifact(memory: &Memory<'_>) -> EntityId {
    let put = memory
        .put_blob_artifact(&BlobArtifactInput {
            id: None,
            name: "erase fixture".to_owned(),
            media_type: "text/plain".to_owned(),
            occurred_at: 1,
            learned_at: None,
        })
        .expect("the owner writes an artifact");
    EntityId::from_hex(&put.id_hex).expect("an artifact id")
}

/// The owner previews the erase of `record`, then confirms it on
/// `owner_proof`, naming `check_in_ref` when given.
fn erase(
    memory: &Memory<'_>,
    owner_proof: &AuthenticatedOwner,
    record: EntityId,
    check_in_ref: Option<&str>,
) -> RecordEraseOutcome {
    let preview = preview_record_erase(memory, RecordEraseRequest { record })
        .expect("the owner previews the erase");
    confirm_record_erase(
        memory,
        owner_proof,
        RecordEraseConfirmRequest {
            record,
            preview_digest: preview.preview_digest,
            also_same_bytes: false,
            check_in_ref: check_in_ref.map(str::to_owned),
        },
    )
    .expect("the owner confirms the erase")
}

/// The decision of an Owner's erase on their own proof, applying
/// `check_in` asked by `requester` when given.
fn owner_erase(check_in: Option<String>, requester: Option<String>) -> Option<CheckInDecision> {
    Some(CheckInDecision {
        act_class: "erase".to_owned(),
        role: "owner".to_owned(),
        mode: None,
        basis: "own_proof".to_owned(),
        check_in,
        requester,
    })
}

/// The shared vault with its workspace house bound at Deputy, and the
/// owner's Grant to the house naming the vault delete and the erase.
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
        let (vault, owner, owner_proof, issuer) = rooted(&dir);
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
                b"check-in destructive org",
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
            ["read", VAULT_DELETE, ERASE, "vault.members.remove"]
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
            "a Deputy always asks the Owner on a catastrophe row: {opened}"
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
}

#[test]
fn an_owners_delete_records_its_own_proof() {
    let fx = DeputyHouse::new();
    let act = fx
        .vault
        .propose_delete_vault(&fx.owner_proof, SHARED)
        .expect("the owner starts the delete");
    assert_eq!(
        act.check_in,
        Some(CheckInDecision {
            act_class: "vault_delete".to_owned(),
            role: "owner".to_owned(),
            mode: None,
            basis: "own_proof".to_owned(),
            check_in: None,
            requester: None,
        }),
        "the act records that the Owner went on their own proof"
    );
}

#[test]
fn the_owner_applies_a_deputys_approved_delete_on_their_own_proof() {
    let fx = DeputyHouse::new();
    let digest = vault_delete_effect_digest(SHARED);
    let delete = fx.open(VAULT_DELETE, &digest);
    let delete_id = EntityId::from_hex(&delete).expect("a check-in id");

    let early =
        fx.vault
            .propose_delete_vault_with_check_in(&fx.owner_proof, SHARED, Some(delete_id));
    assert!(
        early.is_err(),
        "the owner has not answered: the ref starts nothing: {early:?}"
    );

    // A check-in for another act is no approval of the delete.
    let other_digest = [0x5a; 32];
    let other = fx.open("vault.members.remove", &other_digest);
    fx.approve(&other, &other_digest);
    let wrong = fx.vault.propose_delete_vault_with_check_in(
        &fx.owner_proof,
        SHARED,
        Some(EntityId::from_hex(&other).expect("a check-in id")),
    );
    assert!(
        wrong.is_err(),
        "another act's check-in starts nothing: {wrong:?}"
    );

    fx.approve(&delete, &digest);
    let act = fx
        .vault
        .propose_delete_vault_with_check_in(&fx.owner_proof, SHARED, Some(delete_id))
        .expect("the owner applies the approved delete");
    assert_eq!(
        act.check_in,
        Some(CheckInDecision {
            act_class: "vault_delete".to_owned(),
            role: "owner".to_owned(),
            mode: None,
            basis: "own_proof".to_owned(),
            check_in: Some(delete),
            requester: Some(fx.house.to_hex()),
        }),
        "the act names the check-in it applied and the house that asked"
    );
    assert_eq!(act.starter, fx.owner.to_hex(), "the owner starts the act");
    assert!(
        fx.vault
            .pending_check_in(&delete_id)
            .expect("read the check-in")
            .expect("stored")
            .consumed_at
            .is_some(),
        "the start spent the check-in"
    );
    let again =
        fx.vault
            .propose_delete_vault_with_check_in(&fx.owner_proof, SHARED, Some(delete_id));
    assert!(again.is_err(), "a spent check-in applies once: {again:?}");
}

#[test]
fn the_owner_applies_a_deputys_approved_erase_on_their_own_proof() {
    let fx = DeputyHouse::new();
    let memory = fx.vault.memory(fx.owner, EdgeActorClass::Human);
    let record = artifact(&memory);
    let digest = record_erase_effect_digest(&record, false);
    let asked = fx.open(ERASE, &digest);
    fx.approve(&asked, &digest);
    let outcome = erase(&memory, &fx.owner_proof, record, Some(&asked));
    assert_eq!(
        outcome.first.reason, "owner_erase",
        "a sole Owner's erase runs at once: {outcome:?}"
    );
    assert_eq!(
        outcome.check_in,
        owner_erase(Some(asked.clone()), Some(fx.house.to_hex())),
        "the outcome names the check-in it applied and the house that asked"
    );
    assert!(
        fx.vault
            .pending_check_in(&EntityId::from_hex(&asked).expect("a check-in id"))
            .expect("read the check-in")
            .expect("stored")
            .consumed_at
            .is_some(),
        "the confirm spent the check-in"
    );
}

#[test]
fn an_erase_held_by_the_veto_window_records_its_decision_on_its_act() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (vault, owner, owner_proof, _issuer) = rooted(&dir);
    let second = EntityId::now();
    person(&vault, second);
    let member = |member_ref| InitialSharedMember {
        member_ref,
        role: Some(Role::Owner),
    };
    vault
        .initialize_shared_vault(
            &owner_proof,
            SHARED,
            None,
            &[member(owner), member(second)],
            1,
        )
        .expect("a shared vault with two Owners");
    let second_proof = proof(&vault, second);
    let invitation = vault
        .shared_invitations(&second_proof, SHARED)
        .expect("invitations")
        .into_iter()
        .find(|open| open.role == Role::Owner)
        .expect("the founding invitation");
    vault
        .accept_shared_invitation(&second_proof, SHARED, &invitation.id)
        .expect("the second Owner accepts");
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let record = artifact(&memory);
    let outcome = erase(&memory, &owner_proof, record, None);
    let act_id = outcome
        .first_act
        .clone()
        .unwrap_or_else(|| panic!("two Owners: the erase waits on its act: {outcome:?}"));
    let act = vault
        .pending_authority_act(&act_id)
        .expect("read the act")
        .expect("the act is stored");
    assert_eq!(
        act.check_in,
        owner_erase(None, None),
        "the erase act records that the Owner went on their own proof"
    );
    assert_eq!(outcome.check_in, act.check_in, "the outcome says the same");
}
