//! Own-device and engine-default Grants read as derived (pass 28 R4; FIX
//! GRANT-UNACTED-ARM-WIDER-THAN-DERIVED, ENGINE-DEFAULT-GRANT-NO-ACT).
//!
//! No act gives either kind. An own-device Grant stands while the fold names its holder a
//! live Owner of the vault; a base agent's Steward Grant stands while it holds no more than
//! the build's default table gives that agent. Before R4 every row over the own-device
//! residence that no counted act named read from itself: a member row put with no act, an
//! own-device row for a person who owns nothing, and a base agent's Steward row beyond its
//! default all conferred. The owner's own-device row and the Coach's default Steward row
//! still do.
//!
//! Runs on public paths and the test doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features
//! --test derived_grant_standing`.
#![cfg(all(feature = "sync", feature = "test-support", oneiron_test_support))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::authority::HostSlipIssuer;
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{
    EngineControlActor, EngineControlClass, FederationGrant, FederationGrantPreset as Preset,
    FederationGrantRole as Role, InitialSharedMember, own_device_residence_scope,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::sync::{SyncSelector, SyncSelectorWorld, authorize_sync_selector};
use oneiron::temporal::TimeRange;
use oneiron::test_doors::coach::{
    ENGINE_CONTROLS_WORK_BUDGET_VERB, coach, read_and_engine_controls,
};
use oneiron::test_doors::grant_act::put_unkeyed_member_grant;
use oneiron::test_doors::steward::{
    STEWARD_READ_VERB, dreamer, open_owner_carrier_vault, receive_steward_grant_row,
};
use oneiron::test_support::provision_act_carrier;
use oneiron::{EntityId, Vault, VaultConfig};

const SHARED: u64 = 42;

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

/// A fresh personal vault whose install carries acts, and its owner.
fn carrier_vault() -> (tempfile::TempDir, Vault, HostSlipIssuer, EntityId) {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault");
    let (issuer, owner) = provision_act_carrier(&vault);
    (dir, vault, issuer, owner)
}

/// `owner` shares the vault as its Owner, and `member` accepts its founding invitation at
/// `role`.
fn share_with(vault: &Vault, owner: EntityId, member: EntityId, role: Role) {
    person(vault, member);
    vault
        .initialize_shared_vault(
            &proof(vault, owner),
            SHARED,
            None,
            &[
                InitialSharedMember {
                    member_ref: owner,
                    role: Some(Role::Owner),
                },
                InitialSharedMember {
                    member_ref: member,
                    role: Some(role),
                },
            ],
            vault.now_recorded_at(),
        )
        .expect("a shared vault");
    let member_proof = proof(vault, member);
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

/// A row over the own-device residence for `holder` at `role`, put with no act: its id.
fn residence_row(vault: &Vault, holder: EntityId, role: Role, preset: Preset) -> EntityId {
    let grant = FederationGrant::new(own_device_residence_scope(), holder, role, preset);
    let id = EntityId::now();
    put_unkeyed_member_grant(vault, id, &grant).expect("the row lands");
    id
}

/// Whether the residence selector under Grant `grant`, held by `holder`, is authorized.
fn residence_selector_authorized(vault: &Vault, grant: EntityId, holder: EntityId) -> bool {
    let selector = SyncSelector::new(
        grant,
        holder,
        SyncSelectorWorld::All,
        Vec::new(),
        Vec::new(),
    );
    authorize_sync_selector(vault, own_device_residence_scope(), &selector).is_ok()
}

#[test]
fn a_member_row_over_the_residence_that_no_act_gives_backs_no_selector() {
    let (_dir, vault, _, _) = carrier_vault();
    let stranger = EntityId::now();
    person(&vault, stranger);
    let id = residence_row(&vault, stranger, Role::Member, Preset::Member);

    assert!(
        !residence_selector_authorized(&vault, id, stranger),
        "a member row over the own-device residence that no act gives backs no selector"
    );
}

#[test]
fn an_own_device_row_for_a_person_who_owns_nothing_backs_no_selector() {
    let (_dir, vault, _, _) = carrier_vault();
    let stranger = EntityId::now();
    person(&vault, stranger);
    let id = residence_row(&vault, stranger, Role::Owner, Preset::Owner);

    assert!(
        !residence_selector_authorized(&vault, id, stranger),
        "an own-device row stands only while its holder is a live Owner of the vault"
    );
}

/// Guard: the owner's own-device row, which no act gives, backs the owner's selector.
#[test]
fn the_owners_own_device_row_backs_his_selector() {
    let (_dir, vault, _, owner) = carrier_vault();
    let id = residence_row(&vault, owner, Role::Owner, Preset::Owner);

    assert!(
        residence_selector_authorized(&vault, id, owner),
        "the live owner's own-device row backs his residence selector"
    );
}

#[test]
fn an_own_device_row_for_a_member_who_is_no_owner_backs_no_selector() {
    let (_dir, vault, _, owner) = carrier_vault();
    let member = EntityId::now();
    share_with(&vault, owner, member, Role::Member);
    let id = residence_row(&vault, member, Role::Owner, Preset::Owner);

    assert!(
        !residence_selector_authorized(&vault, id, member),
        "an own-device row for a member who is no Owner of the shared vault backs no selector"
    );
}

/// Guard: once the vault is shared, the owner's own-device row stands on the shared vault's
/// owner set.
#[test]
fn the_owners_own_device_row_keeps_his_selector_once_he_shares() {
    let (_dir, vault, _, owner) = carrier_vault();
    let id = residence_row(&vault, owner, Role::Owner, Preset::Owner);
    share_with(&vault, owner, EntityId::now(), Role::Member);

    assert!(
        residence_selector_authorized(&vault, id, owner),
        "a live Owner of the shared vault keeps his own-device row's selector"
    );
}

fn allowed(vault: &Vault, holder: EntityId, class: EngineControlClass) -> bool {
    vault
        .engine_control_allowed(EngineControlActor::Holder(holder), class)
        .expect("check")
}

#[test]
fn a_base_agents_steward_row_beyond_its_default_table_gives_no_engine_control() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_owner_carrier_vault(dir.path()).expect("owner carrier vault");
    let dreamer = dreamer(&vault).expect("the Dreamer");
    receive_steward_grant_row(
        &vault,
        dreamer,
        &[STEWARD_READ_VERB, ENGINE_CONTROLS_WORK_BUDGET_VERB],
    )
    .expect("the row lands");

    assert!(
        !allowed(&vault, dreamer, EngineControlClass::WorkBudget),
        "no default table gives the Dreamer an engine.controls class, so a row that names one \
         stands for nothing"
    );
}

/// Guard: the Coach's default Steward row, which no act gives, tunes the engine.
#[test]
fn the_coachs_default_steward_row_gives_its_engine_controls() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_owner_carrier_vault(dir.path()).expect("owner carrier vault");
    let coach = coach(&vault).expect("the Coach");
    receive_steward_grant_row(&vault, coach, &read_and_engine_controls()).expect("the row lands");

    assert!(
        allowed(&vault, coach, EngineControlClass::WorkBudget),
        "the Coach's default Steward row gives its engine.controls classes"
    );
}
