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
//! An engine-default row no act gives reads only for the verbs in the meet with its agent's
//! Steward reach, the meet every Steward use reads (Engine RULING
//! R4-DEFAULT-END-AFTER-WHOLE-REVOKE = C). Before it, a default-shape row put after the owner
//! revoked the Dreamer's Grant whole, or narrowed it, read with every default verb at each fold
//! reader. The engine's own default still reads with its default verbs before any revoke.
//! The meet holds the data axes too (FIX ENGINE-DEFAULT-DERIVED-LIMITS (b)): a default-shape
//! row reaches no record the agent's standing rows do not reach together.
//!
//! Runs on public paths and the test doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features
//! --test derived_grant_standing`.
#![cfg(all(feature = "sync", feature = "test-support", oneiron_test_support))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;

use oneiron::authority::HostSlipIssuer;
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{
    EngineControlActor, EngineControlClass, FederationGrant, FederationGrantPreset as Preset,
    FederationGrantRole as Role, FederationGrantScope, InitialSharedMember, ScopeAxis,
    SystemAgentGrantNarrowing, own_device_residence_scope,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::sync::{SyncSelector, SyncSelectorWorld, authorize_sync_selector};
use oneiron::temporal::TimeRange;
use oneiron::test_doors::coach::{
    ENGINE_CONTROLS_WORK_BUDGET_VERB, coach, read_and_engine_controls,
};
use oneiron::test_doors::derive::narrow_steward_grant_to_project;
use oneiron::test_doors::grant_act::put_unkeyed_member_grant;
use oneiron::test_doors::grant_standing::{
    grant_row_scope, grant_row_verbs, selector_export_scope, shared_vault_grant_ids,
};
use oneiron::test_doors::steward::{
    STEWARD_READ_VERB, STEWARD_VERBS, dreamer, open_owner_carrier_vault, receive_steward_grant_row,
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

/// A personal vault whose install carries acts, its owner and the Dreamer, with the engine's
/// default Steward Grants stood as a host's first open stands them.
fn defaults_vault() -> (tempfile::TempDir, Vault, EntityId, EntityId) {
    let (dir, vault, _, owner) = carrier_vault();
    let dreamer = dreamer(&vault).expect("the Dreamer");
    vault
        .provision_system_agent_grants()
        .expect("the host's first open");
    (dir, vault, owner, dreamer)
}

/// `owner` narrows the Dreamer's Grant to `keep` (none revokes it whole), confirming what
/// breaks when the door asks.
fn narrow_dreamer(vault: &Vault, owner: EntityId, dreamer: EntityId, keep: &[&str]) {
    let owner = proof(vault, owner);
    let keep: BTreeSet<String> = keep.iter().map(|verb| (*verb).to_owned()).collect();
    let confirm = match vault
        .narrow_system_agent_grant(&owner, dreamer, &keep, None)
        .expect("narrowing")
    {
        SystemAgentGrantNarrowing::ConfirmRequired { confirm, .. } => confirm,
        SystemAgentGrantNarrowing::Narrowed { .. } => return,
        SystemAgentGrantNarrowing::Unchanged => panic!("the narrowing takes a verb"),
    };
    assert!(matches!(
        vault
            .narrow_system_agent_grant(&owner, dreamer, &keep, Some(confirm))
            .expect("confirmed narrowing"),
        SystemAgentGrantNarrowing::Narrowed { .. }
    ));
}

fn sorted(verbs: &[&str]) -> Vec<String> {
    let verbs: BTreeSet<String> = verbs.iter().map(|verb| (*verb).to_owned()).collect();
    verbs.into_iter().collect()
}

#[test]
fn a_default_shape_row_put_after_the_owners_whole_revoke_stands_for_nothing() {
    let (_dir, vault, owner, dreamer) = defaults_vault();
    narrow_dreamer(&vault, owner, dreamer, &[]);
    let forged = receive_steward_grant_row(&vault, dreamer, &STEWARD_VERBS).expect("the row lands");

    assert_eq!(
        grant_row_verbs(&vault, forged).expect("the fold reader"),
        None,
        "after the owner's whole revoke the opt-out's row gives no verb, so a default-shape row \
         put after it stands for nothing"
    );
    assert!(
        !residence_selector_authorized(&vault, forged, dreamer),
        "the row backs no selector either"
    );
    assert!(
        vault
            .engine_default_grants(&proof(&vault, owner))
            .expect("the engine-defaults door")
            .iter()
            .all(|(grant, _)| *grant != forged),
        "the engine-defaults door shows the owner no such Grant"
    );
}

#[test]
fn a_default_shape_row_put_after_a_narrowing_reads_only_the_kept_verbs() {
    let (_dir, vault, owner, dreamer) = defaults_vault();
    narrow_dreamer(&vault, owner, dreamer, &[STEWARD_READ_VERB]);
    let forged = receive_steward_grant_row(&vault, dreamer, &STEWARD_VERBS).expect("the row lands");

    assert_eq!(
        grant_row_verbs(&vault, forged).expect("the fold reader"),
        Some(sorted(&[STEWARD_READ_VERB])),
        "a row no act gives only narrows the meet: it reads no verb the owner took back"
    );
}

#[test]
fn a_default_shape_row_put_over_the_shared_vault_after_the_whole_revoke_stands_for_nothing() {
    let (_dir, vault, owner, dreamer) = defaults_vault();
    narrow_dreamer(&vault, owner, dreamer, &[]);
    share_with(&vault, owner, EntityId::now(), Role::Member);
    let mut grant = FederationGrant::new(
        FederationGrantScope::vault(SHARED),
        dreamer,
        Role::Steward,
        Preset::Steward,
    );
    grant.authority_scope.verbs = STEWARD_VERBS
        .iter()
        .map(|verb| (*verb).to_owned())
        .collect();
    let forged = EntityId::now();
    put_unkeyed_member_grant(&vault, forged, &grant).expect("the row lands");

    assert_eq!(
        grant_row_verbs(&vault, forged).expect("the fold reader"),
        None,
        "the shared scope's reader holds the meet too"
    );
    assert!(
        !shared_vault_grant_ids(&vault, SHARED)
            .expect("the membership census")
            .contains(&forged),
        "the membership census reads no standing for the row"
    );
}

/// Guard: before any revoke the engine's default row reads with its default verbs.
#[test]
fn the_engine_default_row_reads_with_its_default_verbs_before_any_revoke() {
    let (_dir, vault, owner, dreamer) = defaults_vault();
    let (default, verbs) = vault
        .engine_default_grants(&proof(&vault, owner))
        .expect("the engine-defaults door")
        .into_iter()
        .find(|(_, receipt)| receipt.agent == dreamer)
        .map(|(grant, receipt)| (grant, receipt.verbs.into_iter().collect::<Vec<_>>()))
        .expect("the engine stood the Dreamer's default");

    assert!(!verbs.is_empty(), "the default gives the Dreamer verbs");
    assert_eq!(
        grant_row_verbs(&vault, default).expect("the fold reader"),
        Some(verbs),
        "the engine's default row reads with the verbs it was stood with"
    );
}

/// The Dreamer's engine-default Grant, as its receipt names it, and the verbs it was stood with.
fn dreamer_default(vault: &Vault, owner: EntityId, dreamer: EntityId) -> (EntityId, Vec<String>) {
    vault
        .engine_default_grants(&proof(vault, owner))
        .expect("the engine-defaults door")
        .into_iter()
        .find(|(_, receipt)| receipt.agent == dreamer)
        .map(|(grant, receipt)| (grant, receipt.verbs.into_iter().collect()))
        .expect("the engine stood the Dreamer's default")
}

#[test]
fn a_default_shape_row_reaches_no_record_the_agents_standing_rows_do_not_reach() {
    let (_dir, vault, owner, dreamer) = defaults_vault();
    let (default, _) = dreamer_default(&vault, owner, dreamer);
    narrow_steward_grant_to_project(&vault, default, EntityId::now())
        .expect("the default row held to one project");
    let held = grant_row_scope(&vault, default)
        .expect("the fold reader")
        .expect("the default row stands")
        .audience;
    assert_ne!(held, ScopeAxis::All, "the default row holds one project");
    let forged = receive_steward_grant_row(&vault, dreamer, &STEWARD_VERBS).expect("the row lands");

    assert_eq!(
        grant_row_scope(&vault, forged)
            .expect("the fold reader")
            .map(|scope| scope.audience),
        Some(held),
        "a row no act gives reaches only the projects the agent's standing rows reach together"
    );
}

/// Catches a door that asks only whether a row stands, then judges by the stored row's own
/// scope (review r4c P2-1): the sync selector export filters a default-shape row no act gives
/// by the projects the agent's standing rows reach together, not by the row's whole axes.
#[test]
fn the_selector_export_reads_a_default_shape_row_within_the_agents_reach() {
    let (_dir, vault, owner, dreamer) = defaults_vault();
    let (default, _) = dreamer_default(&vault, owner, dreamer);
    narrow_steward_grant_to_project(&vault, default, EntityId::now())
        .expect("the default row held to one project");
    let held = grant_row_scope(&vault, default)
        .expect("the fold reader")
        .expect("the default row stands")
        .audience;
    assert_ne!(
        held,
        ScopeAxis::All,
        "FIXTURE: the default row holds one project"
    );
    let forged = receive_steward_grant_row(&vault, dreamer, &STEWARD_VERBS).expect("the row lands");

    assert_eq!(
        selector_export_scope(&vault, forged)
            .expect("the row backs the export filter")
            .audience,
        held,
        "the export filters a row no act gives by the projects the agent's standing rows reach"
    );
}
