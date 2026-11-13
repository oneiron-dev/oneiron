//! Who may demote another actor's graduated ramp scope (census L7-33; FIX
//! 22934; Engine RULING L7-33-WHO = A, Fri 13 Nov 18:06 JST). Demotion
//! narrows, and ARCH-0082 `#changing` rules that narrowing is delegation:
//! "Tighten or loosen a row for an act you hold: a policy holder ..., own
//! proof, lands at once". So a policy holder (the vault owner, or an Admin or
//! Delegate whose Owner-minted `policy.change` grant names the demotion
//! target) demotes under its own person proof. A role label alone demotes
//! nothing, and a Member without the power is refused. "Tighten a child's
//! row ...: the parent or grantor, nothing": the agent whose run spawned a
//! child demotes the child's scope on its own facade, and another agent may
//! not. Re-graduation stays the owner's tap.
//!
//! Every demotion receipt names who demoted in its `demoted_by` field (Engine
//! RULING NEXT-ROW-8 = A, Fri 13 Nov 19:21 JST; FIX 24090): the owner, the
//! policy holder, the spawning parent, the scope's own actor, or the person
//! whose ruling caused it. The receipt's `actor` stays the scope's.
//!
//! The shipped grant rows give the `policy.change` verb to no role, so the
//! owner first lets the Admin role carry it, and a run spawns its child
//! through the dispatcher, both through the hidden doors in
//! `oneiron::test_doors::consent_graduation_demotion`, built only under
//! `--cfg oneiron_test_support`; every assertion is here. Without that cfg
//! this target is empty. Run:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test -p oneiron
//! --all-features --test graduated_scope_demotion_authors`.
#![cfg(oneiron_test_support)]

use oneiron::consent::{ActionClass, ActionEnvelope, ActorBound, AuthenticatedOwner, GrantBound};
use oneiron::consent_graduation::{
    DemotionReason, RAMP_DEMOTE_GRANT_TARGET, RampScope, RampState, is_ramp_demotion_receipt,
};
use oneiron::federation::{FederationGrantRole as Role, InitialSharedMember};
use oneiron::identity_topology::ProposalOutcome;
use oneiron::receipt::{ReceiptKind, ReceiptQuery};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::temporal::TimeRange;
use oneiron::test_doors::consent_graduation_demotion as doors;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};

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

/// The vault's people: its embedded owner, an Admin and a Member, each of
/// whom has accepted a founding invitation into shared vault [`SHARED`]. The
/// owner's grant rows let the Admin role carry the `policy.change` verb, so
/// the Admin holds the policy power once a grant names its target.
struct Roster {
    owner: EntityId,
    admin: EntityId,
    member: EntityId,
}

fn shared_roster(vault: &Vault) -> Roster {
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    doors::admit_policy_verb(vault, &proof(vault, owner), &[Role::Admin])
        .expect("the owner lets an Admin carry the policy verb");
    let admin = EntityId::now();
    let member = EntityId::now();
    person(vault, admin);
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
                    member_ref: admin,
                    role: Some(Role::Admin),
                },
                InitialSharedMember {
                    member_ref: member,
                    role: Some(Role::Member),
                },
            ],
            1,
        )
        .expect("a shared vault with an Admin and a Member");
    for (person, role) in [(admin, Role::Admin), (member, Role::Member)] {
        let own = proof(vault, person);
        let invitation = vault
            .shared_invitations(&own, SHARED)
            .expect("the person's invitations")
            .into_iter()
            .find(|open| open.role == role)
            .expect("the person's founding invitation");
        vault
            .accept_shared_invitation(&own, SHARED, &invitation.id)
            .expect("the person accepts");
    }
    Roster {
        owner,
        admin,
        member,
    }
}

/// The owner mints `holder` the vault-scope policy power over the ramp
/// demotion: a `policy.change` standing grant whose target is
/// [`RAMP_DEMOTE_GRANT_TARGET`].
fn grant_demotion_power(vault: &Vault, owner: EntityId, holder: EntityId) {
    let bound = GrantBound::action(
        ActorBound::new(holder.to_hex())
            .and_then(|bound| bound.with_actor_class("human"))
            .expect("the holder's bound"),
        ActionClass::new("policy.change").expect("the policy class"),
        ActionEnvelope::new(["owner_policy_rows".to_owned()])
            .and_then(|envelope| envelope.with_target(RAMP_DEMOTE_GRANT_TARGET))
            .expect("the demotion target"),
    )
    .expect("the policy grant bound");
    vault
        .create_standing_grant(&proof(vault, owner), bound)
        .expect("the owner mints the policy power");
}

/// An agent's scope the owner has graduated: its standing grant is live.
fn graduated_scope(vault: &Vault, owner: EntityId, agent: &str) -> RampScope {
    let scope = RampScope::new("send_email", "client_followup", agent).expect("scope");
    vault
        .create_standing_grant(
            &proof(vault, owner),
            scope.to_grant_bound().expect("the scope's bound"),
        )
        .expect("the owner graduates the scope");
    assert_eq!(
        vault.ramp_scope_state(&scope).expect("state"),
        RampState::Graduated
    );
    scope
}

fn grant_is_live(vault: &Vault, scope: &RampScope) -> bool {
    let grant_ref = scope.grant_ref().expect("grant ref");
    vault
        .consent_grant(&grant_ref)
        .expect("grant row")
        .is_some_and(|row| row.is_active())
}

/// One demotion receipt on the public receipt query: the scope's actor, the
/// revoked grant, and who demoted.
#[derive(Debug, PartialEq, Eq)]
struct Demotion {
    actor: Option<String>,
    grant_ref: Option<String>,
    demoted_by: Option<String>,
}

fn demotion_receipts(vault: &Vault) -> Vec<Demotion> {
    vault
        .receipts(ReceiptQuery::default().with_kind(ReceiptKind::Gate))
        .expect("receipts")
        .into_iter()
        .filter(is_ramp_demotion_receipt)
        .map(|record| Demotion {
            actor: record.actor.clone(),
            // The receipt fields' wire keys (oneiron_store::receipt_row::FIELD_GRANT_REF,
            // oneiron::store::receipt_row::FIELD_DEMOTED_BY).
            grant_ref: record.fields.get("grant_ref").cloned(),
            demoted_by: record.fields.get("demoted_by").cloned(),
        })
        .collect()
}

/// The receipt one demotion of `scope` by `demoter` writes.
fn demotion_by(scope: &RampScope, demoter: EntityId) -> Demotion {
    Demotion {
        actor: Some(scope.actor.clone()),
        grant_ref: Some(scope.grant_ref().expect("grant ref")),
        demoted_by: Some(demoter.to_hex()),
    }
}

/// An Admin whose Owner-minted grant names the demotion target demotes an
/// agent's graduated scope under its own person proof: the standing grant is
/// revoked, the demotion receipt names the scope, the grant and the Admin as
/// its demoter, and the scope rides the propose lane again. Red on main: the
/// door took the owner's proof only, so the Admin was refused as a non-owner.
/// Red on #7504's head: the receipt named no demoter.
#[test]
fn a_policy_holder_demotes_an_agents_graduated_scope() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("vault");
    let roster = shared_roster(&vault);
    grant_demotion_power(&vault, roster.owner, roster.admin);
    let agent = EntityId::now().to_hex();
    let scope = graduated_scope(&vault, roster.owner, &agent);

    vault
        .demote_scope_to_propose(
            &proof(&vault, roster.admin),
            &scope,
            DemotionReason::Rejected,
        )
        .expect("a policy holder demotes another actor's graduated scope");

    assert!(
        !grant_is_live(&vault, &scope),
        "the demotion revokes the scope's standing grant"
    );
    assert_ne!(
        vault.ramp_scope_state(&scope).expect("state"),
        RampState::Graduated
    );
    assert_eq!(
        demotion_receipts(&vault),
        vec![demotion_by(&scope, roster.admin)],
        "one demotion receipt, naming the scope's actor, the revoked grant and the Admin"
    );
}

/// Neither a Member nor an Admin that carries the policy verb but holds no
/// grant naming the demotion target holds the power: each is refused, the
/// grant stays live, and no demotion receipt is written. The owner's own
/// demotion still lands, and its receipt names the owner as the demoter.
#[test]
fn a_person_without_the_policy_power_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("vault");
    let roster = shared_roster(&vault);
    let agent = EntityId::now().to_hex();
    let scope = graduated_scope(&vault, roster.owner, &agent);

    for (who, person) in [
        ("a Member", roster.member),
        ("an Admin with no grant naming the target", roster.admin),
    ] {
        let refused =
            vault.demote_scope_to_propose(&proof(&vault, person), &scope, DemotionReason::Rejected);
        assert!(refused.is_err(), "{who} must not demote: {refused:?}");
        assert!(
            grant_is_live(&vault, &scope),
            "{who}'s refusal leaves the grant"
        );
        assert!(
            demotion_receipts(&vault).is_empty(),
            "{who}'s refusal writes no receipt"
        );
    }

    vault
        .demote_scope_to_propose(
            &proof(&vault, roster.owner),
            &scope,
            DemotionReason::Rejected,
        )
        .expect("the owner demotes, as before");
    assert!(!grant_is_live(&vault, &scope));
    assert_eq!(
        demotion_receipts(&vault),
        vec![demotion_by(&scope, roster.owner)],
        "one demotion receipt, naming the owner as the demoter"
    );
}

/// The agent whose run spawned a child demotes the child's graduated scope
/// on its own facade, with no owner proof: the grant is revoked and the
/// demotion receipt names the parent as the demoter. The child is the
/// attenuated fork the
/// dispatcher minted for the parent's run, pinned to it by the engine. Before
/// that, a sibling agent no pin ties to the child is refused and changes
/// nothing. Red on main: an actor demoted only its own scope there, so the
/// parent was refused too.
#[test]
fn a_parent_agent_demotes_its_spawned_childs_graduated_scope() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("vault");
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let parent = doors::define_agent(&vault, "ramp parent").expect("the parent agent");
    let sibling = doors::define_agent(&vault, "ramp sibling").expect("a sibling agent");
    let child = doors::spawn_attenuated_child(&vault, parent).expect("the parent spawns a child");
    let scope = graduated_scope(&vault, owner, &child.to_hex());

    let refused = vault
        .memory(sibling, EdgeActorClass::Agent)
        .demote_own_ramp_scope(&scope);
    assert!(
        refused.is_err(),
        "an agent must not strip another agent's earned lane: {refused:?}"
    );
    assert!(
        grant_is_live(&vault, &scope),
        "the refusal leaves the grant"
    );
    assert!(
        demotion_receipts(&vault).is_empty(),
        "the refusal writes no receipt"
    );

    vault
        .memory(parent, EdgeActorClass::Agent)
        .demote_own_ramp_scope(&scope)
        .expect("the parent demotes its spawned child's scope with no owner proof");
    assert!(
        !grant_is_live(&vault, &scope),
        "the demotion revokes the child's standing grant"
    );
    assert_eq!(
        demotion_receipts(&vault),
        vec![demotion_by(&scope, parent)],
        "one demotion receipt, naming the child's scope, the revoked grant and the parent"
    );
}

/// An agent that steps its own graduated scope back is named as its own
/// demoter.
#[test]
fn an_agents_own_demotion_names_the_agent() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("vault");
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let agent = doors::define_agent(&vault, "ramp self").expect("an agent");
    let scope = graduated_scope(&vault, owner, &agent.to_hex());

    vault
        .memory(agent, EdgeActorClass::Agent)
        .demote_own_ramp_scope(&scope)
        .expect("an agent demotes its own scope");
    assert!(!grant_is_live(&vault, &scope));
    assert_eq!(
        demotion_receipts(&vault),
        vec![demotion_by(&scope, agent)],
        "one demotion receipt, naming the agent as its own demoter"
    );
}

/// The owner's rejecting ruling in a graduated scope demotes it, and the
/// demotion receipt names the owner who ruled.
#[test]
fn an_owners_rejecting_ruling_names_the_owner_as_the_demoter() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("vault");
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let agent = EntityId::now().to_hex();
    let scope = graduated_scope(&vault, owner, &agent);

    vault
        .record_proposal_outcome_for_ramp(&proof(&vault, owner), &scope, ProposalOutcome::Rejected)
        .expect("the owner rules");
    assert!(
        !grant_is_live(&vault, &scope),
        "a rejection in a graduated scope demotes it"
    );
    assert_eq!(
        demotion_receipts(&vault),
        vec![demotion_by(&scope, owner)],
        "one demotion receipt, naming the owner whose ruling demoted"
    );
}
