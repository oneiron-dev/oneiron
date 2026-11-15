//! A removed shared owner's statement names no owner once its row stands for nothing
//! (R2d review finding 2).
//!
//! On a shared vault the statement's person counts as owner only while one of their Owner
//! rows stands on its counted giving. A bare Owner row put back after the owner was removed
//! names no owner, so a replicated row within that statement waits.
//!
//! Runs on public paths and the test doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features
//! --test agent_definition_shared_owner`.
#![cfg(all(feature = "sync", feature = "test-support", oneiron_test_support))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::agent_def::{AgentCeiling, AgentDefinition, AgentScope, encode_agent_definition};
use oneiron::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{
    FederationGrant, FederationGrantRole as Role, FederationGrantScope, InitialSharedMember,
    decode_federation_grant_body, decode_federation_grant_body_keyed,
};
use oneiron::registry::{ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_FEDERATION_GRANT, ENTITY_TYPE_PERSON};
use oneiron::store::GateDecisionId;
use oneiron::sync::FederationAdmissionRole;
use oneiron::sync::client::ImportTier;
use oneiron::sync::replay::{ReplicatedEntity, replay_entity};
use oneiron::temporal::TimeRange;
use oneiron::test_doors::grant_act::put_keyed_member_grant;
use oneiron::test_doors::grant_standing::{grant_row, standing_member_grant_act};
use oneiron::test_support::provision_act_carrier;
use oneiron::{EntityId, ErrorKind, Vault, VaultConfig};

const SHARED: u64 = 42;
const T0: u64 = 1_773_532_800;

fn at(ts: u64) -> TimeRange {
    TimeRange { start: ts, end: ts }
}

fn running_definition() -> AgentDefinition {
    AgentDefinition::new(
        "custom.revocable",
        "Shared owner fixture",
        "1.0.0",
        None,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        None,
        AgentScope::All,
        AgentCeiling::Proposed,
        None,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
        ClaimSource::UserStated,
        1.0,
        false,
        true,
        rmpv::Value::Map(vec![(
            rmpv::Value::from("definedVia"),
            rmpv::Value::from("shared owner fixture"),
        )]),
        None,
        true,
        None,
    )
}

fn next(
    definition: &AgentDefinition,
    version: &str,
    edit: impl FnOnce(&mut AgentDefinition),
) -> AgentDefinition {
    let mut next = definition.clone();
    next.version = version.to_owned();
    edit(&mut next);
    next
}

fn replay(
    vault: &Vault,
    id: &EntityId,
    definition: &AgentDefinition,
    tier: ImportTier,
) -> oneiron::Result<()> {
    let body = encode_agent_definition(definition).unwrap();
    replay_entity(
        vault,
        ReplicatedEntity {
            id: *id,
            entity_type: ENTITY_TYPE_AGENT_DEF,
            occurred: at(T0),
            learned_at: T0,
            row_version: 0,
            body: &body,
        },
        tier,
    )
}

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

/// `owner` shares the vault as its Owner and invites each of `invited` at its role.
fn share(vault: &Vault, owner: EntityId, invited: &[(EntityId, Role)]) {
    let mut members = vec![InitialSharedMember {
        member_ref: owner,
        role: Some(Role::Owner),
    }];
    members.extend(invited.iter().map(|(member, role)| InitialSharedMember {
        member_ref: *member,
        role: Some(*role),
    }));
    vault
        .initialize_shared_vault(
            &proof(vault, owner),
            SHARED,
            None,
            &members,
            vault.now_recorded_at(),
        )
        .expect("a shared vault");
}

/// `member` accepts its founding invitation at `role`.
fn accept(vault: &Vault, member: EntityId, role: Role) {
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

/// `member`'s membership Grant row in the shared vault: its id and terms.
fn member_row(vault: &Vault, member: EntityId) -> Option<(EntityId, FederationGrant)> {
    vault
        .entities_by_type(ENTITY_TYPE_FEDERATION_GRANT)
        .expect("grants")
        .into_iter()
        .find_map(|id| {
            let body = vault.get(&id).expect("grant row")?;
            let grant = decode_federation_grant_body(&body).ok()?;
            (grant.member_ref == member
                && grant.role != Role::Delegate
                && grant.scope == FederationGrantScope::vault(SHARED))
            .then_some((id, grant))
        })
}

/// The act row `id` stands on now as a member's Grant.
fn standing(vault: &Vault, id: EntityId) -> Option<[u8; 32]> {
    standing_member_grant_act(vault, id, vault.now_recorded_at()).expect("standing read")
}

/// The definition seeded running at `id`, then turned off by a federation member (a peer's
/// restrictive move lands).
fn revoked_at(vault: &Vault, id: EntityId) -> AgentDefinition {
    let running = running_definition();
    vault
        .put_agent_definition(&id, &running, at(T0), T0)
        .unwrap();
    let revoked = next(&running, "1.0.1", |def| {
        def.enabled = false;
        def.approval_status = ClaimApprovalStatus::Rejected;
        def.lifecycle_status = ClaimLifecycleStatus::Retracted;
    });
    replay(
        vault,
        &id,
        &revoked,
        ImportTier::Federated(FederationAdmissionRole::Member),
    )
    .expect("a peer turns a definition off");
    revoked
}

fn turned_on(revoked: &AgentDefinition) -> AgentDefinition {
    next(revoked, "1.0.2", |def| {
        def.enabled = true;
        def.approval_status = ClaimApprovalStatus::Approved;
        def.lifecycle_status = ClaimLifecycleStatus::Active;
    })
}

/// Catches the statement reader recognizing a removed shared owner from a bare membership row:
/// O1 stated the switches, O2 removed O1, O1's old Owner row was put back raw, and a
/// replicated row within O1's statement lands anyway.
#[test]
fn a_removed_owners_put_back_row_states_no_switches() {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault");
    let (issuer, owner) = provision_act_carrier(&vault);
    let o1 = EntityId::now();
    person(&vault, o1);
    share(&vault, owner, &[(o1, Role::Owner)]);
    accept(&vault, o1, Role::Owner);
    let (grant_id, _) = member_row(&vault, o1).expect("O1's grant");
    assert!(
        standing(&vault, grant_id).is_some(),
        "FIXTURE: O1's grant stands on its giving"
    );

    let id = EntityId::now();
    let revoked = revoked_at(&vault, id);
    let on = turned_on(&revoked);
    vault
        .update_agent_definition_as(&proof(&vault, o1), &id, &on, at(T0), T0)
        .expect("O1 states the switches");
    assert_eq!(
        vault.get_agent_definition(&id).unwrap(),
        Some(on.clone()),
        "FIXTURE: O1's turn-on lands"
    );
    let off = next(&on, "1.0.3", |def| def.enabled = false);
    replay(
        &vault,
        &id,
        &off,
        ImportTier::Federated(FederationAdmissionRole::Member),
    )
    .expect("FIXTURE: a peer turns the definition off again");
    let old_body = grant_row(&vault, grant_id)
        .expect("row read")
        .expect("the live Owner row");

    let owner_proof = proof(&vault, owner);
    let act = vault
        .propose_remove_owner(&owner_proof, SHARED, o1, None, None, false)
        .expect("O2 starts remove_owner");
    vault
        .execute_completed_shared_act(&owner_proof, &act.id, Some(&issuer))
        .expect("remove_owner runs");
    assert!(
        member_row(&vault, o1).is_none(),
        "FIXTURE: the removal drops O1's row"
    );
    let (old_grant, old_key) = decode_federation_grant_body_keyed(&old_body).expect("old body");
    let old_key = old_key.expect("the Owner row was keyed by its giving");
    put_keyed_member_grant(&vault, grant_id, &old_grant, &old_key).expect("the old row put back");
    assert_eq!(
        standing(&vault, grant_id),
        None,
        "FIXTURE: the put-back row stands for nothing"
    );

    let replayed = replay(&vault, &id, &on, ImportTier::OwnDevice);
    assert_eq!(
        replayed.as_ref().err().map(oneiron::Error::kind),
        Some(ErrorKind::InvalidAgentDefBody),
        "a row within a removed owner's statement waits: {replayed:?}"
    );
    assert_eq!(
        vault.get_agent_definition(&id).unwrap(),
        Some(off),
        "the stored row stays off"
    );
}
