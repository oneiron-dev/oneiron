//! A federation peer turns no agent definition back on. A member's or a
//! guest's row that re-enables, re-approves or reactivates a stored definition
//! is refused at window admission and at federated replay, as the peer's
//! bytes; the peer's restrictive moves land.
//!
//! An own machine's row turns a definition back on only within the switches
//! the vault's owner last stated on the authority log (Fable pass 28 R2d,
//! Engine RULING AGENT-DEF-OWN-LANE-FIX = B): at own-device replay and at an
//! own window's ingest, a row beyond them, or with no statement standing,
//! waits. The owner's door states the switches it turns on, and his own
//! turn-off replaces the statement.
#![cfg(feature = "sync")]
// Integration-test helpers (non-test fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used)]

use std::sync::Arc;

use loro::{ExportMode, LoroDoc};
use oneiron::agent_def::{AgentCeiling, AgentDefinition, AgentScope, encode_agent_definition};
use oneiron::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use oneiron::consent::AuthenticatedOwner;
use oneiron::registry::{ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_AUTHORITY_LOG};
use oneiron::store::GateDecisionId;
use oneiron::sync::bridge::{Materializer, register_observer_b};
use oneiron::sync::client::ImportTier;
use oneiron::sync::quarantine::{pending_remat_windows, quarantined_records};
use oneiron::sync::replay::{ReplicatedEntity, replay_entity};
use oneiron::sync::schema::create_window_doc;
use oneiron::sync::types::WindowKey;
use oneiron::sync::window::forward_rematerialize;
use oneiron::sync::{FederationAdmissionRole, admit_federated_window_update};
use oneiron::test_support::provision_act_carrier;
use oneiron::{EntityId, ErrorKind, Vault};

use crate::sync_harness::open_vault_with_memory_keystore;
use crate::sync_harness::{
    T0, WINDOW, clear_policy_manifests, entity_blob, map_insert_bytes, test_config, time_range,
};

fn running_definition() -> AgentDefinition {
    AgentDefinition::new(
        "custom.revocable",
        "Revocation fixture",
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
        // A stored definition names where it came from (a non-empty map).
        rmpv::Value::Map(vec![(
            rmpv::Value::from("definedVia"),
            rmpv::Value::from("it_sync fixture"),
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
            occurred: time_range(T0),
            learned_at: T0,
            row_version: 0,
            body: &body,
        },
        tier,
    )
}

fn admit(
    vault: &Vault,
    id: &EntityId,
    definition: &AgentDefinition,
    role: FederationAdmissionRole,
) -> oneiron::Result<Vec<(WindowKey, Vec<u8>)>> {
    let key = WindowKey::new(WINDOW);
    let peer = create_window_doc("federation-peer", &key);
    let body = encode_agent_definition(definition).unwrap();
    map_insert_bytes(
        &peer.get_map("entities"),
        &id.to_hex(),
        &entity_blob(ENTITY_TYPE_AGENT_DEF, time_range(T0), T0, &body),
    );
    peer.commit();
    let update = peer.export(ExportMode::all_updates()).unwrap();
    admit_federated_window_update(vault, &key, &update, role, None)
}

/// A fresh definition seeded running, then turned off by a federation
/// member: a peer's restrictive moves land.
fn revoked_definition(vault: &Vault) -> (EntityId, AgentDefinition) {
    let id = EntityId::now();
    (id, revoked_definition_at(vault, id))
}

/// [`revoked_definition`] at `id`.
fn revoked_definition_at(vault: &Vault, id: EntityId) -> AgentDefinition {
    let running = running_definition();
    vault
        .put_agent_definition(&id, &running, time_range(T0), T0)
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
    assert_eq!(
        vault.get_agent_definition(&id).unwrap(),
        Some(revoked.clone())
    );
    revoked
}

#[test]
fn a_federation_peer_turns_no_agent_definition_back_on() {
    let dir = tempfile::tempdir().unwrap();
    let vault = open_vault_with_memory_keystore(dir.path(), test_config());
    clear_policy_manifests(&vault);
    let widenings: [(&str, fn(&mut AgentDefinition)); 4] = [
        ("enabled", |def| def.enabled = true),
        ("re-proposed", |def| {
            def.approval_status = ClaimApprovalStatus::Proposed;
        }),
        ("approved", |def| {
            def.approval_status = ClaimApprovalStatus::Approved;
        }),
        ("active", |def| {
            def.lifecycle_status = ClaimLifecycleStatus::Active;
        }),
    ];
    let mut let_through = Vec::new();
    for role in [
        FederationAdmissionRole::Member,
        FederationAdmissionRole::Guest,
    ] {
        for (move_name, widen) in widenings {
            let (id, revoked) = revoked_definition(&vault);
            let widened = next(&revoked, "1.0.2", widen);
            let admitted = admit(&vault, &id, &widened, role).map(|_| ());
            let replayed = replay(&vault, &id, &widened, ImportTier::Federated(role));
            for (road, outcome) in [("window", admitted), ("replay", replayed)] {
                // Refused as the peer's bytes, so the frame quarantines.
                if outcome.as_ref().err().map(oneiron::Error::kind)
                    != Some(ErrorKind::InvalidAgentDefBody)
                {
                    let_through.push(format!("{role:?} {road} {move_name}: {outcome:?}"));
                }
            }
            if vault.get_agent_definition(&id).unwrap() != Some(revoked) {
                let_through.push(format!("{role:?} {move_name}: the stored row moved"));
            }
        }
    }
    assert!(
        let_through.is_empty(),
        "a federation peer turned a definition back on: {let_through:#?}"
    );

    // Pass 28 R2d: no owner statement stands, so an own machine's row turns
    // nothing back on either; it waits for one.
    let (id, revoked) = revoked_definition(&vault);
    let restored = next(&running_definition(), "1.0.3", |_| {});
    let replayed = replay(&vault, &id, &restored, ImportTier::OwnDevice);
    assert_eq!(
        replayed.as_ref().err().map(oneiron::Error::kind),
        Some(ErrorKind::InvalidAgentDefBody),
        "an own-device turn-on no owner stated waits: {replayed:?}"
    );
    assert_eq!(vault.get_agent_definition(&id).unwrap(), Some(revoked));
}

/// A vault whose install carries acts, and its owner's proof. The carrier
/// installs the vault's one keystore.
fn carrying_vault(dir: &std::path::Path) -> (Arc<Vault>, AuthenticatedOwner) {
    let vault = Arc::new(Vault::open(dir, test_config()).unwrap());
    clear_policy_manifests(&vault);
    let (_issuer, person) = provision_act_carrier(&vault);
    let owner = vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .unwrap();
    (vault, owner)
}

/// The owner's edit through his door, which states the switches it turns on.
fn owner_edit(vault: &Vault, owner: &AuthenticatedOwner, id: &EntityId, def: &AgentDefinition) {
    // What the door answers besides is the reach stem's (agent_definition_owner_reach.rs).
    let _reach = vault
        .update_agent_definition_as(owner, id, def, time_range(T0), T0)
        .expect("the owner's edit");
}

/// The authority log entries the vault holds.
fn authority_entries(vault: &Vault) -> u64 {
    vault
        .count_entities_by_type(ENTITY_TYPE_AUTHORITY_LOG)
        .unwrap()
}

/// `revoked` turned back on: enabled, approved, active.
fn turned_on(revoked: &AgentDefinition, version: &str) -> AgentDefinition {
    next(revoked, version, |def| {
        def.enabled = true;
        def.approval_status = ClaimApprovalStatus::Approved;
        def.lifecycle_status = ClaimLifecycleStatus::Active;
    })
}

/// Lands `definition` at `id` through an own window's ingest (Observer B over
/// a local window doc), as an own machine's row; returns the quarantine
/// reasons it left.
fn ingest_own_window(
    vault: &Arc<Vault>,
    id: &EntityId,
    definition: &AgentDefinition,
) -> Vec<String> {
    let before = quarantined_records(vault).unwrap().len();
    let doc = LoroDoc::new();
    let materializer = Arc::new(Materializer::new());
    let _subs = register_observer_b(&doc, vault, &materializer, WINDOW);
    let body = encode_agent_definition(definition).unwrap();
    map_insert_bytes(
        &doc.get_map("entities"),
        &id.to_hex(),
        &entity_blob(ENTITY_TYPE_AGENT_DEF, time_range(T0), T0, &body),
    );
    doc.commit();
    quarantined_records(vault)
        .unwrap()
        .into_iter()
        .skip(before)
        .map(|(_, record)| record.reason_code)
        .collect()
}

/// Catches an own-device row that goes beyond the owner's statement: the
/// owner turned the definition on at Approved, and his own machine's row
/// moves it to Auto.
#[test]
fn an_own_device_row_beyond_the_owners_statement_waits() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, owner) = carrying_vault(dir.path());
    let (id, revoked) = revoked_definition(&vault);
    let on = turned_on(&revoked, "1.0.2");
    owner_edit(&vault, &owner, &id, &on);
    let auto = next(&on, "1.0.3", |def| {
        def.approval_status = ClaimApprovalStatus::Auto;
    });
    let replayed = replay(&vault, &id, &auto, ImportTier::OwnDevice);
    assert_eq!(
        replayed.as_ref().err().map(oneiron::Error::kind),
        Some(ErrorKind::InvalidAgentDefBody),
        "a row beyond the owner's statement waits: {replayed:?}"
    );
    assert_eq!(vault.get_agent_definition(&id).unwrap(), Some(on));
}

/// Catches the owner's turn-on left off the authority log, and the honest
/// re-enable lost: the owner turned the definition on (a statement is
/// written), a writer below him turned it off again, and his other install's
/// row (its words reworded since, so bytes no act names) turns it back on
/// within his statement. Its replay half was green before pass 28 R2d too
/// (own-device replay was trust-blind); it guards that the statement keeps
/// this flow.
#[test]
fn an_own_device_row_within_the_owners_statement_lands() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, owner) = carrying_vault(dir.path());
    let (id, revoked) = revoked_definition(&vault);
    let on = turned_on(&revoked, "1.0.2");
    let entries = authority_entries(&vault);
    owner_edit(&vault, &owner, &id, &on);
    assert!(
        authority_entries(&vault) > entries,
        "the turn-on is stated on the authority log"
    );
    let off = next(&on, "1.0.3", |def| def.enabled = false);
    replay(
        &vault,
        &id,
        &off,
        ImportTier::Federated(FederationAdmissionRole::Member),
    )
    .expect("a peer turns a definition off");
    let reworded = next(&on, "1.0.4", |def| {
        def.desc = "Revocation fixture, reworded".to_owned();
    });
    replay(&vault, &id, &reworded, ImportTier::OwnDevice)
        .expect("a row within the owner's statement lands");
    assert_eq!(vault.get_agent_definition(&id).unwrap(), Some(reworded));
}

/// Catches a replay of the owner's old "on" row after he turned the
/// definition off himself: his turn-off replaces his statement.
#[test]
fn the_owners_turn_off_replaces_his_statement() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, owner) = carrying_vault(dir.path());
    let (id, revoked) = revoked_definition(&vault);
    let on = turned_on(&revoked, "1.0.2");
    owner_edit(&vault, &owner, &id, &on);
    let off = next(&on, "1.0.3", |def| def.enabled = false);
    owner_edit(&vault, &owner, &id, &off);
    let replayed = replay(&vault, &id, &on, ImportTier::OwnDevice);
    assert_eq!(
        replayed.as_ref().err().map(oneiron::Error::kind),
        Some(ErrorKind::InvalidAgentDefBody),
        "the old turn-on waits once the owner turned it off: {replayed:?}"
    );
    assert_eq!(vault.get_agent_definition(&id).unwrap(), Some(off));
}

/// Catches the own window's ingest believing an own machine's row: a
/// turn-on no owner stated is quarantined as pending, and the stored row
/// stays off.
#[test]
fn an_own_window_holds_a_turn_on_no_owner_stated() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, _owner) = carrying_vault(dir.path());
    let (id, revoked) = revoked_definition(&vault);
    let reasons = ingest_own_window(&vault, &id, &turned_on(&revoked, "1.0.2"));
    assert_eq!(reasons, ["InvalidAgentDefBody"], "one pending refusal");
    assert_eq!(vault.get_agent_definition(&id).unwrap(), Some(revoked));
}

/// Catches the own window's ingest refusing the honest re-enable: the owner
/// turned the definition on, a peer turned it off, and the own window's row
/// within his statement lands. Green before pass 28 R2d too.
#[test]
fn an_own_window_lands_a_turn_on_the_owner_stated() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, owner) = carrying_vault(dir.path());
    let (id, revoked) = revoked_definition(&vault);
    let on = turned_on(&revoked, "1.0.2");
    owner_edit(&vault, &owner, &id, &on);
    let off = next(&on, "1.0.3", |def| def.enabled = false);
    replay(
        &vault,
        &id,
        &off,
        ImportTier::Federated(FederationAdmissionRole::Member),
    )
    .expect("a peer turns a definition off");
    let reasons = ingest_own_window(&vault, &id, &on);
    assert!(reasons.is_empty(), "nothing quarantined: {reasons:?}");
    assert_eq!(vault.get_agent_definition(&id).unwrap(), Some(on));
}

/// Catches the own window's pending hold losing its retry: a turn-on no owner stated is
/// quarantined as a dependency with its rematerialization marker kept, and lands on retry
/// with no re-send once the owner's statement arrives.
#[test]
fn an_own_window_holds_a_turn_on_as_a_dependency_until_the_owner_states_it() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, owner) = carrying_vault(dir.path());
    let (id, revoked) = revoked_definition(&vault);
    let on = turned_on(&revoked, "1.0.2");
    let window_key = WindowKey::new(WINDOW);
    let doc = create_window_doc("owner", &window_key);
    let materializer = Materializer::new();
    let body = encode_agent_definition(&on).unwrap();
    map_insert_bytes(
        &doc.get_map("entities"),
        &id.to_hex(),
        &entity_blob(ENTITY_TYPE_AGENT_DEF, time_range(T0), T0, &body),
    );
    doc.commit();
    let before = quarantined_records(&vault).unwrap().len();
    forward_rematerialize(&vault, &doc, &materializer, &window_key).unwrap();
    let reasons: Vec<String> = quarantined_records(&vault)
        .unwrap()
        .into_iter()
        .skip(before)
        .map(|(_, record)| record.reason_code)
        .collect();
    assert_eq!(reasons, ["InvalidAgentDefBody"], "one pending refusal");
    assert_eq!(vault.get_agent_definition(&id).unwrap(), Some(revoked));
    assert_eq!(
        pending_remat_windows(&vault).unwrap(),
        vec![WINDOW.to_owned()],
        "the held row keeps its retry marker"
    );
    owner_edit(&vault, &owner, &id, &on);
    let off = next(&on, "1.0.3", |def| def.enabled = false);
    replay(
        &vault,
        &id,
        &off,
        ImportTier::Federated(FederationAdmissionRole::Member),
    )
    .expect("a peer turns the definition off again");
    assert_eq!(
        vault.get_agent_definition(&id).unwrap(),
        Some(off),
        "the peer's restrictive move lands after the statement"
    );
    forward_rematerialize(&vault, &doc, &materializer, &window_key).unwrap();
    assert_eq!(
        vault.get_agent_definition(&id).unwrap(),
        Some(on),
        "the held row lands with no re-send once the owner states it"
    );
}
