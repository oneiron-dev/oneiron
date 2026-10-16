//! A federation peer turns no agent definition back on. A member's or a
//! guest's row that re-enables, re-approves or reactivates a stored definition
//! is refused at window admission and at federated replay, as the peer's
//! bytes; the peer's restrictive moves land. Own-device replay is trust-blind
//! and turns the definition back on.
#![cfg(feature = "sync")]
// Integration-test helpers (non-test fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used)]

use loro::ExportMode;
use oneiron::agent_def::{AgentCeiling, AgentDefinition, AgentScope, encode_agent_definition};
use oneiron::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use oneiron::registry::ENTITY_TYPE_AGENT_DEF;
use oneiron::sync::client::ImportTier;
use oneiron::sync::replay::{ReplicatedEntity, replay_entity};
use oneiron::sync::schema::create_window_doc;
use oneiron::sync::types::WindowKey;
use oneiron::sync::{FederationAdmissionRole, admit_federated_window_update};
use oneiron::{EntityId, ErrorKind, Vault};

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
        rmpv::Value::Map(Vec::new()),
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
) -> oneiron::Result<Vec<u8>> {
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
    admit_federated_window_update(vault, &key, &update, role)
}

/// A fresh definition seeded running, then turned off by a federation
/// member: a peer's restrictive moves land.
fn revoked_definition(vault: &Vault) -> (EntityId, AgentDefinition) {
    let id = EntityId::now();
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
    (id, revoked)
}

#[test]
fn a_federation_peer_turns_no_agent_definition_back_on() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), test_config()).unwrap();
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

    let (id, _) = revoked_definition(&vault);
    let restored = next(&running_definition(), "1.0.3", |_| {});
    replay(&vault, &id, &restored, ImportTier::OwnDevice).expect("own-device replay");
    assert_eq!(vault.get_agent_definition(&id).unwrap(), Some(restored));
}
