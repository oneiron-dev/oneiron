//! A federation peer sends no TASK authority fact (FIX
//! TASK-FACT-FROM-FEDERATION-PEER; Fable pass 28, Appendix B).
//!
//! Who owns, took, cancelled or acknowledged a task is read from its role-6
//! fact rows, and the task fold believes every fact it holds: a fact carries
//! no proof of who made it until it carries its carrier's signature (pass 28
//! R5). So a member's or a guest's role-6 row is refused at window admission
//! and at federated replay, as the peer's bytes. A peer's ordinary TASK row
//! still lands.
//!
//! Run: `cargo test --locked -p oneiron --all-features --test
//! federation_refuses_peer_task_fact`.
#![cfg(all(feature = "sync", feature = "test-support"))]
// Integration-test helpers (non-test fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used)]

use std::sync::Arc;

use loro::ExportMode;
use oneiron::habit::TaskRole;
use oneiron::registry::ENTITY_TYPE_TASK;
use oneiron::sync::client::ImportTier;
use oneiron::sync::replay::{ReplicatedEntity, replay_entity};
use oneiron::sync::schema::create_window_doc;
use oneiron::sync::types::WindowKey;
use oneiron::sync::{FederationAdmissionRole, admit_federated_window_update};
use oneiron::temporal::TimeRange;
use oneiron::{
    EntityId, ErrorKind, HnswConfig, TASK_AUTHORITY_FACT_SCHEMA_VERSION,
    TASK_AUTHORITY_FACT_SUBKIND, TaskAuthorityFactKind, Vault, VaultConfig,
};

/// March 2026, the window every row here is written in.
const WINDOW: &str = "2026-03";
/// 2026-03-15 00:00 UTC, inside [`WINDOW`].
const T0: u64 = 1_773_532_800;

const ROLES: [FederationAdmissionRole; 2] = [
    FederationAdmissionRole::Member,
    FederationAdmissionRole::Guest,
];

fn open_vault(path: &std::path::Path) -> Vault {
    let mut config = VaultConfig::device();
    config.map_size = 16 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = None;
    config.max_readers = 16;
    config.hnsw = HnswConfig::default();
    let vault = Vault::open(path, config).unwrap();
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing().unwrap();
    vault
}

fn msgpack(value: &rmpv::Value) -> Vec<u8> {
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, value).unwrap();
    bytes
}

/// One strict-v1 authority fact body from literal parts: a peer's fact as it
/// arrives on the wire.
fn authority_fact_body(
    task_ref: EntityId,
    kind: TaskAuthorityFactKind,
    actor: EntityId,
) -> Vec<u8> {
    msgpack(&rmpv::Value::Map(vec![
        (
            rmpv::Value::from("role"),
            rmpv::Value::from(TaskRole::AuthorityFact.role_byte()),
        ),
        (
            rmpv::Value::from("schema_version"),
            rmpv::Value::from(TASK_AUTHORITY_FACT_SCHEMA_VERSION),
        ),
        (
            rmpv::Value::from("subkind"),
            rmpv::Value::from(TASK_AUTHORITY_FACT_SUBKIND),
        ),
        (
            rmpv::Value::from("task_ref"),
            rmpv::Value::from(task_ref.to_hex()),
        ),
        (rmpv::Value::from("kind"), rmpv::Value::from(kind.as_byte())),
        (
            rmpv::Value::from("actor_ref"),
            rmpv::Value::from(actor.to_hex()),
        ),
        (rmpv::Value::from("occurred_at"), rmpv::Value::from(T0)),
    ]))
}

/// A peer's ordinary TASK row (role 1).
fn task_body() -> Vec<u8> {
    msgpack(&rmpv::Value::Map(vec![(
        rmpv::Value::from("role"),
        rmpv::Value::from(TaskRole::Task.role_byte()),
    )]))
}

/// The pinned entity metadata header and body, from literal parts: type u8,
/// occurred start and end, learned-at and row version (u64 BE each), body.
fn entity_blob(body: &[u8]) -> Vec<u8> {
    let mut blob = vec![ENTITY_TYPE_TASK];
    for stamp in [T0, T0, T0, 0] {
        blob.extend_from_slice(&stamp.to_be_bytes());
    }
    blob.extend_from_slice(body);
    blob
}

/// The window door: a peer's update carrying one TASK row at `id`.
fn admit(
    vault: &Vault,
    id: &EntityId,
    body: &[u8],
    role: FederationAdmissionRole,
) -> oneiron::Result<Vec<(WindowKey, Vec<u8>)>> {
    let key = WindowKey::new(WINDOW);
    let peer = create_window_doc("federation-peer", &key);
    peer.get_map("entities")
        .insert(&id.to_hex(), entity_blob(body).as_slice())
        .unwrap();
    peer.commit();
    let update = peer.export(ExportMode::all_updates()).unwrap();
    admit_federated_window_update(vault, &key, &update, role, None)
}

/// The replay door, at the peer's tier.
fn replay(
    vault: &Vault,
    id: &EntityId,
    body: &[u8],
    role: FederationAdmissionRole,
) -> oneiron::Result<()> {
    replay_entity(
        vault,
        ReplicatedEntity {
            id: *id,
            entity_type: ENTITY_TYPE_TASK,
            occurred: TimeRange { start: T0, end: T0 },
            learned_at: T0,
            row_version: 0,
            body,
        },
        ImportTier::Federated(role),
    )
}

#[test]
fn a_federation_peer_sends_no_task_authority_fact() {
    let dir = tempfile::tempdir().unwrap();
    let vault = open_vault(dir.path());
    let task = EntityId::now();
    let forger = EntityId::now();
    let mut let_through = Vec::new();
    for role in ROLES {
        for kind in [
            TaskAuthorityFactKind::Owner,
            TaskAuthorityFactKind::Cancelled,
            TaskAuthorityFactKind::Acked,
        ] {
            let body = authority_fact_body(task, kind, forger);
            let fact = EntityId::now();
            let admitted = admit(&vault, &fact, &body, role).map(|_| ());
            let replayed = replay(&vault, &fact, &body, role);
            for (door, outcome) in [("window", admitted), ("replay", replayed)] {
                // Refused as the peer's bytes, so the frame quarantines.
                if outcome.as_ref().err().map(oneiron::Error::kind)
                    != Some(ErrorKind::InvalidTaskBody)
                {
                    let_through.push(format!("{role:?} {door} {kind:?}: {outcome:?}"));
                }
            }
            if vault.entity_exists(&fact).unwrap() {
                let_through.push(format!("{role:?} {kind:?}: the fact row landed"));
            }
        }
    }
    assert!(
        let_through.is_empty(),
        "a federation peer's task authority fact was let through: {let_through:#?}"
    );
}

#[test]
fn a_federation_peer_task_row_still_lands() {
    let dir = tempfile::tempdir().unwrap();
    let vault = open_vault(dir.path());
    for role in ROLES {
        let task = EntityId::now();
        let admitted = admit(&vault, &task, &task_body(), role)
            .unwrap_or_else(|error| panic!("{role:?}: a peer's task row is admitted: {error:?}"));
        assert!(
            !admitted.is_empty(),
            "{role:?}: the admitted update carries the task row"
        );
        replay(&vault, &task, &task_body(), role)
            .unwrap_or_else(|error| panic!("{role:?}: a peer's task row lands: {error:?}"));
        assert!(vault.entity_exists(&task).unwrap(), "{role:?}");
    }
}
