//! A staged foreign import holding a peer's TASK authority fact settles
//! `Failed(AdmissionRejected)` (FIX TASK-FACT-STAGED-CONFIRM-NEVER-SETTLES).
//!
//! The window door refuses a federation peer's task authority fact (FIX
//! TASK-FACT-FROM-FEDERATION-PEER), and that refusal reads nothing but the
//! artifact's digest-pinned bytes, so no later policy admits them:
//! - a fresh stage of such an artifact settles a Failed receipt at once,
//!   rather than answering a retryable error and writing no receipt;
//! - a Pending receipt an older door staged over such bytes (planted through
//!   `oneiron::test_doors::staged_vault_import`) settles Failed at its
//!   confirmation, which imports nothing and drops the staged content; a
//!   second confirmation answers the failed receipt, and a stage of the same
//!   bytes again reads Failed;
//! - an artifact with an ordinary TASK row and no fact still stages Pending.
//!
//! Run with `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test staged_import_task_fact_settles`.
#![cfg(all(feature = "sync", oneiron_test_support))]
// Integration-test helpers (non-test fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used)]

use std::sync::Arc;

use loro::ExportMode;
use oneiron::batch::export::{
    ForeignVaultImportSource, StagedVaultImport, VaultImportClassification,
    VaultImportConfirmation, VaultImportFailure, VaultImportReceipt, VaultImportStageStatus,
    stage_foreign_vault_import, vault_import_stage_receipt, vault_import_staged_content,
};
use oneiron::habit::TaskRole;
use oneiron::registry::ENTITY_TYPE_TASK;
use oneiron::sync::bridge::Materializer;
use oneiron::sync::client::{SyncClient, SyncClientConfig};
use oneiron::sync::manager::WindowManager;
use oneiron::sync::schema::create_window_doc;
use oneiron::sync::types::WindowKey;
use oneiron::sync::{FederationAdmissionRole, admit_federated_window_update};
use oneiron::test_doors::staged_vault_import::stage_unadmitted;
use oneiron::{
    EntityId, TASK_AUTHORITY_FACT_SCHEMA_VERSION, TASK_AUTHORITY_FACT_SUBKIND,
    TaskAuthorityFactKind, Vault, VaultConfig,
};

/// March 2026, the window every row here is written in.
const WINDOW: &str = "2026-03";
/// 2026-03-15 00:00 UTC, inside [`WINDOW`].
const T0: u64 = 1_773_532_800;
/// The verdict the window door refuses a peer's task authority fact with.
const FACT_REFUSAL: &str = "a federation peer cannot send a task authority fact";

/// A vault and a sync client over it: the client runs the confirmation leg.
fn open_client() -> (tempfile::TempDir, Arc<Vault>, SyncClient) {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).unwrap());
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing().unwrap();
    let manager = Arc::new(WindowManager::new(
        Arc::clone(&vault),
        Arc::new(Materializer::new()),
        "staged-task-fact",
    ));
    let (client, _events) = SyncClient::new(manager, SyncClientConfig::default()).unwrap();
    (dir, vault, client)
}

fn msgpack(value: &rmpv::Value) -> Vec<u8> {
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, value).unwrap();
    bytes
}

/// One strict-v1 Owner fact body from literal parts: a peer's fact as it
/// arrives on the wire.
fn owner_fact_body(task_ref: EntityId, actor: EntityId) -> Vec<u8> {
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
        (
            rmpv::Value::from("kind"),
            rmpv::Value::from(TaskAuthorityFactKind::Owner.as_byte()),
        ),
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

/// A foreign artifact: one window update carrying one TASK row `body` at `id`.
fn artifact(id: EntityId, body: &[u8]) -> (WindowKey, Vec<u8>) {
    let key = WindowKey::new(WINDOW);
    let peer = create_window_doc("federation-peer", &key);
    peer.get_map("entities")
        .insert(&id.to_hex(), entity_blob(body).as_slice())
        .unwrap();
    peer.commit();
    let update = peer.export(ExportMode::all_updates()).unwrap();
    (key, update)
}

/// The classification a foreign authority chain's manifest gets.
fn foreign_classification() -> VaultImportReceipt {
    VaultImportReceipt {
        manifest_digest: [0x5a; 32],
        classification: VaultImportClassification::ForeignAuthorityChain,
        mismatches: vec![],
        exported_vault_id: None,
        local_vault_id: None,
        exported_label: None,
        expected_label: None,
        byte_faithful: false,
    }
}

fn source() -> ForeignVaultImportSource {
    ForeignVaultImportSource::ForeignPlatform {
        platform: "elsewhere".into(),
    }
}

/// The window door's own refusal of `update`: the fact verdict, so the
/// receipts below settle for that refusal and no other.
fn assert_window_door_refuses_the_fact(vault: &Vault, key: &WindowKey, update: &[u8]) {
    let refused =
        admit_federated_window_update(vault, key, update, FederationAdmissionRole::Guest, None)
            .map(|_| ())
            .unwrap_err();
    assert!(
        refused.to_string().contains(FACT_REFUSAL),
        "the window door refuses the peer's fact: {refused}"
    );
}

/// Asserts the durable receipt `id` is `Failed(AdmissionRejected)` and keeps
/// no staged content.
fn assert_failed(vault: &Vault, id: &[u8; 32]) {
    let receipt = vault_import_stage_receipt(vault, id)
        .unwrap()
        .expect("the stage leaves a receipt");
    assert_eq!(
        (receipt.status, receipt.failure),
        (
            VaultImportStageStatus::Failed,
            Some(VaultImportFailure::AdmissionRejected)
        ),
        "the receipt settles Failed(AdmissionRejected): {receipt:?}"
    );
    assert_eq!(
        vault_import_staged_content(vault, id).unwrap(),
        None,
        "a failed receipt keeps no staged content"
    );
}

#[test]
fn a_fresh_stage_of_a_task_fact_settles_failed() {
    let (_dir, vault, _client) = open_client();
    let fact = EntityId::now();
    let (key, update) = artifact(fact, &owner_fact_body(EntityId::now(), EntityId::now()));
    assert_window_door_refuses_the_fact(&vault, &key, &update);

    let staged =
        stage_foreign_vault_import(&vault, &foreign_classification(), source(), &key, &update)
            .expect("a stage of a peer's task fact settles a receipt, not a retryable error");
    assert_eq!(
        staged.receipt.status,
        VaultImportStageStatus::Failed,
        "the stage answers its failed receipt: {:?}",
        staged.receipt
    );
    assert!(
        staged.admitted_update.is_empty(),
        "a failed stage carries no admitted bytes"
    );
    assert_failed(&vault, &staged.receipt.receipt_id);
    assert!(!vault.entity_exists(&fact).unwrap(), "the fact never lands");
}

#[test]
fn a_pending_stage_holding_a_task_fact_settles_failed_at_its_confirmation() {
    let (_dir, vault, mut client) = open_client();
    let fact = EntityId::now();
    let (key, update) = artifact(fact, &owner_fact_body(EntityId::now(), EntityId::now()));
    assert_window_door_refuses_the_fact(&vault, &key, &update);
    // An older door staged the fact's bytes: a Pending receipt over them.
    let planted = stage_unadmitted(&vault, &foreign_classification(), source(), &key, &update)
        .expect("plant the older door's Pending stage");
    let id = planted.receipt.receipt_id;
    assert_eq!(
        planted.receipt.status,
        VaultImportStageStatus::Pending,
        "the planted stage is Pending"
    );
    let confirmation = VaultImportConfirmation {
        receipt_id: id,
        actor: EntityId::now(),
        confirmed_at_secs: 1,
    };
    let again = StagedVaultImport {
        receipt: planted.receipt.clone(),
        admitted_update: planted.admitted_update.clone(),
    };

    assert!(
        client
            .confirm_staged_vault_import(planted, confirmation)
            .is_err(),
        "the confirmation refuses the peer's fact"
    );
    assert_failed(&vault, &id);
    assert!(
        !vault.entity_exists(&fact).unwrap(),
        "the refused confirmation imports nothing"
    );

    // A second confirmation reads the failed receipt.
    match client.confirm_staged_vault_import(again, confirmation) {
        Ok(receipt) => panic!("a failed staged import confirmed: {receipt:?}"),
        Err(error) => assert!(
            format!("{error:?}").contains("failed staged import"),
            "the second confirmation answers the failed receipt: {error:?}"
        ),
    }
    // A stage of the same bytes again reads the failed receipt.
    let restaged =
        stage_foreign_vault_import(&vault, &foreign_classification(), source(), &key, &update)
            .expect("a stage of the same bytes reads its receipt");
    assert_eq!(
        (restaged.receipt.receipt_id, restaged.receipt.status),
        (id, VaultImportStageStatus::Failed),
        "the same bytes stage to the same failed receipt"
    );
}

#[test]
fn an_artifact_with_no_task_fact_still_stages_pending() {
    let (_dir, vault, _client) = open_client();
    let (key, update) = artifact(EntityId::now(), &task_body());
    let staged =
        stage_foreign_vault_import(&vault, &foreign_classification(), source(), &key, &update)
            .expect("an ordinary TASK row stages");
    assert_eq!(
        staged.receipt.status,
        VaultImportStageStatus::Pending,
        "an artifact with no task fact waits for its confirmation: {:?}",
        staged.receipt
    );
}
