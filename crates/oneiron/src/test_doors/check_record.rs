//! Test doors for `tests/code_check_record.rs` and `tests/code_check_reuse.rs`:
//! the bound checkout's worktree path, the TASK's request revision, a TASK
//! revision bump through the typed write path, and a stored record's PROJECT
//! relabel. Compiled only under `--cfg oneiron_test_support`; never API.

use std::path::PathBuf;

use rmpv::Value;

use crate::EntityId;
use crate::attempt_queue::AttemptId;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::checkout::lease::load_act_in_txn;
use crate::error::{Error, RecordError, Result};
use crate::git_wire::GitWire;
use crate::registry::ENTITY_TYPE_TASK;
use crate::store::checkout_lease::{CheckoutError, CheckoutId};
use crate::temporal::TimeRange;
use crate::vault::Vault;

/// A checkout failure as the test reads it: a store failure as it is, anything else as not found.
fn checkout_error(error: CheckoutError) -> Error {
    match error {
        CheckoutError::Store(error) => error,
        _ => Error::EntityNotFound,
    }
}

/// The worktree path of the `checkout`.`epoch` lease: what the run's bound checkout materialized.
pub fn check_record_worktree_path(vault: &Vault, checkout: &str, epoch: u64) -> Result<PathBuf> {
    let entity = EntityId::from_hex(checkout).map_err(|_| Error::InvalidKey)?;
    let id = CheckoutId::from_bytes(*entity.as_bytes()).map_err(checkout_error)?;
    let txn = vault.store.env.read_txn()?;
    let lease = load_act_in_txn(vault, &txn, id)
        .map_err(checkout_error)?
        .ok_or(Error::EntityNotFound)?;
    if lease.epoch != epoch {
        return Err(Error::EntityNotFound);
    }
    GitWire::new(vault)?
        .checkout_worktree_path(&lease)
        .map_err(checkout_error)
}

/// The TASK's request revision: what `start` and `finish` capture.
pub fn check_record_task_revision(vault: &Vault, task: EntityId) -> Result<u64> {
    let txn = vault.store.env.read_txn()?;
    crate::task_verb::linear_store::task_revision_in_txn(&vault.store, &txn, task)
}

/// Revises the TASK's typed body through the vault's typed write path, so
/// its request revision rises as a public rewrite would raise it: what a
/// reuse refuses as a revised source. Answers the new revision. The body
/// keeps every key and changes only its label; the revision row is never
/// written directly.
pub fn check_record_revise_task(vault: &Vault, task: EntityId) -> Result<u64> {
    let txn = vault.store.env.read_txn()?;
    let raw = vault
        .get_raw_in(&txn, &task)?
        .ok_or(Error::EntityNotFound)?;
    drop(txn);
    let header = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("task record"))?;
    if header.entity_type != ENTITY_TYPE_TASK {
        return Err(Error::InvalidKey);
    }
    let body = raw
        .get(ENTITY_METADATA_HEADER_LEN..)
        .ok_or(Error::CorruptedIndex("task record"))?;
    let mut cursor = body;
    let value =
        rmpv::decode::read_value(&mut cursor).map_err(|_| Error::CorruptedIndex("task body"))?;
    if !cursor.is_empty() {
        return Err(Error::CorruptedIndex("task body"));
    }
    let Value::Map(mut entries) = value else {
        return Err(Error::Record(RecordError::InvalidTaskBody(
            "tasks.create.body",
        )));
    };
    let mut revised = false;
    for (key, val) in &mut entries {
        if key.as_str() == Some("label") {
            let seen = match val {
                Value::String(label) => label.as_str().unwrap_or("task").to_owned(),
                _ => "task".to_owned(),
            };
            *val = Value::from(format!("{seen}-revised"));
            revised = true;
        }
    }
    if !revised {
        entries.push((Value::from("label"), Value::from("revised")));
    }
    let mut encoded = Vec::new();
    rmpv::encode::write_value(&mut encoded, &Value::Map(entries))
        .map_err(|_| Error::CorruptedIndex("task body"))?;
    vault.put_entity(
        &task,
        ENTITY_TYPE_TASK,
        TimeRange {
            start: header.occurred_start,
            end: header.occurred_end,
        },
        header.learned_at,
        &encoded,
    )?;
    check_record_task_revision(vault, task)
}

/// Moves the stored check record to `project`: what a reuse from outside
/// the PROJECT refuses. One write transaction; reads and re-puts the record
/// with its producer's project changed.
pub fn check_record_relabel_project(
    vault: &Vault,
    attempt_id: &str,
    check: EntityId,
    project: EntityId,
) -> Result<()> {
    let entity = EntityId::from_hex(attempt_id).map_err(|_| Error::InvalidKey)?;
    let attempt = AttemptId::from_bytes(entity.as_bytes()).map_err(|_| Error::InvalidKey)?;
    vault.with_write_txn(|txn| {
        let key = (attempt, check);
        let mut record = crate::check_record::CHECK_RECORDS
            .get(&vault.store, txn, &key)?
            .ok_or(Error::EntityNotFound)?;
        record.producer.project = project;
        crate::check_record::CHECK_RECORDS.put(&vault.store, txn, &key, &record)?;
        Ok(())
    })
}
