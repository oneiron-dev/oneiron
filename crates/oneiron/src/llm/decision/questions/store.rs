//! Immutable question versions and a CAS-updated scheduling head in vault_meta.

use super::super::types::invalid;
use super::records::*;
use crate::{EntityId, Error, Result, Vault};
use serde::{Serialize, de::DeserializeOwned};

pub(super) const PREFIX: &[u8] = b"typed_question:v1:";

pub fn create_question(
    vault: &Vault,
    principal: EntityId,
    mut definition: QuestionDefinition,
    now: u64,
) -> Result<QuestionRecord> {
    definition.question.id = EntityId::now();
    definition.question.version = 1;
    definition.validate()?;
    let record = QuestionRecord {
        schema_version: 1,
        principal,
        definition,
        created_at: now,
    };
    vault.with_write_txn(|txn| {
        let id = record.definition.question.id;
        super::arrival::watch(&vault.store, txn, &record)?;
        put(
            vault,
            txn,
            &key(id, b"version", &1_u32.to_be_bytes()),
            &record,
        )?;
        put(
            vault,
            txn,
            &key(id, b"head", &[]),
            &QuestionHead {
                version: 1,
                paused: false,
                last_refresh: None,
            },
        )
    })?;
    Ok(record)
}

pub fn read_question(
    vault: &Vault,
    principal: EntityId,
    id: EntityId,
    version: Option<u32>,
) -> Result<Option<QuestionRecord>> {
    let txn = vault.store.env.read_txn()?;
    let Some(head) = load::<QuestionHead>(vault, &txn, &key(id, b"head", &[]))? else {
        return Ok(None);
    };
    let record: Option<QuestionRecord> = load(
        vault,
        &txn,
        &key(
            id,
            b"version",
            &version.unwrap_or(head.version).to_be_bytes(),
        ),
    )?;
    if let Some(record) = &record {
        if record.schema_version != 1 {
            return Err(invalid("unsupported question schema"));
        }
        record.definition.validate()?;
    }
    Ok(record.filter(|r| r.principal == principal))
}

pub fn edit_question(
    vault: &Vault,
    principal: EntityId,
    id: EntityId,
    expected_version: u32,
    mut definition: QuestionDefinition,
    now: u64,
) -> Result<QuestionRecord> {
    vault.with_write_txn(|txn| {
        let mut head = owned_head(vault, txn, principal, id)?;
        if head.version != expected_version {
            return Err(Error::ConcurrentWrite("standing question changed"));
        }
        let version = head
            .version
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow("question version"))?;
        definition.question.id = id;
        definition.question.version = version;
        definition.validate()?;
        let record = QuestionRecord {
            schema_version: 1,
            principal,
            definition,
            created_at: now,
        };
        put(
            vault,
            txn,
            &key(id, b"version", &version.to_be_bytes()),
            &record,
        )?;
        super::arrival::watch(&vault.store, txn, &record)?;
        head.version = version;
        put(vault, txn, &key(id, b"head", &[]), &head)?;
        Ok(record)
    })
}

pub fn pause_question(
    vault: &Vault,
    principal: EntityId,
    id: EntityId,
    paused: bool,
) -> Result<()> {
    vault.with_write_txn(|txn| {
        let mut head = owned_head(vault, txn, principal, id)?;
        head.paused = paused;
        put(vault, txn, &key(id, b"head", &[]), &head)
    })
}

pub(super) fn owned_head(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    principal: EntityId,
    id: EntityId,
) -> Result<QuestionHead> {
    let head: QuestionHead =
        load(vault, txn, &key(id, b"head", &[]))?.ok_or(Error::EntityNotFound)?;
    let record: QuestionRecord = load(
        vault,
        txn,
        &key(id, b"version", &head.version.to_be_bytes()),
    )?
    .ok_or(Error::EntityNotFound)?;
    if record.principal != principal {
        return Err(Error::EntityNotFound);
    }
    Ok(head)
}

pub(super) fn key(id: EntityId, family: &[u8], suffix: &[u8]) -> Vec<u8> {
    [PREFIX, id.as_bytes(), b":", family, b":", suffix].concat()
}
pub(super) fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(value).map_err(|_| invalid("typed question encoding failed"))
}
pub(super) fn decode<T: DeserializeOwned>(raw: &[u8]) -> Result<T> {
    rmp_serde::from_slice(raw).map_err(|_| Error::CorruptedIndex("typed question record"))
}
pub(super) fn load<T: DeserializeOwned>(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    key: &[u8],
) -> Result<Option<T>> {
    vault
        .store
        .vault_meta
        .get(txn, key)?
        .map(|raw| decode(&raw))
        .transpose()
}
pub(super) fn put<T: Serialize>(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    key: &[u8],
    value: &T,
) -> Result<()> {
    let text =
        serde_json::to_string(value).map_err(|_| invalid("typed question encoding failed"))?;
    crate::batch::secret_scan::scan_metadata_field(&text)?;
    vault.store.vault_meta.put(txn, key, &encode(value)?)?;
    Ok(())
}
pub(super) fn list<T: DeserializeOwned>(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    prefix: &[u8],
) -> Result<Vec<T>> {
    vault
        .store
        .vault_meta
        .prefix_iter(txn, prefix)?
        .map(|row| {
            let (_, raw) = row?;
            decode(&raw)
        })
        .collect()
}
