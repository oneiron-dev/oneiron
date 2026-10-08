//! Value-only canonical recovery for generic EntityDoc owners.

use super::{EntityDoc, storage};
use crate::error::ArtifactError;
use crate::recovery::CanonicalEntityDocument;
use crate::side_table::HexId;
fn invalid(reason: &'static str) -> crate::Error {
    ArtifactError::InvalidRecoveryArtifact(reason).into()
}
use crate::{EntityId, Result, Vault};
use heed::{RoTxn, RwTxn};

fn guard(vault: &Vault, txn: &RoTxn<'_>, entity: &EntityId) -> Result<()> {
    // Existing causal bases, pinned quotes and receipts cannot be rebuilt from
    // a value-only snapshot. Refuse instead of discarding their authority.
    if !super::forks::all_forks(&vault.store, txn, entity)?.is_empty() {
        return Err(invalid("entity document forks require causal recovery"));
    }
    let store = &vault.store;
    let key_prefix = format!("{}:", entity.to_hex()).into_bytes();
    if super::pins::ENTITY_DOC_PIN
        .iter_raw_from(store, txn, &key_prefix)?
        .next()
        .transpose()?
        .is_some()
        || super::forks::ENTITY_DOC_RECEIPT
            .iter_raw_from(store, txn, &key_prefix)?
            .next()
            .transpose()?
            .is_some()
        || super::pins::ENTITY_DOC_PURGE_RECEIPT
            .iter_raw_from(store, txn, &key_prefix)?
            .next()
            .transpose()?
            .is_some()
    {
        return Err(invalid(
            "entity document citations or receipts require causal recovery",
        ));
    }
    Ok(())
}

pub(crate) fn capture(
    vault: &Vault,
    txn: &RoTxn<'_>,
    bytes: [u8; 16],
) -> Result<Option<CanonicalEntityDocument>> {
    let entity = EntityId::from_bytes(bytes)?;
    if !storage::has_record_head(&vault.store, txn, &entity)? {
        return Ok(None);
    }
    guard(vault, txn, &entity)?;
    let head = storage::head(&vault.store, txn, &entity)?;
    let doc = storage::load(&vault.store, txn, &head)?;
    Ok(Some(CanonicalEntityDocument {
        entity_id: bytes,
        document_id: *EntityId::from_hex(&head.document)?.as_bytes(),
        field: match head.field {
            storage::TextField::Utf8Body => None,
            storage::TextField::MapField(field) => Some(field),
        },
        text: doc.text(),
        birth_actor: *EntityId::from_hex(&doc.birth().actor)?.as_bytes(),
        birth_at: doc.birth().at,
    }))
}

pub(crate) fn restore(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    row: &CanonicalEntityDocument,
) -> Result<()> {
    let entity = EntityId::from_bytes(row.entity_id)?;
    guard(vault, txn, &entity)?;
    let document_id = EntityId::from_bytes(row.document_id)?;
    let document = document_id.to_hex();
    // An existing head keeps its updates until `persist` below replaces them
    // with the recovered snapshot: it reads the intact document first, so
    // recovering the same text owes the turn no tag pass.
    let existing = storage::ENTITY_DOC_HEAD.get(&vault.store, txn, &HexId(entity))?;
    if let Some(old) = &existing
        && old.document != document
    {
        return Err(invalid(
            "entity document recovery conflicts with existing head",
        ));
    }
    let doc = EntityDoc::rebuild_value(
        entity,
        &row.text,
        EntityId::from_bytes(row.birth_actor)?,
        row.birth_at,
    )?;
    let mut head = storage::Head {
        entity: entity.to_hex(),
        incarnation: EntityId::now().to_hex(),
        document,
        field: match &row.field {
            None => storage::TextField::Utf8Body,
            Some(field) => storage::TextField::MapField(field.clone()),
        },
        generation: 0,
        pending: 0,
    };
    storage::persist(vault, txn, &entity, &mut head, &doc, None)?;
    // With no head the text could not be read, so a MESSAGE or TURN whose
    // text this restores owes its turn a tag pass (ARCH-0036).
    if existing.is_none()
        && let Some(entity_type) = crate::tagging::text_entity_type_in_txn(vault, txn, &entity)?
    {
        crate::tagging::mark_on_publication_in_txn(vault, txn, &entity, entity_type)?;
    }
    Ok(())
}
