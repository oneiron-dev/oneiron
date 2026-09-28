//! Value-only canonical recovery for generic EntityDoc owners.

use super::{EntityDoc, storage};
use crate::error::ArtifactError;
use crate::recovery::CanonicalEntityDocument;
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
    for prefix in ["pin", "receipt", "purge"] {
        let key = format!("entity_doc:v1:{prefix}:{}:", entity.to_hex());
        if vault
            .store
            .sync_state
            .prefix_iter(txn, &key)?
            .next()
            .transpose()?
            .is_some()
        {
            return Err(invalid(
                "entity document citations or receipts require causal recovery",
            ));
        }
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
    let document = EntityId::from_bytes(row.document_id)?.to_hex();
    if let Some(raw) = vault
        .store
        .vault_meta
        .get(txn, storage::head_key(&entity).as_bytes())?
    {
        let old: storage::Head = storage::decode(&raw)?;
        if old.document != document {
            return Err(invalid(
                "entity document recovery conflicts with existing head",
            ));
        }
        storage::delete_prefix(&vault.store, txn, &format!("u:e:{document}:"))?;
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
    storage::persist(vault, txn, &entity, &mut head, &doc, None)
}
