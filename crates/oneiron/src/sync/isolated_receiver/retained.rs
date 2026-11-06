//! The native after-entity obligations on an unobserved candidate and its writer.

use crate::sync::loro_support::{
    TombstoneIndex, map_delete, map_for_each_value_bytes, map_get_bytes,
};
use crate::sync::types::WindowKey;
use crate::sync::window_rows::HISTORY_FREE_WINDOW;
use crate::{EntityId, Error, Result, Vault};
use loro::{CommitOptions, LoroDoc, LoroValue, ValueOrContainer};

pub(super) fn native_notes(doc: &LoroDoc) -> Result<Option<crate::sync::note::State>> {
    if crate::sync::note::is_native(doc) {
        return crate::sync::note::validate(doc).map(Some);
    }
    for name in [
        "documents",
        "entity_documents",
        "document_heads",
        "head_move_receipts",
        "note_forks",
        "note_proposals",
    ] {
        if !doc.get_map(name).is_empty() {
            return Err(crate::note::documents::invalid(
                "peer window cannot authorize NOTE recovery",
            ));
        }
    }
    Ok(None)
}

pub(super) fn stage_in_txn(
    vault: &Vault,
    doc: &LoroDoc,
    key: &WindowKey,
    notes: Option<crate::sync::note::State>,
    txn: &mut heed::RwTxn<'_>,
) -> Result<Vec<EntityId>> {
    scrub_redacted_attributions_in_txn(vault, doc, key, txn)?;
    let tombstones = TombstoneIndex::build(&doc.get_map("tombstones"));
    let healed = match notes {
        Some(notes) => {
            crate::sync::note::apply_in_txn(vault, &tombstones, notes, key.as_str(), txn)?
        }
        None => Vec::new(),
    };
    if let Some(world) = key.world() {
        let mut witnesses = Vec::new();
        doc.get_map("retained_claim_worlds").for_each(|raw, value| {
            witnesses.push((raw.to_owned(), value));
        });
        for (raw, value) in witnesses {
            let id = EntityId::from_hex(&raw)?;
            if let ValueOrContainer::Value(LoroValue::Binary(bytes)) = value
                && bytes.as_ref() != world.as_bytes()
            {
                return Err(Error::InvalidConfig(
                    "foreign retained world witness".into(),
                ));
            }
            let Some(blob) = map_get_bytes(&doc.get_map("entities"), &raw) else {
                return Err(Error::InvalidConfig("orphan retained world witness".into()));
            };
            if !crate::sync::types::retained_world_shell_belongs_to_window(
                vault,
                txn,
                doc,
                &tombstones,
                &id,
                &blob,
                key,
                false,
            )? {
                return Err(Error::InvalidConfig(
                    "unproven retained world witness".into(),
                ));
            }
            vault
                .store
                .sync_state
                .put(txn, &format!("m:dw:{raw}"), key.as_str().as_bytes())?;
        }
    }
    let mut shells = Vec::new();
    doc.get_map("entities").for_each(|raw, value| {
        if matches!(value, ValueOrContainer::Value(LoroValue::Binary(blob))
            if blob.len() == crate::batch::ENTITY_METADATA_HEADER_LEN)
            && let Ok(id) = EntityId::from_hex(raw)
            && let Some((blob, tombstone)) =
                crate::recovery::retained_soft_shell(doc, &tombstones, &id)
        {
            shells.push((id, blob, tombstone));
        }
    });
    for (id, blob, tombstone) in shells {
        if !vault.local_hard_delete_marker_exists_in_txn(txn, &id)? {
            crate::batch::restore_recovery_shell_in_txn(vault, txn, &id, &blob, &tombstone)?;
        }
    }
    Ok(healed)
}

fn scrub_redacted_attributions_in_txn(
    vault: &Vault,
    doc: &LoroDoc,
    key: &WindowKey,
    txn: &mut heed::RwTxn<'_>,
) -> Result<()> {
    let entities = doc.get_map("entities");
    let mut redacted = crate::identity_topology::redacted_keys_in_txn(&vault.store, txn)?;
    map_for_each_value_bytes(&entities, |_, blob| {
        if let Some(key) = blob.and_then(crate::identity_topology::redaction_carrier_key) {
            redacted.insert(key);
        }
    });
    if redacted.is_empty() {
        return Ok(());
    }
    HISTORY_FREE_WINDOW.put(&vault.store, txn, &key.as_str().to_owned(), &[1u8])?;
    let mut keys = Vec::new();
    map_for_each_value_bytes(&entities, |raw, blob| {
        if blob
            .and_then(crate::identity_topology::attribution_carrier_key)
            .is_some_and(|key| redacted.contains(&key))
        {
            keys.push(raw.to_owned());
        }
    });
    for raw in &keys {
        map_delete(&entities, raw)?;
    }
    if !keys.is_empty() {
        crate::sync::row_birth::drop_orphan_births(doc)?;
        crate::sync::origin_positions::drop_unbound(doc)?;
        doc.commit_with(CommitOptions::new().origin(crate::sync::bridge::BRIDGE_ORIGIN));
    }
    Ok(())
}
