//! Full-window UPDATE locality admission without live document side effects.

use std::collections::HashMap;

use loro::json::{JsonOpContent, MapOp};
use loro::{ContainerID, ContainerType, LoroDoc, LoroValue};

use crate::EntityId;
use crate::batch::EntityMetadataHeader;
use crate::error::SyncError;
use crate::registry::ENTITY_TYPE_DIAGNOSTIC;
use crate::sync::loro_support::{map_for_each_value_bytes, map_get_bytes};
use crate::{Error, Result};

/// Refuses diagnostic carriers before a full-window update can mutate the
/// live document, materialize rows, persist bytes or fan out to another peer.
///
/// Inspect the incoming operation range, not just final map state: a put
/// followed by a delete still carries the diagnostic body in wire history.
/// A snapshot also carries live state outside its retained operation range.
/// Missing causal dependencies are refused rather than relaying uninspected
/// pending operations; a peer can negotiate the missing prefix and retry.
pub fn validate_window_update_locality(doc: &LoroDoc, update: &[u8]) -> Result<()> {
    validate_window_update(doc, update, None, None)
}

/// Checks a peer's complete operation range against the window's world axis.
/// Production imports use the vault-aware door below instead.
#[cfg(test)]
pub(in crate::sync) fn validate_window_update_residence(
    doc: &LoroDoc,
    update: &[u8],
    key: &crate::sync::WindowKey,
) -> Result<()> {
    validate_window_update(doc, update, Some(key), None)
}

/// Owner-lane admission with the vault's durable entity residence as proof
/// for edges and tombstones. Run before importing or relaying the update.
pub fn validate_window_update_residence_with_vault(
    vault: &crate::Vault,
    doc: &LoroDoc,
    update: &[u8],
    key: &crate::sync::WindowKey,
) -> Result<()> {
    validate_window_update(doc, update, Some(key), Some(vault))
}

fn validate_window_update(
    doc: &LoroDoc,
    update: &[u8],
    key: Option<&crate::sync::WindowKey>,
    vault: Option<&crate::Vault>,
) -> Result<()> {
    let decode_error = |source| {
        Error::Sync(SyncError::CrdtDecodeError {
            context: "window locality admission",
            source,
        })
    };
    let metadata = LoroDoc::decode_import_blob_meta(update, true).map_err(decode_error)?;
    let candidate = if metadata.mode.is_snapshot() {
        LoroDoc::from_snapshot(update).map_err(decode_error)?
    } else {
        let candidate = doc.fork();
        let imported = candidate.import(update).map_err(decode_error)?;
        if imported.pending.is_some() {
            return Err(Error::InvalidConfig(
                "window update has unresolved dependencies".into(),
            ));
        }
        candidate
    };
    let is_diagnostic = |blob: &[u8]| {
        EntityMetadataHeader::parse(blob)
            .is_some_and(|header| header.entity_type == ENTITY_TYPE_DIAGNOSTIC)
    };
    if metadata.mode.is_snapshot() {
        let mut diagnostic = false;
        let mut misplaced = false;
        map_for_each_value_bytes(&candidate.get_map("entities"), |_, blob| {
            diagnostic |= blob.is_some_and(is_diagnostic);
            misplaced |= key.is_some_and(|key| {
                blob.is_none_or(|blob| !crate::sync::types::entity_belongs_to_window(blob, key))
            });
        });
        if diagnostic {
            return Err(Error::InvalidConfig(
                "diagnostic observations are local-only".into(),
            ));
        }
        if misplaced {
            return Err(Error::InvalidConfig(
                "entity outside window residence".into(),
            ));
        }
    }
    let entities = ContainerID::new_root("entities", ContainerType::Map);
    let edges = ContainerID::new_root("edges", ContainerType::Map);
    let tombstones = ContainerID::new_root("tombstones", ContainerType::Map);
    let operations =
        candidate.export_json_updates(&metadata.partial_start_vv, &metadata.partial_end_vv);
    // A fork of a shallow window may no longer retain operations repeated in
    // this input. Refuse an incomplete inspection instead of forwarding bytes
    // whose history is unavailable to the admission check.
    let expected = metadata
        .partial_end_vv
        .iter()
        .try_fold(0_usize, |total, (peer, end)| {
            let start = metadata.partial_start_vv.get(peer).copied().unwrap_or(0);
            let count = usize::try_from(end.checked_sub(start)?).ok()?;
            total.checked_add(count)
        });
    let inspected = operations
        .changes
        .iter()
        .flat_map(|change| &change.ops)
        .try_fold(0_usize, |total, op| total.checked_add(op.content.op_len()));
    if expected.is_none() || expected != inspected {
        return Err(Error::InvalidConfig(
            "window update history is unavailable".into(),
        ));
    }
    // A deleted world's live map has no claim body, but ordinary Loro
    // history retains the validated insertion that assigned its world. Keep
    // that evidence until every edge op in this same import is inspected.
    let mut historical = HashMap::<EntityId, Vec<u8>>::new();
    for op in operations.changes.iter().flat_map(|change| &change.ops) {
        if op.container == entities
            && let JsonOpContent::Map(MapOp::Insert {
                key: raw_key,
                value: LoroValue::Binary(blob),
            }) = &op.content
            && let Ok(id) = EntityId::from_hex(raw_key)
        {
            historical.insert(id, blob.to_vec());
        }
    }
    if metadata.mode.is_snapshot()
        && let (Some(key), Some(vault)) = (key, vault)
    {
        let edges = candidate.get_map("edges");
        let mut edge_keys = Vec::new();
        edges.for_each(|edge, _| edge_keys.push(edge.to_owned()));
        for edge in edge_keys {
            check_edge_residence(vault, &candidate, &edge, key, &historical)?;
        }
        let tombstones = candidate.get_map("tombstones");
        let mut tombstone_keys = Vec::new();
        tombstones.for_each(|id, _| tombstone_keys.push(id.to_owned()));
        for id in tombstone_keys {
            check_tombstone_residence(vault, &id, key)?;
        }
    }
    for op in operations.changes.into_iter().flat_map(|change| change.ops) {
        let JsonOpContent::Map(MapOp::Insert {
            key: map_key,
            value,
        }) = op.content
        else {
            continue;
        };
        if op.container == entities {
            match value {
                LoroValue::Binary(blob) => {
                    if is_diagnostic(&blob) {
                        return Err(Error::InvalidConfig(
                            "diagnostic observations are local-only".into(),
                        ));
                    }
                    if key.is_some_and(|key| {
                        !crate::sync::types::entity_belongs_to_window(&blob, key)
                    }) {
                        return Err(Error::InvalidConfig(
                            "entity outside window residence".into(),
                        ));
                    }
                }
                _ if key.is_some_and(|key| key.world().is_some()) => {
                    return Err(Error::InvalidConfig("non-binary world entity".into()));
                }
                _ => {}
            }
        } else if let (Some(key), Some(vault)) = (key, vault) {
            if op.container == edges {
                check_edge_residence(vault, &candidate, &map_key, key, &historical)?;
            } else if op.container == tombstones {
                check_tombstone_residence(vault, &map_key, key)?;
            }
        }
    }
    Ok(())
}

fn check_edge_residence(
    vault: &crate::Vault,
    doc: &LoroDoc,
    edge: &str,
    key: &crate::sync::WindowKey,
    historical: &HashMap<EntityId, Vec<u8>>,
) -> Result<()> {
    let denied = || Error::InvalidConfig("edge outside window residence".into());
    let Some((src, _, tgt)) = crate::sync::bridge::parse_edge_key(edge) else {
        return if key.world().is_none() {
            Ok(())
        } else {
            Err(Error::InvalidKey)
        };
    };
    let txn = vault.store.env.read_txn()?;
    if crate::sync::types::edge_belongs_to_window_in(vault, &txn, doc, &src, &tgt, key)? {
        return Ok(());
    }
    if key.world().is_none() {
        return Err(denied());
    }
    let entities = doc.get_map("entities");
    let mut worlds = [None, None];
    let mut learned = [None, None];
    for (index, id) in [src, tgt].iter().enumerate() {
        let stored = vault.store.entities.get(&txn, id.as_bytes())?;
        let live = map_get_bytes(&entities, &id.to_hex());
        let old = historical.get(id);
        let raw = if let Some(stored) = stored.as_deref() {
            let header = EntityMetadataHeader::parse(stored)
                .ok_or(Error::CorruptedIndex("entity metadata"))?;
            if header.entity_type == crate::registry::ENTITY_TYPE_CLAIM
                && stored.len() == crate::batch::ENTITY_METADATA_HEADER_LEN
            {
                let old = old.ok_or_else(denied)?;
                let old_header = EntityMetadataHeader::parse(old).ok_or_else(denied)?;
                if old_header.learned_at != header.learned_at {
                    return Err(denied());
                }
                old.as_slice()
            } else {
                stored
            }
        } else if let Some(live) = live.as_deref() {
            live
        } else {
            old.map(Vec::as_slice).ok_or_else(denied)?
        };
        let header = EntityMetadataHeader::parse(raw).ok_or_else(denied)?;
        worlds[index] = Some(crate::sync::types::entity_world(raw)?);
        learned[index] = Some(header.learned_at);
    }
    if !crate::sync::types::edge_worlds_match(worlds[0].flatten(), worlds[1].flatten(), key) {
        return Err(denied());
    }
    let carrier = if worlds[0].flatten().is_none() {
        learned[1]
    } else {
        learned[0]
    };
    if carrier
        .is_none_or(|at| crate::sync::WindowKey::from_timestamp(at).as_str() != &key.as_str()[..7])
    {
        return Err(denied());
    }
    Ok(())
}

fn check_tombstone_residence(
    vault: &crate::Vault,
    id: &str,
    key: &crate::sync::WindowKey,
) -> Result<()> {
    let Ok(id) = crate::EntityId::from_hex(id) else {
        return if key.world().is_none() {
            Ok(())
        } else {
            Err(Error::InvalidKey)
        };
    };
    let txn = vault.store.env.read_txn()?;
    if crate::sync::types::tombstone_residence_in(vault, &txn, &id, key)?
        == crate::sync::types::TombstoneResidence::Wrong
    {
        return Err(Error::InvalidConfig(
            "tombstone outside window residence".into(),
        ));
    }
    Ok(())
}
