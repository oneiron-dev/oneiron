//! Full-window UPDATE locality admission without live document side effects.

use std::collections::HashMap;

use loro::json::{JsonOpContent, MapOp};
use loro::{ContainerID, ContainerType, LoroDoc, LoroValue};

use crate::EntityId;
use crate::batch::EntityMetadataHeader;
use crate::error::SyncError;
use crate::registry::{
    ENTITY_TYPE_DIAGNOSTIC, ENTITY_TYPE_SECRET_CUSTODY, ENTITY_TYPE_WORLD_KEY_PAD,
};
use crate::sync::loro_support::{TombstoneIndex, map_for_each_value_bytes, map_get_bytes};
use crate::{Error, Result};

/// Refuses diagnostic and secret-custody carriers before a full-window update
/// can mutate the live document, materialize rows, persist bytes or fan out to
/// another peer.
///
/// Inspect the incoming operation range, not just final map state: a put
/// followed by a delete still carries the refused body in wire history.
/// A snapshot also carries live state, and a shallow one its root state,
/// outside its retained operation range.
/// Missing causal dependencies are refused rather than relaying uninspected
/// pending operations; a peer can negotiate the missing prefix and retry.
pub fn validate_window_update_locality(doc: &LoroDoc, update: &[u8]) -> Result<()> {
    validate_window_update(doc, update, None, None, &HashMap::new())
}

/// Checks a peer's complete operation range against the window's world axis.
/// Production imports use the vault-aware door below instead.
#[cfg(test)]
pub(in crate::sync) fn validate_window_update_residence(
    doc: &LoroDoc,
    update: &[u8],
    key: &crate::sync::WindowKey,
) -> Result<()> {
    validate_window_update(doc, update, Some(key), None, &HashMap::new())
}

/// Owner-lane admission with the vault's durable entity residence as proof
/// for edges and tombstones. Run before importing or relaying the update.
pub fn validate_window_update_residence_with_vault(
    vault: &crate::Vault,
    doc: &LoroDoc,
    update: &[u8],
    key: &crate::sync::WindowKey,
) -> Result<()> {
    validate_window_update(doc, update, Some(key), Some(vault), &HashMap::new())
}

/// Client-only cross-month staging evidence. Rows are kept in RAM until the
/// owner window carrying them passes its own residence and history admission.
pub(in crate::sync) fn validate_window_update_with_staged_worlds(
    vault: &crate::Vault,
    doc: &LoroDoc,
    update: &[u8],
    key: &crate::sync::WindowKey,
    staged: &HashMap<EntityId, (crate::sync::WindowKey, Vec<u8>)>,
) -> Result<()> {
    validate_window_update(doc, update, Some(key), Some(vault), staged)
}

fn validate_window_update(
    doc: &LoroDoc,
    update: &[u8],
    key: Option<&crate::sync::WindowKey>,
    vault: Option<&crate::Vault>,
    staged: &HashMap<EntityId, (crate::sync::WindowKey, Vec<u8>)>,
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
    let candidate_tombstones = TombstoneIndex::build(&candidate.get_map("tombstones"));
    let local_only = |blob: &[u8]| {
        EntityMetadataHeader::parse(blob).and_then(|header| match header.entity_type {
            ENTITY_TYPE_DIAGNOSTIC => Some(Error::InvalidConfig(
                "diagnostic observations are local-only".into(),
            )),
            ENTITY_TYPE_SECRET_CUSTODY => Some(crate::secret_custody::reject_secret_custody_byte()),
            // A destroyed world's pad arriving late never rejoins a window;
            // a live world's pad replicates with the base rows.
            ENTITY_TYPE_WORLD_KEY_PAD => vault.and_then(|vault| late_pad(vault, blob)),
            _ => None,
        })
    };
    if let Some(key) = key {
        let witnesses = candidate.get_map("retained_claim_worlds");
        let mut invalid_witness = false;
        witnesses.for_each(|raw, value| {
            let valid_id = EntityId::from_hex(raw)
                .ok()
                .is_some_and(|id| id.to_hex() == raw);
            let valid_world = matches!(value,
                loro::ValueOrContainer::Value(LoroValue::Binary(bytes))
                    if key.world().is_some_and(|world| bytes.as_slice() == world.as_bytes()));
            invalid_witness |= !valid_id || !valid_world;
        });
        if invalid_witness || (key.world().is_none() && !witnesses.is_empty()) {
            return Err(Error::InvalidConfig(
                "invalid retained world witness".into(),
            ));
        }
        if key.world().is_some() {
            let mut shells = Vec::new();
            map_for_each_value_bytes(&candidate.get_map("entities"), |raw, blob| {
                if let Some(blob) = blob
                    && EntityMetadataHeader::parse(blob).is_some_and(|header| {
                        header.entity_type == crate::registry::ENTITY_TYPE_CLAIM
                            && blob.len() == crate::batch::ENTITY_METADATA_HEADER_LEN
                    })
                {
                    shells.push((raw.to_owned(), blob.to_vec()));
                }
            });
            for (raw, blob) in shells {
                let Some(vault) = vault else {
                    return Err(Error::InvalidConfig(
                        "world shell needs vault residence".into(),
                    ));
                };
                let id = EntityId::from_hex(&raw).map_err(|_| Error::InvalidKey)?;
                let txn = vault.store.env.read_txn()?;
                if !crate::sync::types::retained_world_shell_belongs_to_window(
                    vault,
                    &txn,
                    &candidate,
                    &candidate_tombstones,
                    &id,
                    &blob,
                    key,
                    false,
                )? {
                    return Err(Error::InvalidConfig("unproven world shell".into()));
                }
            }
        }
    }
    if metadata.mode.is_snapshot() {
        let mut refused = None;
        let mut misplaced = false;
        map_for_each_value_bytes(&candidate.get_map("entities"), |_, blob| {
            if refused.is_none() {
                refused = blob.and_then(local_only);
            }
            misplaced |= key.is_some_and(|key| {
                blob.is_none_or(|blob| {
                    !(crate::sync::types::entity_belongs_to_window(blob, key)
                        || (key.world().is_some()
                            && blob.len() == crate::batch::ENTITY_METADATA_HEADER_LEN
                            && EntityMetadataHeader::parse(blob).is_some_and(|header| {
                                header.entity_type == crate::registry::ENTITY_TYPE_CLAIM
                            })))
                })
            });
        });
        if let Some(error) = refused {
            return Err(error);
        }
        // OF-422: every custody transition the snapshot holds is the owner's.
        crate::sync::custody::admit_custody_map(
            vault,
            key,
            &candidate.get_map(crate::sync::custody::CUSTODY_MAP),
        )?;
        // A snapshot can also carry the state at a root, where a carrier
        // deleted after the root survives outside the retained ops, and
        // later exports reuse that root as encoded. Two Loro readers decode
        // it: the state load keeps a container's last table entry and the
        // root-history load its first, so first require tables that read
        // one way. Then a read through Loro can still be steered away from
        // the root: the latest-state section masks it, and replay or checkout
        // resolves a key from a retained op that shares the root entry's id.
        // So decode the snapshot with its root section standing in as the
        // latest state, which Loro loads as-is with no replay, and read the
        // root's own values. Every value Loro can later derive comes from
        // that section, the retained ops or the latest-state section, and
        // each is read here.
        let corrupt = || decode_error(loro::LoroError::DecodeDataCorruptionError);
        let sections = snapshot_sections(update).ok_or_else(corrupt)?;
        let [_, latest, root] = sections;
        if !(latest == EMPTY_STATE || state_section_is_canonical(latest))
            || !state_section_is_canonical(root)
        {
            return Err(Error::InvalidConfig(
                "snapshot state is not canonical".into(),
            ));
        }
        if !root.is_empty() {
            let root = root_as_latest_state(update, sections).ok_or_else(corrupt)?;
            let root = LoroDoc::from_snapshot(&root).map_err(decode_error)?;
            let mut at_root = None;
            map_for_each_value_bytes(&root.get_map("entities"), |_, blob| {
                if at_root.is_none() {
                    at_root = blob.and_then(local_only);
                }
            });
            if let Some(error) = at_root {
                return Err(error);
            }
            crate::sync::custody::admit_custody_map(
                vault,
                key,
                &root.get_map(crate::sync::custody::CUSTODY_MAP),
            )?;
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
            check_edge_residence(
                vault,
                &candidate,
                &candidate_tombstones,
                &edge,
                key,
                &historical,
                staged,
            )?;
        }
        let tombstones = candidate.get_map("tombstones");
        let mut tombstone_keys = Vec::new();
        tombstones.for_each(|id, _| tombstone_keys.push(id.to_owned()));
        for id in tombstone_keys {
            check_tombstone_residence(vault, &id, key)?;
        }
    }
    let witnesses = ContainerID::new_root("retained_claim_worlds", ContainerType::Map);
    let births = ContainerID::new_root(crate::sync::row_birth::ROW_BIRTHS_MAP, ContainerType::Map);
    let custody = ContainerID::new_root(crate::sync::custody::CUSTODY_MAP, ContainerType::Map);
    for op in operations.changes.into_iter().flat_map(|change| change.ops) {
        let JsonOpContent::Map(MapOp::Insert {
            key: map_key,
            value,
        }) = op.content
        else {
            continue;
        };
        if op.container == births {
            crate::sync::row_birth::validate_carried_birth(&candidate, &map_key, &value)?;
        } else if op.container == custody {
            // OF-422: put-then-delete still carries the bytes on the wire.
            crate::sync::custody::admit_custody_carrier(vault, key, &map_key, &value)?;
        } else if op.container == witnesses {
            if key.is_none_or(|key| key.world().is_none())
                || !matches!(value, LoroValue::Binary(ref bytes)
                    if key.and_then(crate::sync::WindowKey::world)
                        .is_some_and(|world| bytes.as_slice() == world.as_bytes()))
            {
                return Err(Error::InvalidConfig(
                    "invalid retained world witness".into(),
                ));
            }
        } else if op.container == entities {
            match value {
                LoroValue::Binary(blob) => {
                    if let Some(error) = local_only(&blob) {
                        return Err(error);
                    }
                    if key.is_some_and(|key| {
                        !(crate::sync::types::entity_belongs_to_window(&blob, key)
                            || (blob.len() == crate::batch::ENTITY_METADATA_HEADER_LEN
                                && key.world().is_some()
                                && vault.is_some_and(|vault| {
                                    let Ok(id) = EntityId::from_hex(&map_key) else {
                                        return false;
                                    };
                                    let Ok(txn) = vault.store.env.read_txn() else {
                                        return false;
                                    };
                                    crate::sync::types::retained_world_shell_belongs_to_window(
                                        vault,
                                        &txn,
                                        &candidate,
                                        &candidate_tombstones,
                                        &id,
                                        &blob,
                                        key,
                                        false,
                                    )
                                    .unwrap_or(false)
                                })))
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
                check_edge_residence(
                    vault,
                    &candidate,
                    &candidate_tombstones,
                    &map_key,
                    key,
                    &historical,
                    staged,
                )?;
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
    tombstones: &TombstoneIndex,
    edge: &str,
    key: &crate::sync::WindowKey,
    historical: &HashMap<EntityId, Vec<u8>>,
    staged: &HashMap<EntityId, (crate::sync::WindowKey, Vec<u8>)>,
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
    if crate::sync::types::edge_belongs_to_window_in(vault, &txn, doc, tombstones, &src, &tgt, key)?
    {
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
            match old {
                Some(raw) => raw.as_slice(),
                None => {
                    let Some((staged_key, raw)) = staged.get(id) else {
                        return Err(Error::InvalidConfig("edge endpoint unresolved".into()));
                    };
                    if staged_key.world() != key.world()
                        || !crate::sync::types::entity_belongs_to_window(raw, staged_key)
                    {
                        return Err(denied());
                    }
                    raw.as_slice()
                }
            }
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

/// Loro 1.16 lays a fast snapshot out as a header (magic, checksum, mode)
/// and three u32-length-prefixed sections: ops, latest state, root state.
const SNAPSHOT_HEADER: usize = 22;
/// A latest-state section Loro left out: the decode replays from the root.
const EMPTY_STATE: &[u8] = b"E";

/// The sections of a fast snapshot, `None` for any other layout, so
/// admission refuses rather than guesses.
fn snapshot_sections(snapshot: &[u8]) -> Option<[&[u8]; 3]> {
    let mut rest = snapshot.get(SNAPSHOT_HEADER..)?;
    let mut sections = [&[][..]; 3];
    for section in &mut sections {
        let (len, tail) = rest.split_first_chunk::<4>()?;
        let len = usize::try_from(u32::from_le_bytes(*len)).ok()?;
        (*section, rest) = tail.split_at_checked(len)?;
    }
    rest.is_empty().then_some(sections)
}

/// `snapshot` with its root-state section copied over its latest-state
/// section, so a decode loads the encoded root as the doc's state and
/// replays nothing. The checksum is xxh32 over everything from byte 20.
fn root_as_latest_state(snapshot: &[u8], [ops, _, root]: [&[u8]; 3]) -> Option<Vec<u8>> {
    let mut rebuilt = snapshot.get(..SNAPSHOT_HEADER)?.to_vec();
    for section in [ops, root, root] {
        rebuilt.extend_from_slice(&u32::try_from(section.len()).ok()?.to_le_bytes());
        rebuilt.extend_from_slice(section);
    }
    let checksum = xxhash_rust::xxh32::xxh32(&rebuilt[20..], u32::from_le_bytes(*b"LORO"));
    rebuilt[16..20].copy_from_slice(&checksum.to_le_bytes());
    Some(rebuilt)
}

/// Whether a state section reads one way through every Loro reader: empty,
/// or a table whose blocks validate and whose keys strictly increase, each
/// the canonical bytes of a container id or the frontiers entry. Loro's own
/// encoder writes only such tables.
fn state_section_is_canonical(section: &[u8]) -> bool {
    if section.is_empty() {
        return true;
    }
    let Ok(table) = loro::kv_store::sstable::SsTable::import_all(section.to_vec().into(), true)
    else {
        return false;
    };
    let mut previous: Option<Vec<u8>> = None;
    table.iter().all(|(key, _)| {
        let key = &key[..];
        let canonical =
            key == b"fr" || ContainerID::try_from_bytes(key).is_ok_and(|id| id.to_bytes() == key);
        let increasing = previous.as_deref().is_none_or(|previous| previous < key);
        previous = Some(key.to_vec());
        canonical && increasing
    })
}

/// The refusal of a late pad `blob`: one of a world whose keys this replica
/// destroyed. A replica that cannot read its own destruction facts refuses.
fn late_pad(vault: &crate::Vault, blob: &[u8]) -> Option<Error> {
    let late = (|| -> Result<bool> {
        let txn = vault.store.env.read_txn()?;
        crate::world_keys::late_pad_in_txn(&vault.store, &txn, blob)
    })();
    match late {
        Ok(false) => None,
        Ok(true) => Some(Error::InvalidConfig(
            "a destroyed world's key pad cannot rejoin a window".into(),
        )),
        Err(error) => Some(error),
    }
}
