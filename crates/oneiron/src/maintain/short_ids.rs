//! Short-id hash refresh, orphan reap, and alias-backing guards.

use std::collections::{HashMap, HashSet};

use xxhash_rust::xxh32::xxh32;

use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, encode_short_id_forward_key, parse_short_id_value};
use crate::entity_id::parse_entity_id;
use crate::error::{Error, Result};
use crate::store::ShortIdAliasTarget;

/// Recomputes short-id content hashes and reaps orphaned/stale mappings under
/// the pinned ARCH-0019 directions: `short_ids_reverse` (entity id ->
/// `short_id ‖ content_hash`) is the entity-keyed source of truth; `short_ids`
/// (`short_id ‖ content_hash` -> entity id) is repaired or pruned from it.
pub(super) fn recompute_short_id_hashes(vault: &Vault) -> Result<(u64, u64)> {
    struct ShortIdHashUpdate {
        reverse_key: Vec<u8>,
        updated_value: Vec<u8>,
        owned_old_forward_key: Option<Vec<u8>>,
        new_forward_key: Vec<u8>,
    }

    let mut wtxn = vault.store.env.write_txn()?;

    // Pass 1: walk the entity-keyed reverse rows. Refresh drifted content
    // hashes (rewriting BOTH rows — the hash is part of the forward KEY),
    // repair missing/stale forward rows, and reap rows whose backing entity
    // record is gone or whose bytes are corrupt.
    let mut hash_updates: Vec<ShortIdHashUpdate> = Vec::new();
    // (forward key, entity id) rows to (re)write.
    let mut forward_repairs: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    // Forward keys written by this pass. Pass 2 consults this so an
    // intra-pass refresh/repair can never be collected from a stale view of
    // the reverse row it just fixed.
    let mut reserved_forward_keys: HashSet<Vec<u8>> = HashSet::new();
    // (reverse key, paired forward key when recoverable) rows to reap.
    let mut reverse_orphans: Vec<(Vec<u8>, Option<Vec<u8>>)> = Vec::new();

    for entry in vault.store.short_ids_reverse.iter(&wtxn)? {
        let (key, value) = entry?;

        let id = match parse_entity_id(&key, ERR_SHORT_IDS_REVERSE_KEY) {
            Ok(id) => id,
            // `parse_entity_id` returns `CorruptedIndex` on length mismatch
            // and `InvalidKey` for reserved sentinel patterns. Both are
            // corrupt reverse rows that must be pruned, not propagated.
            Err(Error::CorruptedIndex(_)) | Err(Error::InvalidKey) => {
                // The reverse key is corrupt, so its value cannot safely name
                // a forward row. A corrupt/aliased value could point at a
                // healthy forward row for another entity. Fail closed: prune
                // only this reverse row; pass 2 owns forward-row reaping from
                // valid forward keys. (ONE-1114 delete-safety.)
                reverse_orphans.push((key.to_vec(), None));
                continue;
            }
            Err(other) => return Err(other),
        };

        let (short_id, current_hash) = match parse_short_id_value(&value) {
            Ok(parsed) => parsed,
            Err(Error::CorruptedIndex(_)) => {
                reverse_orphans.push((key.to_vec(), None));
                continue;
            }
            Err(other) => return Err(other),
        };
        let current_forward_key = encode_short_id_forward_key(short_id, current_hash);

        let Some(blob) = vault.store.entities.get(&wtxn, id.as_bytes())? else {
            let owned_forward_key = match vault.store.short_ids.get(&wtxn, &current_forward_key)? {
                Some(forward_id) if forward_id == key => Some(current_forward_key),
                Some(_) => {
                    tracing::warn!(
                        "short-id maintenance skipped unowned reverse-derived forward reap"
                    );
                    None
                }
                None => None,
            };
            reverse_orphans.push((key.to_vec(), owned_forward_key));
            continue;
        };

        if blob.len() < ENTITY_METADATA_HEADER_LEN {
            return Err(Error::InvalidKey);
        }

        let payload = &blob[ENTITY_METADATA_HEADER_LEN..];
        let new_hash = (xxh32(payload, 0) % 256) as u8;
        if new_hash != current_hash {
            let mut updated_value = Vec::with_capacity(short_id.len() + 1);
            updated_value.extend_from_slice(short_id.as_bytes());
            updated_value.push(new_hash);
            let new_forward_key = encode_short_id_forward_key(short_id, new_hash);
            if let Some(forward_id) = vault.store.short_ids.get(&wtxn, &new_forward_key)?
                && forward_id != key
            {
                if forward_key_is_claimed_by_reverse(vault, &wtxn, &forward_id, &new_forward_key)? {
                    tracing::warn!(
                        "short-id maintenance pruned backed reverse row with owned refreshed forward alias"
                    );
                    reverse_orphans.push((key.to_vec(), None));
                } else {
                    tracing::warn!(
                        "short-id maintenance skipped stale reverse-derived forward overwrite"
                    );
                }
                continue;
            }
            let owned_old_forward_key =
                match vault.store.short_ids.get(&wtxn, &current_forward_key)? {
                    Some(forward_id) if forward_id == key => Some(current_forward_key),
                    Some(_) => {
                        tracing::warn!(
                            "short-id maintenance skipped unowned reverse-derived forward delete"
                        );
                        None
                    }
                    None => None,
                };
            reserved_forward_keys.insert(new_forward_key.clone());
            hash_updates.push(ShortIdHashUpdate {
                reverse_key: key.to_vec(),
                updated_value,
                owned_old_forward_key,
                new_forward_key,
            });
            continue;
        }

        match vault.store.short_ids.get(&wtxn, &current_forward_key)? {
            Some(forward_id) if forward_id == key => {}
            Some(forward_id) => {
                if forward_key_is_claimed_by_reverse(
                    vault,
                    &wtxn,
                    &forward_id,
                    &current_forward_key,
                )? {
                    tracing::warn!(
                        "short-id maintenance pruned backed reverse row with owned forward alias"
                    );
                    reverse_orphans.push((key.to_vec(), None));
                } else {
                    tracing::warn!(
                        "short-id maintenance skipped stale reverse-derived forward overwrite"
                    );
                }
            }
            None => {
                reserved_forward_keys.insert(current_forward_key.clone());
                forward_repairs.push((current_forward_key, key.to_vec()));
            }
        }
    }

    for update in &hash_updates {
        vault
            .store
            .short_ids_reverse
            .put(&mut wtxn, &update.reverse_key, &update.updated_value)?;
        if let Some(old_forward_key) = &update.owned_old_forward_key {
            vault.store.short_ids.delete(&mut wtxn, old_forward_key)?;
        }
        vault
            .store
            .short_ids
            .put(&mut wtxn, &update.new_forward_key, &update.reverse_key)?;
    }
    for (forward_key, id) in &forward_repairs {
        vault.store.short_ids.put(&mut wtxn, forward_key, id)?;
    }

    // ONE-1930: an alias names its target by FORWARD KEY, and the content hash
    // is part of that key — so a hash refresh above has just invalidated every
    // alias pointing at the row it moved. Retarget them here, before pass 2
    // consults aliases for ownership, or the legacy rows they back look like
    // orphans and get reaped.
    let moved_targets: HashMap<&[u8], &[u8]> = hash_updates
        .iter()
        .filter_map(|update| {
            Some((
                update.owned_old_forward_key.as_deref()?,
                update.new_forward_key.as_slice(),
            ))
        })
        .collect();
    if !moved_targets.is_empty() {
        for (legacy_id, target) in vault.store.short_id_aliases(&wtxn)? {
            let ShortIdAliasTarget::EntityForwardKey(old_key) = &target else {
                continue;
            };
            let Some(new_key) = moved_targets.get(old_key.as_slice()) else {
                continue;
            };
            vault.store.retarget_short_id_alias(
                &mut wtxn,
                &legacy_id,
                &target,
                &ShortIdAliasTarget::EntityForwardKey((*new_key).to_vec()),
            )?;
        }
    }
    for (reverse_key, forward_key) in &reverse_orphans {
        // `Some(forward_key)` entries are queued only from validly keyed
        // reverse rows; corrupt-keyed rows prune only themselves.
        if let Some(forward_key) = forward_key {
            vault.store.short_ids.delete(&mut wtxn, forward_key)?;
        }
        vault
            .store
            .short_ids_reverse
            .delete(&mut wtxn, reverse_key)?;
    }

    // Pass 2: forward rows without a healthy reverse counterpart are orphans.
    // Runs after pass-1 writes so repaired/refreshed rows are not re-pruned.
    let mut forward_orphans = Vec::new();
    for entry in vault.store.short_ids.iter(&wtxn)? {
        let (key, value) = entry?;

        // The forward KEY shares the `(short_id ‖ content_hash)` shape with
        // the reverse VALUE; an unparsable key is a corrupt row to prune.
        if parse_short_id_value(&key).is_err() {
            forward_orphans.push(key.to_vec());
            continue;
        }

        let id = match parse_entity_id(&value, ERR_SHORT_IDS_FORWARD_VALUE) {
            Ok(id) => id,
            Err(Error::CorruptedIndex(_)) | Err(Error::InvalidKey) => {
                forward_orphans.push(key.to_vec());
                continue;
            }
            Err(other) => return Err(other),
        };

        let reverse_value = vault.store.short_ids_reverse.get(&wtxn, id.as_bytes())?;
        match reverse_value.as_deref() {
            Some(reverse_value) if *reverse_value == *key => {}
            _ if reserved_forward_keys.contains(key.as_ref()) => {
                tracing::warn!(
                    "short-id maintenance kept in-pass reserved forward row despite stale reverse view"
                );
            }
            canonical => {
                if !forward_row_is_alias_backed(vault, &wtxn, &key, canonical)? {
                    forward_orphans.push(key.to_vec());
                }
            }
        }
    }
    for forward_key in &forward_orphans {
        vault.store.short_ids.delete(&mut wtxn, forward_key)?;
    }

    wtxn.commit()?;
    Ok((
        hash_updates.len() as u64,
        (reverse_orphans.len() + forward_orphans.len()) as u64,
    ))
}

/// Whether a forward row that does NOT match its entity's reverse row is a
/// deliberately retained legacy row rather than orphan garbage (ONE-1930).
///
/// It is retained when an alias for its presentation id names that same
/// entity's CURRENT canonical row: the legacy id, the legacy forward row and
/// the canonical row then all agree about which entity they describe, which is
/// exactly the post-re-key steady state. Any weaker test would let a genuinely
/// stale row survive by merely having an alias somewhere.
fn forward_row_is_alias_backed(
    vault: &Vault,
    txn: &heed::RwTxn<'_>,
    forward_key: &[u8],
    canonical_forward_key: Option<&[u8]>,
) -> Result<bool> {
    let Some(canonical) = canonical_forward_key else {
        return Ok(false);
    };
    let Ok((short_id, _)) = parse_short_id_value(forward_key) else {
        return Ok(false);
    };
    Ok(matches!(
        vault.store.resolve_short_id_alias(txn, short_id)?,
        Some(ShortIdAliasTarget::EntityForwardKey(target)) if target == canonical
    ))
}

fn forward_key_is_claimed_by_reverse(
    vault: &Vault,
    txn: &heed::RwTxn<'_>,
    forward_id: &[u8],
    forward_key: &[u8],
) -> Result<bool> {
    let Ok(owner) = parse_entity_id(forward_id, ERR_SHORT_IDS_FORWARD_VALUE) else {
        return Ok(false);
    };
    Ok(matches!(
        vault.store.short_ids_reverse.get(txn, owner.as_bytes())?,
        Some(reverse_value) if *reverse_value == *forward_key
    ))
}

const ERR_SHORT_IDS_REVERSE_KEY: &str = "short_ids_reverse key";

const ERR_SHORT_IDS_FORWARD_VALUE: &str = "short_ids value";
