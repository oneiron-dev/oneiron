//! The fork mirror: each fork of a typed body the window carries, written into
//! the window's document beside its body.

use super::*;

/// Writes into `doc`, window `window`'s document, each fork of the typed
/// bodies among `entities` this vault holds that adds to the window's copy:
/// one the window lacks, or one that holds all of the window's copy and more
/// (`CarriedFork::covers`). A window copy that holds what this vault's lacks
/// stands, merged here as it lands. The window is pinned history-free before
/// a copy naming an actor this vault erased changes. Each fork's row commits
/// on its own, after this pass's other writes, and each part of a snapshot
/// too large to ride in its row after it, so no one update holds more than a
/// part. Returns whether it wrote.
pub(crate) fn mirror_typed_body_forks(
    vault: &Vault,
    doc: &LoroDoc,
    window: &WindowKey,
    entities: &[EntityId],
) -> Result<bool> {
    if window.world().is_some() {
        return Ok(false);
    }
    let bodies = {
        let rtxn = vault.store.env.read_txn()?;
        let mut bodies = Vec::new();
        for entity in entities {
            if crate::typed_body::sync_frame::has_typed_body_in_txn(&vault.store, &rtxn, entity)? {
                bodies.push(*entity);
            }
        }
        bodies
    };
    let mut wrote = false;
    for entity in &bodies {
        wrote |= mirror_body_forks(vault, doc, window, entity)?;
    }
    Ok(wrote)
}

/// [`mirror_typed_body_forks`] for the forks of `entity`'s body.
fn mirror_body_forks(
    vault: &Vault,
    doc: &LoroDoc,
    window: &WindowKey,
    entity: &EntityId,
) -> Result<bool> {
    let owner = &OFFICE_BODY_OWNER;
    let (writes, pin) = {
        let rtxn = vault.store.env.read_txn()?;
        let held = carried_forks_in_txn(vault, &rtxn, entity, owner)?;
        if held.is_empty() {
            return Ok(false);
        }
        let map = doc.get_map(TYPED_BODY_ROWS_MAP);
        let mut writes = Vec::new();
        let mut pin = false;
        for carried in held {
            let key = fork_key(&carried);
            let copy = map_get_bytes(&map, &key).and_then(|bytes| decode_fork(&bytes).ok());
            if let Some(copy) = &copy {
                // The same row: its snapshot may ride whole or in parts. A
                // row whose parts have not all landed in the window (a mirror
                // cut off after its manifest committed) is written again,
                // which writes only the parts the window lacks; otherwise no
                // receiver could ever join its snapshot.
                if copy.birth == carried.birth
                    && copy.record == carried.record
                    && copy.companion == carried.companion
                {
                    if snapshot_parts(copy).is_none_or(|parts| {
                        parts.keys().all(|part| map_contains_binary(&map, &part))
                    }) {
                        continue;
                    }
                    writes.push((key, carried, None));
                    continue;
                }
                match copy.clone().carried_here(vault, &rtxn, owner)? {
                    Some(here) => {
                        if !carried.covers(&here, owner)? {
                            continue;
                        }
                        pin |= here != *copy;
                    }
                    None => pin = true,
                }
            }
            writes.push((key, carried, copy));
        }
        (writes, pin)
    };
    if writes.is_empty() {
        return Ok(false);
    }
    if pin {
        super::super::window::require_history_free_window(vault, window)?;
    }
    let map = doc.get_map(TYPED_BODY_ROWS_MAP);
    for (key, carried, replaced) in &writes {
        write_fork(doc, &map, key, carried, replaced.as_ref())?;
    }
    Ok(true)
}

fn commit(doc: &LoroDoc) {
    doc.commit_with(CommitOptions::new().origin(BRIDGE_ORIGIN));
}

/// Writes `carried` under `key`: its snapshot in its row while the row fits
/// a part, else in linked parts written after the row, each committing on
/// its own. Each part of `replaced`, the copy it replaces, that no fork row
/// lists now goes.
fn write_fork(
    doc: &LoroDoc,
    map: &LoroMap,
    key: &str,
    carried: &CarriedFork,
    replaced: Option<&CarriedFork>,
) -> Result<()> {
    let whole = encode_fork(carried)?;
    match &carried.snapshot {
        Some(ForkSnapshot::Whole(snapshot)) if whole.len() > PART_BYTES => {
            let (parts, pieces) = split_parts(snapshot)?;
            let row = CarriedFork {
                snapshot: Some(ForkSnapshot::Parts(parts)),
                ..carried.clone()
            };
            map_insert_bytes(map, key, &encode_fork(&row)?)?;
            commit(doc);
            write_parts(map, &pieces, || commit(doc))?;
        }
        _ => {
            map_insert_bytes(map, key, &whole)?;
            commit(doc);
        }
    }
    if let Some(old) = replaced.and_then(snapshot_parts) {
        let listed = listed_parts(map);
        let mut gone = false;
        for part in old.keys() {
            if !listed.contains(&part) && map_contains_binary(map, &part) {
                map_delete(map, &part)?;
                gone = true;
            }
        }
        if gone {
            commit(doc);
        }
    }
    Ok(())
}

/// The key of each part a fork row `map` holds lists.
fn listed_parts(map: &LoroMap) -> BTreeSet<String> {
    let mut listed = BTreeSet::new();
    for (_, bytes) in row_values(map, |map_key| map_key.starts_with(FORK_KEY_PREFIX)) {
        if let Ok(carried) = decode_fork(&bytes)
            && let Some(parts) = snapshot_parts(&carried)
        {
            listed.extend(parts.keys());
        }
    }
    listed
}
