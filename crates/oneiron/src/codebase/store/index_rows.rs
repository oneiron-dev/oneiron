use super::*;

pub(super) fn fork_has_other_snapshot(
    store: &Store,
    wtxn: &RwTxn<'_>,
    fork_hash: &CodebaseForkHash,
    id: &EntityId,
) -> Result<bool> {
    let prefix = hash_index_scan_prefix(fork_hash);
    Ok(FORK_INDEX
        .scan_keys(store, wtxn, &prefix)?
        .into_iter()
        .any(|key| key.id != *id))
}

pub(super) fn delete_exact_index_rows_for_snapshot(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    snapshot: &CodebaseSnapshot,
) -> Result<()> {
    REPO_INDEX.delete(
        store,
        wtxn,
        &TextIndexKey {
            value: snapshot.repo_ref.canonical(),
            id: *id,
        },
    )?;
    PROJECT_INDEX.delete(
        store,
        wtxn,
        &TextIndexKey {
            value: snapshot.project_id.clone(),
            id: *id,
        },
    )?;
    FORK_INDEX.delete(
        store,
        wtxn,
        &HashIndexKey {
            value: snapshot.fork_hash,
            id: *id,
        },
    )?;
    SCOPE_INDEX.delete(
        store,
        wtxn,
        &HashIndexKey {
            value: snapshot.scope_key,
            id: *id,
        },
    )?;
    for entry in &snapshot.files {
        let asset_id = codebase_asset_entity_id(&entry.content_hash)?;
        SCOPE_INDEX.delete(
            store,
            wtxn,
            &HashIndexKey {
                value: snapshot.scope_key,
                id: asset_id,
            },
        )?;
    }
    Ok(())
}

pub(super) fn put_scope_index_rows_for_snapshot(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    code_artifact_id: &EntityId,
    snapshot: &CodebaseSnapshot,
) -> Result<()> {
    SCOPE_INDEX.put(
        store,
        wtxn,
        &HashIndexKey {
            value: snapshot.scope_key,
            id: *code_artifact_id,
        },
        &(),
    )?;
    for entry in &snapshot.files {
        let asset_id = codebase_asset_entity_id(&entry.content_hash)?;
        SCOPE_INDEX.put(
            store,
            wtxn,
            &HashIndexKey {
                value: snapshot.scope_key,
                id: asset_id,
            },
            &(),
        )?;
    }
    Ok(())
}

/// Deletes every row of `table`, across every value it indexes, whose id half matches `id`. Used
/// only when a snapshot row failed to decode, so the values it was indexed under are unknown and
/// the whole table must be swept.
pub(super) fn delete_index_rows_for_id<K: SideKey + IndexRowId>(
    table: SideTable<K, (), Raw>,
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let matches: Vec<K> = table
        .scan_keys(store, wtxn, &[])?
        .into_iter()
        .filter(|key| key.id() == *id)
        .collect();
    for key in &matches {
        table.delete(store, wtxn, key)?;
    }
    Ok(())
}

pub(super) fn codebase_ids_by_index<K: SideKey + IndexRowId>(
    table: SideTable<K, (), Raw>,
    store: &Store,
    rtxn: &RoTxn<'_>,
    key_prefix: &[u8],
) -> Result<Vec<EntityId>> {
    let mut ids = Vec::new();
    for key in table.scan_keys(store, rtxn, key_prefix)? {
        let id = key.id();
        let Some(raw) = store.port_entity_record(rtxn, &id)?.map(|row| row.encode()) else {
            continue;
        };
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type == ENTITY_TYPE_CODE_ARTIFACT {
            ids.push(id);
        }
    }
    Ok(ids)
}
