//! One coordinated capture of a quiescent canonical window.
//! The entry point is `capture_canonical_window`.
//! `super` owns byte accounting, row readers and deletion-first marking.

use super::*;

/// Captures a quiescent window plus every NOTE document and head receipt in its scope.
/// The caller must stop window writers while taking this off-hot-path snapshot.
pub fn capture_canonical_window(
    vault: &Vault,
    window: &str,
    doc: &LoroDoc,
) -> Result<CanonicalSnapshot> {
    capture_canonical_window_within(vault, window, doc, usize::MAX)
}

/// Publishes into current custody each pad a row holds that custody lacks,
/// and reads it back, before a Layer-1 artifact is captured or a rebuilt
/// window keeps its pad rows, so each names its pad by reference (KS-5, FIX
/// 7313, 7293). A pad custody still does not hold the same keeps its
/// carrier there, warned by count; a fault preparing them is warned and
/// never stops the capture.
pub(crate) fn prepare_artifact_pads(vault: &Vault) {
    match vault.prepare_image_pads() {
        Ok(0) => {}
        Ok(unprepared) => tracing::warn!(
            unprepared,
            "world key pads current custody does not hold the same keep their carriers in this \
             capture"
        ),
        Err(error) => tracing::warn!(
            kind = ?error.kind(),
            "world key pads were not prepared for this capture; any custody lacks keeps its \
             carrier"
        ),
    }
}

/// [`capture_canonical_window`] holding at most `limit` bytes of copies: the
/// window's rows and their keys, documents, receipts and NOTE workflows. A
/// copy that would pass `limit` is refused with
/// [`ArtifactError::OverlayLimit`] before it is made, so the copies of a
/// window far over the limit cost the limit, not the window. One document
/// is read whole before it is counted, as opening it reads it.
pub(crate) fn capture_canonical_window_within(
    vault: &Vault,
    window: &str,
    doc: &LoroDoc,
    limit: usize,
) -> Result<CanonicalSnapshot> {
    let budget = &mut ByteBudget::new(limit);
    // The shallow value names the roots without copying what they hold.
    let LoroValue::Map(containers) = doc.get_value() else {
        return Err(invalid("window root"));
    };
    if containers.keys().any(|name| {
        ![
            "entities",
            "edges",
            "tombstones",
            "retained_claim_worlds",
            "documents",
            "entity_documents",
            "document_heads",
            "head_move_receipts",
            "note_forks",
            "note_proposals",
            "row_births",
            "custody",
            "room_turns",
            "room_facts",
            "document_pins",
            "message_docs",
            "withdrawn_cutoffs",
            "peer_origins",
        ]
        .contains(&name.as_str())
    }) {
        return Err(invalid("unknown Layer-1 window container"));
    }
    let mut snapshot = CanonicalSnapshot {
        window: window.to_owned(),
        entity_blobs: Vec::new(),
        retained_claim_worlds: Vec::new(),
        base_edges: Vec::new(),
        tombstones: Vec::new(),
        doc_snapshots: Vec::new(),
        entity_documents: Vec::new(),
        document_heads: Vec::new(),
        head_move_receipts: Vec::new(),
        note_forks: Vec::new(),
        note_proposals: Vec::new(),
        container_manifests: Vec::new(),
        schema_manifest: CanonicalSchemaManifest {
            oneiron_schema_version: crate::store::STORAGE_ABI_VERSION,
            loro_version: "1.13.9".to_owned(),
            container_schema_version: 1,
            analyzer_manifest_blake3: *blake3::hash(
                vault
                    .analyzer
                    .manifest()
                    .canonical_json()
                    .map_err(|_| invalid("analyzer manifest"))?
                    .as_bytes(),
            )
            .as_bytes(),
        },
        suppressed_tasks: Vec::new(),
        custody_transitions: Vec::new(),
        room_turns: Vec::new(),
        room_facts: Vec::new(),
        document_pins: Vec::new(),
        peer_origins: Vec::new(),
        row_births: Vec::new(),
        withdrawn_cutoffs: Vec::new(),
    };
    for (key, blob) in binary_rows_within(doc, "entities", budget)? {
        // A pad row goes by its bare reference, its pad in current custody
        // (KS-5, FIX 5686 part 2).
        let blob = crate::world_keys::image_pad_projection(&vault.store, &blob).unwrap_or(blob);
        snapshot.entity_blobs.push(CanonicalEntity {
            id: parse_id(&key)?,
            blob,
        });
    }
    for (key, value) in binary_rows_within(doc, "edges", budget)? {
        let parts: Vec<_> = key.split(':').collect();
        if parts.len() != 3 {
            return Err(invalid("edge key"));
        }
        let edge = CanonicalBaseEdge {
            source: parse_id(parts[0])?,
            kind: parts[1].parse().map_err(|_| invalid("edge kind"))?,
            target: parse_id(parts[2])?,
            value,
        };
        if edge.key()? != key {
            return Err(invalid("noncanonical edge key"));
        }
        snapshot.base_edges.push(edge);
    }
    for (key, row) in binary_rows_within(doc, "room_turns", budget)? {
        snapshot.room_turns.push(CanonicalRoomTurn {
            id: parse_id(&key)?,
            row,
        });
    }
    for (key, row) in binary_rows_within(doc, "room_facts", budget)? {
        snapshot.room_facts.push(CanonicalRoomFact { key, row });
    }
    for (key, carrier) in binary_rows_within(doc, "custody", budget)? {
        // A custody change's protected input rides the map as its own
        // `input:` row while its holder has not answered (WILL L04 row 04):
        // relay, never content, so no image keeps it.
        if key.starts_with("input:") {
            continue;
        }
        let (id, piece) = crate::secret_custody::parse_custody_row_key(&key)
            .ok_or_else(|| invalid("noncanonical custody row key"))?;
        snapshot
            .custody_transitions
            .push(CanonicalCustodyTransition {
                id: *id.as_bytes(),
                piece,
                carrier,
            });
    }
    for (key, value) in binary_rows_within(doc, "tombstones", budget)? {
        snapshot.tombstones.push(CanonicalTombstone {
            id: parse_id(&key)?,
            deleted_at: crate::deletion::decode_tombstone_value(&value).deleted_at,
            value,
        });
    }
    mark_deleted_carriers_first(vault, window, &snapshot)?;
    let txn = vault.store.env.read_txn()?;
    // FIX 4227: the room side rows name no one this vault erased.
    #[cfg(feature = "sync")]
    crate::sync::room_facts::erase_carried_actors(vault, &txn, &mut snapshot.room_facts)?;
    // Pending delete intent is Layer 1 even when a crash preceded CRDT publication.
    for row in vault
        .store
        .port_pending_tombstones_in_window(&txn, WindowAddress::new(window))?
    {
        let row = row?;
        let entity = *row.id.as_bytes();
        let value = row.raw;
        if let Some(previous) = snapshot.tombstones.iter_mut().find(|row| row.id == entity) {
            if crate::deletion::decode_tombstone_value(&previous.value).is_hard()
                && !crate::deletion::decode_tombstone_value(&value).is_hard()
            {
                continue;
            }
            previous.deleted_at = crate::deletion::decode_tombstone_value(&value).deleted_at;
            previous.value = value;
        } else {
            budget.take(entity.len() + value.len())?;
            snapshot.tombstones.push(CanonicalTombstone {
                id: entity,
                deleted_at: crate::deletion::decode_tombstone_value(&value).deleted_at,
                value,
            });
        }
    }
    // A global hard marker outranks stale window content and soft tombstones,
    // including ids whose body is no longer present in the window map.
    let candidates: std::collections::BTreeSet<_> = snapshot
        .entity_blobs
        .iter()
        .map(|row| row.id)
        .chain(snapshot.tombstones.iter().map(|row| row.id))
        .collect();
    for entity in candidates {
        if let Some(value) =
            vault
                .store
                .port_deletion_marker(&txn, DeletionMarker::HardDelete, &id(entity)?)?
        {
            if !crate::deletion::decode_tombstone_value(&value).is_hard() {
                return Err(invalid("invalid hard delete marker"));
            }
            snapshot.tombstones.retain(|row| row.id != entity);
            snapshot.tombstones.push(CanonicalTombstone {
                id: entity,
                deleted_at: crate::deletion::decode_tombstone_value(&value).deleted_at,
                value,
            });
        }
    }
    // A row this vault fenced as deleted, whose tombstone the window no longer
    // holds, was a delete a peer withdrew. A soft tombstone cannot be rebuilt
    // faithfully, and exporting the row would make it live wherever the
    // artifact lands, so the snapshot is refused. The stored row decides, as
    // on every read: a delete-protected record stays live under a fence a
    // peer's tombstone planted before it arrived.
    for row in &snapshot.entity_blobs {
        if snapshot
            .tombstones
            .iter()
            .any(|tombstone| tombstone.id == row.id)
        {
            continue;
        }
        let entity = id(row.id)?;
        // Borrowed: only the stored row's header decides, so the body of a
        // projection under repair is never copied to answer it.
        let marked = match vault.store.port_entity_with_raw(&txn, &entity, |stored| {
            crate::deletion::row_deletion_marked(&vault.store, &txn, &entity, Some(stored))
        })? {
            Some(marked) => marked,
            None => crate::deletion::row_deletion_marked(&vault.store, &txn, &entity, None)?,
        };
        if marked {
            return Err(invalid("deleted row without its tombstone"));
        }
    }
    // Audit identity is the validated LOCAL receipt index, not the peer's
    // entity header or tombstone inventory. A rejected type-change (e.g. an
    // ASSET at this ID) must not become a canonical replacement, and removal
    // of the CRDT map key must not hide a committed event from a fresh vault.
    let mut protected_receipts = std::collections::BTreeSet::new();
    let mut restored_receipts = Vec::new();
    let receipts =
        crate::receipt::canonical_records_in_window(&vault.store, &txn, window, |raw| {
            budget.take(16 + raw.len())
        })?;
    for (receipt_id, local_blob) in receipts {
        let bytes = *receipt_id.as_bytes();
        if let Some(candidate) = snapshot.entity_blobs.iter().find(|row| row.id == bytes) {
            if candidate.blob != local_blob {
                return Err(Error::CorruptedIndex(
                    "canonical receipt record carrier diverged",
                ));
            }
        } else {
            restored_receipts.push(CanonicalEntity {
                id: bytes,
                blob: local_blob,
            });
        }
        protected_receipts.insert(bytes);
    }
    // A receipt-shaped CRDT row that never passed local audit admission is
    // not a source of deletion immunity or an exportable receipt. Refuse the
    // snapshot rather than shipping an artifact whose rebuild will discard it.
    for row in &snapshot.entity_blobs {
        if crate::batch::EntityMetadataHeader::parse(&row.blob)
            .is_some_and(|header| header.entity_type == crate::registry::ENTITY_TYPE_RECEIPT_RECORD)
            && !protected_receipts.contains(&row.id)
        {
            return Err(Error::CorruptedIndex(
                "canonical receipt record not materialized",
            ));
        }
    }
    snapshot.entity_blobs.extend(restored_receipts);
    snapshot
        .tombstones
        .retain(|row| !protected_receipts.contains(&row.id));

    // Hard deletion removes the payload and graph. Soft deletion retains only
    // the exact header and surviving Layer-1 edges, never an old body. The live
    // map may have removed that header already, so recover it from the store.
    let hard: std::collections::BTreeSet<_> = snapshot
        .tombstones
        .iter()
        .filter(|row| crate::deletion::decode_tombstone_value(&row.value).is_hard())
        .map(|row| row.id)
        .collect();
    snapshot.entity_blobs.retain(|row| !hard.contains(&row.id));
    snapshot
        .base_edges
        .retain(|row| !hard.contains(&row.source) && !hard.contains(&row.target));
    for tombstone in &snapshot.tombstones {
        if hard.contains(&tombstone.id) {
            continue;
        }
        let id = EntityId::from_bytes(tombstone.id)?;
        let shell = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, &txn, &id)?
            .ok_or(invalid("missing retained shell"))?;
        if shell.len() != crate::batch::ENTITY_METADATA_HEADER_LEN {
            return Err(invalid("soft delete not materialized"));
        }
        snapshot.entity_blobs.retain(|row| row.id != tombstone.id);
        snapshot.entity_blobs.push(CanonicalEntity {
            id: tombstone.id,
            blob: shell.to_vec(),
        });
    }
    // Only outgoing BaseEdge rows are source records. Never promote edges_in
    // (a Layer-2 reverse index) to canonical truth when recovering a shell.
    let soft: std::collections::BTreeSet<_> = snapshot
        .tombstones
        .iter()
        .filter(|row| !hard.contains(&row.id))
        .map(|row| row.id)
        .collect();
    if !soft.is_empty() {
        snapshot
            .base_edges
            .retain(|row| !soft.contains(&row.source) && !soft.contains(&row.target));
        for row in crate::ports::EdgeStoreInventory::port_edge_rows_raw(&vault.store, &txn)? {
            let (key, value) = row?;
            if key.len() != 33 {
                return Err(invalid("retained edge key"));
            }
            let source: [u8; 16] = key[..16]
                .try_into()
                .map_err(|_| invalid("retained edge source"))?;
            let target: [u8; 16] = key[17..]
                .try_into()
                .map_err(|_| invalid("retained edge target"))?;
            if (soft.contains(&source) || soft.contains(&target))
                && !hard.contains(&source)
                && !hard.contains(&target)
            {
                budget.take(key.len() + value.len())?;
                snapshot.base_edges.push(CanonicalBaseEdge {
                    source,
                    kind: key[16],
                    target,
                    value: value.to_vec(),
                });
            }
        }
    }
    document::capture(vault, &txn, &mut snapshot, budget)?;
    for entity in &snapshot.entity_blobs {
        if crate::batch::EntityMetadataHeader::parse(&entity.blob)
            .is_some_and(|h| h.entity_type != crate::registry::ENTITY_TYPE_NOTE)
            && let Some(row) = crate::entity_doc::capture_canonical(vault, &txn, entity.id)?
        {
            budget.take(row.held())?;
            snapshot.entity_documents.push(row);
        }
    }
    snapshot.entity_documents.sort_by_key(|row| row.entity_id);
    // FIX 853: the pins the window carries on documents not captured above.
    #[cfg(feature = "sync")]
    {
        let documents = snapshot
            .entity_documents
            .iter()
            .map(|row| id(row.entity_id))
            .collect::<Result<std::collections::BTreeSet<_>>>()?;
        let rows = binary_rows_within(doc, "document_pins", budget)?;
        for (key, row) in
            crate::sync::document_pins::canonical_pin_rows(vault, &txn, rows, &documents)?
        {
            snapshot
                .document_pins
                .push(CanonicalPinCarrier { key, row });
        }
    }
    snapshot.entity_blobs.sort_by_key(|row| row.id);
    // FIX 5023: a copied origin claim names no actor this vault erased, in
    // the form every export carries, before the peer digests read its bytes.
    // It replaces a copy already counted, and never refuses on its size.
    #[cfg(feature = "sync")]
    for entity in &mut snapshot.entity_blobs {
        if let Some(blob) = crate::origin::actor_erase::canonical_origin_claim_in_txn(
            vault,
            &txn,
            &id(entity.id)?,
            &entity.blob,
        )? {
            entity.blob = blob;
        }
    }
    // FIX 4550: the peer origins of the final rows, with their final bytes.
    peer_origins::capture(doc, &mut snapshot, budget)?;
    // FIX 3069, 8820: the final rows' births, and the window's cutoffs.
    #[cfg(feature = "sync")]
    {
        row_births::capture(vault, &txn, doc, &mut snapshot, budget)?;
        withdrawn_cutoffs::capture(vault, &txn, doc, &mut snapshot, budget)?;
    }
    // Only a TASK row carries a refusal: a forged fact may name any id as its
    // task, and the artifact's validation refuses a mark on anything else.
    for entity in &snapshot.entity_blobs {
        if crate::batch::EntityMetadataHeader::parse(&entity.blob)
            .is_some_and(|header| header.entity_type == crate::registry::ENTITY_TYPE_TASK)
            && crate::task_authority::fact_suppressed_in(&vault.store, &txn, &id(entity.id)?)?
        {
            snapshot.suppressed_tasks.push(entity.id);
        }
    }
    let carried: std::collections::BTreeMap<_, _> =
        binary_rows_within(doc, "retained_claim_worlds", budget)?
            .into_iter()
            .collect();
    if let Some((_, hex)) = window.split_once('@') {
        let world = EntityId::from_hex(hex).map_err(|_| invalid("window world"))?;
        for entity in &snapshot.entity_blobs {
            let header = crate::batch::EntityMetadataHeader::parse(&entity.blob)
                .ok_or(invalid("entity metadata"))?;
            if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM
                || entity.blob.len() != crate::batch::ENTITY_METADATA_HEADER_LEN
            {
                continue;
            }
            if vault
                .store
                .port_deletion_marker(&txn, DeletionMarker::WindowAddress, &id(entity.id)?)?
                .as_deref()
                != Some(window.as_bytes())
                && carried.get(&id(entity.id)?.to_hex()).map(Vec::as_slice)
                    != Some(world.as_bytes().as_slice())
            {
                return Err(invalid("soft claim world address"));
            }
            snapshot.retained_claim_worlds.push(CanonicalShellWorld {
                id: entity.id,
                world: *world.as_bytes(),
            });
        }
    }
    if carried.keys().any(|id| {
        !snapshot.retained_claim_worlds.iter().any(|row| {
            EntityId::from_bytes(row.id)
                .ok()
                .is_some_and(|entity| entity.to_hex() == *id)
        })
    }) {
        return Err(invalid("orphan retained world witness"));
    }
    snapshot
        .base_edges
        .sort_by_key(|row| (row.source, row.kind, row.target));
    snapshot.tombstones.sort_by_key(|row| row.id);
    snapshot.refresh_containers();
    snapshot.validate()?;
    for edge in &snapshot.base_edges {
        if edge.kind == crate::EdgeKind::AddressedTo as u8
            && crate::recovery::trusted_soft_addressing_edge(
                &snapshot,
                &id(edge.source)?,
                &id(edge.target)?,
                &edge.value,
            )?
            && !matches!(
                crate::batch::stored_entity_type(&vault.store, &txn, &id(edge.target)?)?,
                Some(crate::registry::ENTITY_TYPE_PERSON | crate::registry::ENTITY_TYPE_AGENT_DEF)
            )
        {
            return Err(invalid(
                "retained addressing recipient missing or not a PERSON or AGENT_DEF",
            ));
        }
    }
    Ok(snapshot)
}
