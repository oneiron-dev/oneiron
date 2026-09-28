//! The write-time projector shared by local batches and sync materialization.
use super::*;
use crate::batch::{BatchOp, apply_ops};
use crate::error::RecordError;
use crate::store::Store;

fn invalid() -> Error {
    RecordError::InvalidProjectBody("invalid project or ancestry").into()
}
fn invalid_room() -> Error {
    RecordError::InvalidProjectRoomBody("invalid derived home room").into()
}
fn dependency(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    kind: u8,
) -> Result<ProjectRecord> {
    let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(store, txn, &id)? else {
        if store
            .sync_state
            .get(txn, &crate::deletion::local_hard_delete_key(&id))?
            .is_some()
        {
            return Err(invalid());
        }
        return Err(RecordError::ProjectDependencyPending.into());
    };
    let header = EntityMetadataHeader::parse(&raw)
        .ok_or(Error::CorruptedIndex("project dependency header"))?;
    if header.entity_type != kind {
        return Err(invalid());
    }
    if raw.len() == ENTITY_METADATA_HEADER_LEN {
        // A soft-erased parent is terminal, not an out-of-order arrival.
        return Err(invalid());
    }
    rmp_serde::from_slice(&raw[ENTITY_METADATA_HEADER_LEN..])
        .map_err(|_| Error::CorruptedIndex("project dependency body"))
}

pub(crate) fn validate_project_body(id: EntityId, bytes: &[u8]) -> Result<Vec<EntityId>> {
    let body: ProjectRecord = rmp_serde::from_slice(bytes).map_err(|_| invalid())?;
    if body.schema_version != 1
        || usize::from(body.depth) > crate::context_projection::CONTEXT_PROJECTION_MAX_ANCESTORS
        || body.home_room != home_room_id(id).to_hex()
        || body.roster.is_empty()
    {
        return Err(invalid());
    }
    let mut refs = vec![&body.claims_scope_ref, &body.leader, &body.home_room];
    if body.parents.len() > 256
        || body.parents.iter().collect::<BTreeSet<_>>().len() != body.parents.len()
    {
        return Err(invalid());
    }
    refs.extend(&body.parents);
    // A card mint on a message carries only `born_from`. A converted thread
    // also names its origin room, thread and position: all of them or none.
    match (&body.origin_room, &body.origin_thread, body.origin_at) {
        (None, None, None) => {}
        (Some(room), Some(thread), Some(_))
            if body.born_from.is_some() && !body.parents.is_empty() =>
        {
            refs.extend([room, thread]);
        }
        _ => return Err(invalid()),
    }
    refs.extend(body.goal.iter());
    refs.extend(body.born_from.iter());
    refs.extend(body.budget.iter());
    for list in [
        &body.board,
        &body.roster,
        &body.sessions,
        &body.tasks,
        &body.branches,
        &body.skill_forks,
        &body.asks,
    ] {
        if list.len() > 4096 || list.iter().collect::<BTreeSet<_>>().len() != list.len() {
            return Err(invalid());
        }
        refs.extend(list);
    }
    let mut ids = Vec::new();
    for value in refs {
        let id = EntityId::from_hex(value).map_err(|_| invalid())?;
        if id.to_hex() != *value {
            return Err(invalid());
        }
        ids.push(id);
    }
    if !body.roster.contains(&body.leader) {
        return Err(invalid());
    }
    if body.goal_record.as_ref().is_some_and(|goal| {
        goal.project_id != id.to_hex()
            || goal.goal.trim().is_empty()
            || goal.why.trim().is_empty()
            || goal.axes.is_empty()
            || goal.axes.len() > 128
            || goal.axes.iter().any(|axis| axis.trim().is_empty())
            || body.why.as_deref() != Some(goal.why.as_str())
    }) || body.budget_share.as_ref().is_some_and(|budget| {
        budget.project_id != id.to_hex()
            || !body.parents.contains(&budget.parent_id)
            || budget.share_bps > 10_000
    }) {
        return Err(invalid());
    }
    Ok(ids)
}

/// Project membership carries a birth-depth cache, not authority. Replacing
/// members with an older view must not roll back the policy contribution set.
pub(crate) fn normalize_project_body(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    bytes: &[u8],
    posture: crate::HostingPrivacyPosture,
) -> Result<Vec<u8>> {
    validate_project_body(id, bytes)?;
    let mut body: ProjectRecord = rmp_serde::from_slice(bytes).map_err(|_| invalid())?;
    if body.parents.contains(&id.to_hex()) {
        return Err(invalid());
    }
    body.depth = match crate::gate::project_depth::birth_for_project(store, txn, id)? {
        Some((_, birth)) => birth.depth,
        None if crate::gate::project_depth::implicit_birth_applies(store, txn, posture, id)? => {
            crate::gate::project_depth::canonical_birth(id)?.depth
        }
        None => return Err(RecordError::ProjectDependencyPending.into()),
    };
    encode(&body)
}

pub(crate) fn reconcile_project_rooms(
    store: &Store,
    config: &crate::VaultConfig,
    analyzer: &crate::analyzer::MultilingualAnalyzer,
    trusted: bool,
    txn: &mut heed::RwTxn<'_>,
    touched: &BTreeSet<EntityId>,
) -> Result<()> {
    let Some(project_kind) = project_type(store) else {
        return Ok(());
    };
    let mut room_ops = Vec::new();
    let mut origins = Vec::new();
    for id in touched {
        let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(store, txn, id)? else {
            continue;
        };
        let header = EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("project projection header"))?;
        if header.entity_type != project_kind || raw.len() == ENTITY_METADATA_HEADER_LEN {
            continue;
        }
        let body: ProjectRecord = rmp_serde::from_slice(&raw[ENTITY_METADATA_HEADER_LEN..])
            .map_err(|_| Error::CorruptedIndex("project projection body"))?;
        // The card's provenance is a MESSAGE, not just a parseable entity ID.
        // Missing replicated dependencies are retryable by the sync entity pass;
        // a wrong kind or erased source is terminal at every write door.
        if let Some(source) = &body.born_from {
            let source = EntityId::from_hex(source).map_err(|_| invalid())?;
            let Some(message) = store.entities.get(txn, source.as_bytes())? else {
                if store
                    .sync_state
                    .get(txn, &crate::deletion::local_hard_delete_key(&source))?
                    .is_some()
                {
                    return Err(invalid());
                }
                return Err(RecordError::ProjectDependencyPending.into());
            };
            let message_header = EntityMetadataHeader::parse(&message)
                .ok_or(Error::CorruptedIndex("project born-from header"))?;
            if message_header.entity_type != crate::registry::ENTITY_TYPE_MESSAGE
                || message.len() == ENTITY_METADATA_HEADER_LEN
            {
                return Err(invalid());
            }
        }
        // Fail closed on cycles, dangling parents, and non-project parents.
        let mut visited = BTreeSet::from([id.to_hex()]);
        let mut pending = body.parents.clone();
        while let Some(next) = pending.pop() {
            if next == id.to_hex() || visited.len() > 256 {
                return Err(invalid());
            }
            // A shared ancestor in a diamond is not a cycle.
            if !visited.insert(next.clone()) {
                continue;
            }
            let parent_body = dependency(
                store,
                txn,
                EntityId::from_hex(&next).map_err(|_| invalid())?,
                project_kind,
            )?;
            pending.extend(parent_body.parents);
        }
        origins.push((*id, body.clone()));
        // The body is the authority for the project DAG. Materialize its
        // `belongs_to` links in the same batch as the home room, so PPR and
        // graph readers see both parents (or neither on a rejected write).
        let mut existing = std::collections::BTreeMap::new();
        for row in crate::ports::EdgeStoreRead::port_edges(
            store,
            txn,
            id,
            crate::ports::EdgeDirection::Out,
            Some(crate::edge::EdgeKind::BelongsTo),
            None,
        )? {
            let edge = row?;
            // The PROJECT body owns only PROJECT-to-PROJECT parent links.
            // A venture may also belong to an ORG; saving its body must not
            // remove or rewrite that independently owned relationship.
            if is_project_entity(store, txn, edge.target)? {
                existing.insert(edge.target.to_hex(), edge.weight);
            }
        }
        for parent in existing.keys() {
            if !body.parents.contains(parent) {
                room_ops.push(BatchOp::DeleteEdge {
                    src: *id,
                    kind: crate::edge::EdgeKind::BelongsTo,
                    tgt: EntityId::from_hex(parent).map_err(|_| invalid())?,
                });
            }
        }
        for parent in &body.parents {
            if existing.get(parent).copied() != Some(HUB_MEMBERSHIP_WEIGHT) {
                room_ops.push(BatchOp::Edge {
                    src: *id,
                    kind: crate::edge::EdgeKind::BelongsTo,
                    tgt: EntityId::from_hex(parent).map_err(|_| invalid())?,
                    weight: HUB_MEMBERSHIP_WEIGHT,
                    vad: crate::affect::Vad::NEUTRAL,
                });
            }
        }
        let room_id = EntityId::from_hex(&body.home_room)?;
        let room = ProjectRoom {
            schema_version: 1,
            kind: "channel".into(),
            project_id: id.to_hex(),
            member_ids: body.roster.clone(),
            claims_scope_ref: body.claims_scope_ref.clone(),
            origin: body.origin_card(),
        };
        let previous: Option<ProjectRoom> =
            match record(store, txn, room_id, ENTITY_TYPE_CONVERSATION) {
                Err(Error::InvalidConfig(_)) => return Err(invalid_room()),
                other => other?,
            };
        if previous.is_none() && !crate::conversation::fresh_id_in_txn(store, txn, room_id)? {
            return Err(invalid_room());
        }
        if previous
            .as_ref()
            .is_some_and(|old| old.project_id != id.to_hex())
        {
            return Err(invalid());
        }
        if previous.as_ref() == Some(&room) {
            // A batch can submit the exact derived room beside its PROJECT.
            // Even when no room rewrite is needed, its owner marker must land.
            let marker = [ROOM_PROJECT, room_id.as_bytes()].concat();
            if store.vault_meta.get(txn, &marker)?.as_deref() != Some(id.as_bytes()) {
                store.vault_meta.put(txn, &marker, id.as_bytes())?;
            }
            continue;
        }
        let change = ProjectRoomChange {
            project_id: id.to_hex(),
            room_id: room_id.to_hex(),
            previous_members: previous.map_or(vec![], |old| old.member_ids),
            member_ids: room.member_ids.clone(),
            at: header.learned_at,
        };
        let event = EntityId::now();
        store.vault_meta.put(
            txn,
            &[CHANGES, id.as_bytes(), event.as_bytes()].concat(),
            &encode(&change)?,
        )?;
        store.vault_meta.put(
            txn,
            &[ROOM_PROJECT, room_id.as_bytes()].concat(),
            id.as_bytes(),
        )?;
        room_ops.push(BatchOp::Put {
            id: room_id,
            entity_type: ENTITY_TYPE_CONVERSATION,
            occurred: TimeRange {
                start: header.occurred_start,
                end: header.occurred_end,
            },
            learned_at: header.learned_at,
            data: encode(&room)?,
            allow_maintenance: false,
            allow_reserved_predicate: false,
            hub_sync_imported: false,
        });
    }
    if !room_ops.is_empty() {
        // Only Conversation rows recurse. Their reciprocal check below cannot
        // produce another project operation or detach membership from the roster.
        apply_ops(store, config, analyzer, txn, room_ops, trusted, true, true)?;
    }
    // Generic room writes cannot silently widen the derived membership/scope.
    for id in touched {
        let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(store, txn, id)? else {
            continue;
        };
        let header = EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("project projection header"))?;
        if header.entity_type != ENTITY_TYPE_CONVERSATION {
            continue;
        }
        let Ok(room) = decode::<ProjectRoom>(&raw[ENTITY_METADATA_HEADER_LEN..]) else {
            // Non-project conversations keep their own established body shape.
            continue;
        };
        let project_id = EntityId::from_hex(&room.project_id).map_err(|_| invalid_room())?;
        let project = dependency(store, txn, project_id, project_kind)?;
        if room.schema_version != 1
            || room.kind != "channel"
            || project.home_room != id.to_hex()
            || project.roster != room.member_ids
            || project.claims_scope_ref != room.claims_scope_ref
            || project.origin_card() != room.origin
        {
            return Err(invalid_room());
        }
    }
    // Origins are proved against the batch's final state: every derived room
    // above has landed, so a source roster edit in the same batch is seen.
    for (id, body) in &origins {
        origin::validate_binding(store, txn, body)?;
        origin::index_origin(store, txn, *id, body)?;
    }
    Ok(())
}

pub(crate) fn validate_room_body(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    data: &[u8],
) -> Result<()> {
    if store
        .vault_meta
        .get(txn, &[ROOM_PROJECT, id.as_bytes()].concat())?
        .is_some()
    {
        let room: ProjectRoom = rmp_serde::from_slice(data).map_err(|_| invalid_room())?;
        if room.schema_version != 1 || room.kind != "channel" {
            return Err(invalid_room());
        }
    }
    Ok(())
}
