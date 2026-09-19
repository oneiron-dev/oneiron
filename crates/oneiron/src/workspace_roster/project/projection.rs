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
    let Some(raw) = store.entities.get(txn, id.as_bytes())? else {
        return Err(RecordError::ProjectDependencyPending.into());
    };
    let header = EntityMetadataHeader::parse(&raw)
        .ok_or(Error::CorruptedIndex("project dependency header"))?;
    if header.entity_type != kind {
        return Err(invalid());
    }
    if raw.len() == ENTITY_METADATA_HEADER_LEN {
        return Err(RecordError::ProjectDependencyPending.into());
    }
    rmp_serde::from_slice(&raw[ENTITY_METADATA_HEADER_LEN..])
        .map_err(|_| Error::CorruptedIndex("project dependency body"))
}

pub(crate) fn validate_project_body(id: EntityId, bytes: &[u8]) -> Result<Vec<EntityId>> {
    let body: ProjectRecord = rmp_serde::from_slice(bytes).map_err(|_| invalid())?;
    if body.schema_version != 1
        || body.home_room != home_room_id(id).to_hex()
        || body.roster.is_empty()
    {
        return Err(invalid());
    }
    let mut refs = vec![&body.claims_scope_ref, &body.leader, &body.home_room];
    refs.extend(body.parent.iter());
    refs.extend(body.goal.iter());
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
    Ok(ids)
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
    for id in touched {
        let Some(raw) = store.entities.get(txn, id.as_bytes())? else {
            continue;
        };
        let header = EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("project projection header"))?;
        if header.entity_type != project_kind || raw.len() == ENTITY_METADATA_HEADER_LEN {
            continue;
        }
        let body: ProjectRecord = rmp_serde::from_slice(&raw[ENTITY_METADATA_HEADER_LEN..])
            .map_err(|_| Error::CorruptedIndex("project projection body"))?;
        // Fail closed on cycles, dangling parents, and non-project parents.
        let mut visited = BTreeSet::from([id.to_hex()]);
        let mut parent = body.parent.clone();
        while let Some(next) = parent {
            if !visited.insert(next.clone()) || visited.len() > 256 {
                return Err(invalid());
            }
            let parent_body = dependency(
                store,
                txn,
                EntityId::from_hex(&next).map_err(|_| invalid())?,
                project_kind,
            )?;
            parent = parent_body.parent;
        }
        let room_id = EntityId::from_hex(&body.home_room)?;
        let room = ProjectRoom {
            schema_version: 1,
            kind: "channel".into(),
            project_id: id.to_hex(),
            member_ids: body.roster.clone(),
            claims_scope_ref: body.claims_scope_ref.clone(),
        };
        let previous: Option<ProjectRoom> =
            match record(store, txn, room_id, ENTITY_TYPE_CONVERSATION) {
                Err(Error::InvalidConfig(_)) => return Err(invalid_room()),
                other => other?,
            };
        if previous
            .as_ref()
            .is_some_and(|old| old.project_id != id.to_hex())
        {
            return Err(invalid());
        }
        if previous.as_ref() == Some(&room) {
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
        let Some(raw) = store.entities.get(txn, id.as_bytes())? else {
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
        {
            return Err(invalid_room());
        }
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
