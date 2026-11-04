//! Writer CLAIM read anchors (FIX 11000), split from the parent, which
//! re-exports the two infallible capture entry points.
use super::*;

/// Writer anchors for one claim (FIX 11000 PARTLY).
///
/// Infallible capture for Vault sites (settle/inbox/craft, landed): full
/// subject-ancestry thread/room walks plus body and prompt-source worlds.
/// Complete unless any walk, scan, decode, or worlds read fails, in which
/// case the single incomplete empty value (never a refusal, never partial).
/// Content-free ids only; no Grant, facets, session room, or mutation.
/// Callsites attach only to an existing read context via `with_anchors`.
pub(crate) fn gate_claim_anchors_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    body: &crate::ClaimBody,
) -> crate::store::GateReadAnchors {
    gate_claim_anchors_inner(&vault.store, Some(vault), txn, id, body, Some(&[]))
        .unwrap_or_else(|_| crate::store::GateReadAnchors::incomplete())
}

/// Writer anchors for one claim (FIX 11000 PARTLY).
///
/// Infallible capture for the Store-only site (claim_write, unlanded):
/// Store walks with Vault bails (TASK/SUMMARY encountered, TURN needing a
/// summary cover, CLAIM naming a merge summary all mean incomplete) plus
/// proven pending-birth prompt sources. `pending_prompt` is `Some` proven
/// (possibly empty) or `None` unknown; `None` captures incomplete. Any
/// ambiguous, cyclic-unprovable, malformed, unknown, unsupported, overflowed,
/// or errored capture stores the single incomplete empty value. Only
/// complete with nonempty worlds is later readable. Never refuses the write.
pub(crate) fn gate_claim_anchors_store_in(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    body: &crate::ClaimBody,
    pending_prompt: Option<&[EntityId]>,
) -> crate::store::GateReadAnchors {
    gate_claim_anchors_inner(store, None, txn, id, body, pending_prompt)
        .unwrap_or_else(|_| crate::store::GateReadAnchors::incomplete())
}

/// Fallible inner for [`gate_claim_anchors_in`] and
/// [`gate_claim_anchors_store_in`]: any `Err` means incomplete (mapped by
/// the caller), never a write refusal. `vault` is `Some` for full walks,
/// `None` for Store-only walks that bail where Vault covers are needed.
fn gate_claim_anchors_inner(
    store: &crate::store::Store,
    vault: Option<&Vault>,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    body: &crate::ClaimBody,
    pending_prompt: Option<&[EntityId]>,
) -> Result<crate::store::GateReadAnchors> {
    use crate::store::{GateReadAnchors, GateThreadAnchor};
    let subjects: Vec<EntityId> = match &body.subject {
        crate::claim::ClaimSubject::Entity(subject) => vec![*subject],
        crate::claim::ClaimSubject::Edge { source, target, .. } => vec![*source, *target],
    };
    let Some(pending) = pending_prompt else {
        return Err(Error::EntityNotFound);
    };
    for subject in &subjects {
        if crate::ports::EntityStoreRead::port_entity_raw(store, txn, subject)?.is_none() {
            return Err(Error::EntityNotFound);
        }
    }
    let (placed, reached) = anchor_thread_walk_in(store, vault, txn, &subjects)?;
    let rooms = anchor_rooms_store_in(store, txn, &subjects)?;
    let mut worlds = BTreeSet::new();
    worlds.insert(body.world.unwrap_or_else(crate::claim::base_world_id));
    for subject in &subjects {
        let carried = crate::settings::carried_worlds_in(store, txn, subject)?;
        if carried.unknown {
            return Err(Error::EntityNotFound);
        }
        worlds.extend(carried.worlds);
    }
    let stored_own =
        crate::provenance::birth::prompted::prompt_sources_in_txn(store, txn, id)?;
    for prompt in &stored_own {
        let carried = crate::settings::carried_worlds_in(store, txn, prompt)?;
        if carried.unknown {
            return Err(Error::EntityNotFound);
        }
        worlds.extend(carried.worlds);
    }
    for prompt in pending {
        let carried = crate::settings::carried_worlds_in(store, txn, prompt)?;
        if carried.unknown {
            return Err(Error::EntityNotFound);
        }
        worlds.extend(carried.worlds);
    }
    if worlds.is_empty() {
        return Err(Error::EntityNotFound);
    }
    let threads: Vec<GateThreadAnchor> = placed
        .into_iter()
        .map(|(root, turn)| GateThreadAnchor { root, turn })
        .collect();
    let reached: Vec<EntityId> = reached.into_iter().collect();
    let rooms: Vec<EntityId> = rooms.into_iter().collect();
    let worlds: Vec<EntityId> = worlds.into_iter().collect();
    Ok(GateReadAnchors::complete(threads, reached, rooms, worlds))
}

/// Thread anchors from `subjects`: placed (root, turn) under CONTENT plus
/// reached roots under CURRENT. One walk per subject (each with its own
/// `PrivateThreadAncestryRecords` scan), unioned. Place-vs-source, edge
/// sets, and pure word/merge/reaction checks mirror
/// `private_sources::thread_walk_seen_in`; Vault branches run only when
/// `vault` is `Some`, otherwise they bail to `Err` (incomplete). Cover
/// failures are strict here (incomplete) where the readability walk omits
/// them, since anchors must never under-capture. Missing rows skip; an
/// ancestry cycle is `Err`, never a complete capture. Corrupt headers,
/// malformed covers, and scan failures are `Err`.
fn anchor_thread_walk_in(
    store: &crate::store::Store,
    vault: Option<&Vault>,
    txn: &heed::RoTxn<'_>,
    subjects: &[EntityId],
) -> Result<(BTreeSet<(EntityId, EntityId)>, BTreeSet<EntityId>)> {
    let mut placed_all = BTreeSet::new();
    let mut reached_all = BTreeSet::new();
    for subject in subjects {
        let (placed, reached) = anchor_thread_walk_one_in(store, vault, txn, *subject)?;
        placed_all.extend(placed);
        reached_all.extend(reached);
    }
    Ok((placed_all, reached_all))
}

fn anchor_thread_walk_one_in(
    store: &crate::store::Store,
    vault: Option<&Vault>,
    txn: &heed::RoTxn<'_>,
    subject: EntityId,
) -> Result<(BTreeSet<(EntityId, EntityId)>, BTreeSet<EntityId>)> {
    let mut walk = ScanCount::start(
        store,
        txn,
        EngineScan::PrivateThreadAncestryRecords,
        subject.as_bytes(),
    )?;
    enum AnchorVisit {
        Enter(EntityId, Option<Vec<u8>>, bool),
        Leave(EntityId),
    }

    let mut seen: BTreeMap<EntityId, bool> = BTreeMap::new();
    let mut active = BTreeSet::new();
    let mut placed: BTreeSet<(EntityId, EntityId)> = BTreeSet::new();
    let mut reached: BTreeSet<EntityId> = BTreeSet::new();
    let mut pending = vec![AnchorVisit::Enter(subject, None, true)];
    while let Some(visit) = pending.pop() {
        let (id, revision, source) = match visit {
            AnchorVisit::Enter(id, revision, source) => (id, revision, source),
            AnchorVisit::Leave(id) => {
                active.remove(&id);
                continue;
            }
        };
        if active.contains(&id) {
            return Err(Error::EntityNotFound);
        }
        let bytes = match revision {
            Some(bytes) => bytes,
            None if seen.get(&id).is_some_and(|walked| *walked || !source) => continue,
            None => {
                seen.insert(id, source);
                match crate::ports::EntityStoreRead::port_entity_raw(store, txn, &id)? {
                    Some(bytes) => bytes,
                    None => continue,
                }
            }
        };
        let h = EntityMetadataHeader::parse(&bytes)
            .ok_or(Error::CorruptedIndex("thread ancestor header"))?;
        if h.entity_type == ENTITY_TYPE_CONVERSATION {
            continue;
        }
        active.insert(id);
        pending.push(AnchorVisit::Leave(id));
        let body = bytes.get(ENTITY_METADATA_HEADER_LEN..).unwrap_or_default();
        if h.entity_type == crate::registry::ENTITY_TYPE_TASK {
            let Some(vault) = vault else {
                return Err(Error::EntityNotFound);
            };
            let bound = match crate::workspace_roster::task_binding_turns_in(vault, txn, id) {
                Ok(turns) => turns,
                Err(_) => return Err(Error::EntityNotFound),
            };
            for turn in bound {
                if !crate::vault::live_entity_row_in_txn(store, txn, &turn)?.is_live() {
                    return Err(Error::EntityNotFound);
                }
                pending.push(AnchorVisit::Enter(turn, None, source));
            }
            let (place, refs) = crate::task_verb::room_thread_context_refs(body);
            pending.extend(place.map(|id| AnchorVisit::Enter(id, None, false)));
            pending.extend(
                refs.into_iter()
                    .map(|id| AnchorVisit::Enter(id, None, source)),
            );
        }
        if h.entity_type == crate::registry::ENTITY_TYPE_SUMMARY && vault.is_none() {
            return Err(Error::EntityNotFound);
        }
        let kinds: &[EdgeKind] = if h.entity_type == ENTITY_TYPE_TURN {
            let binding = crate::workspace_roster::thread_binding(body)?;
            if let Some(binding) = binding {
                if source {
                    placed.insert((binding.root, id));
                } else {
                    reached.insert(binding.root);
                }
            }
            if vault.is_none() && crate::scope_summary::turn_needs_summary_cover(body) {
                return Err(Error::EntityNotFound);
            }
            let answered = counted_edge_ids(store, txn, &id, EdgeKind::RepliesTo, false)?;
            pending.extend(
                answered
                    .into_iter()
                    .map(|id| AnchorVisit::Enter(id, None, false)),
            );
            &[EdgeKind::SpawnedBy]
        } else {
            &[
                EdgeKind::ChildOf,
                EdgeKind::PartOf,
                EdgeKind::Parent,
                EdgeKind::RepliesTo,
                EdgeKind::SpawnedBy,
                EdgeKind::BelongsTo,
            ]
        };
        for kind in kinds {
            let next = counted_edge_ids(store, txn, &id, *kind, false)?;
            pending.extend(
                next.into_iter()
                    .map(|id| AnchorVisit::Enter(id, None, source)),
            );
        }
        if let Some(vault) = vault {
            match crate::scope_summary::body_covers_in_txn(vault, txn, &id, h.entity_type, body) {
                Ok(Some(covers)) => {
                    pending.extend(
                        covers
                            .into_iter()
                            .map(|id| AnchorVisit::Enter(id, None, source)),
                    );
                }
                Ok(None) => {}
                Err(_) => return Err(Error::EntityNotFound),
            }
        }
        if h.entity_type == ENTITY_TYPE_CLAIM {
            let claim = match crate::claim::decode_claim_body(body, true) {
                Ok(claim) => claim,
                // Strict for anchors (incomplete) where the readability walk
                // omits covers: a subject or cover left out would widen.
                Err(_) => return Err(Error::EntityNotFound),
            };
            {
                if let crate::claim::ClaimSubject::Entity(subject) = &claim.subject {
                    pending.push(AnchorVisit::Enter(*subject, None, source));
                }
                match crate::scope_summary::merge_summary_ref(&claim) {
                    Ok(None) => {}
                    Ok(Some(_)) => {
                        let Some(vault) = vault else {
                            return Err(Error::EntityNotFound);
                        };
                        match crate::scope_summary::merge_word_sources_in_txn(vault, txn, &claim) {
                            Ok(Some(covers)) => {
                                pending.extend(
                                    covers
                                        .into_iter()
                                        .map(|id| AnchorVisit::Enter(id, None, source)),
                                );
                            }
                            Ok(None) => {}
                            Err(_) => return Err(Error::EntityNotFound),
                        }
                    }
                    Err(_) => return Err(Error::EntityNotFound),
                }
                match conversation_summary_covers(&claim) {
                    Ok(Some(covers)) => {
                        pending.extend(
                            covers
                                .into_iter()
                                .map(|id| AnchorVisit::Enter(id, None, source)),
                        );
                    }
                    Ok(None) => {}
                    Err(_) => return Err(Error::EntityNotFound),
                }
                match reaction_covers(&claim) {
                    Ok(Some(covers)) => {
                        pending.extend(
                            covers
                                .into_iter()
                                .map(|id| AnchorVisit::Enter(id, None, source)),
                        );
                    }
                    Ok(None) => {}
                    Err(_) => return Err(Error::EntityNotFound),
                }
            }
        }
        if h.entity_type == crate::registry::ENTITY_TYPE_SUMMARY {
            if let Some(vault) = vault {
                match crate::scope_summary::word_sources_in(vault, txn, &id, &bytes) {
                    Ok(crate::scope_summary::WordSources::From(sources)) => {
                        pending.extend(
                            sources
                                .into_iter()
                                .map(|id| AnchorVisit::Enter(id, None, source)),
                        );
                    }
                    Ok(_) => {}
                    Err(_) => return Err(Error::EntityNotFound),
                }
            }
        }
    }
    walk.rows(seen.len());
    walk.defer(store);
    Ok((placed, reached))
}

/// Reached rooms from `subjects` (Store-only): every CONVERSATION reachable
/// via the six ancestry edges plus Entity claim subjects, unioned over
/// subjects, each with its own `RoomAncestryRecords` scan. Rooms are
/// terminals; missing rows skip (as `rooms_of_revision_in` does), while an
/// ancestry cycle, corrupt headers, malformed claim bodies, and scan failures
/// are `Err`.
/// Multiple rooms collect (never an ambiguity refusal); the writer session
/// room is never injected.
fn anchor_rooms_store_in(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    subjects: &[EntityId],
) -> Result<BTreeSet<EntityId>> {
    let mut rooms_all = BTreeSet::new();
    for subject in subjects {
        let mut walk = ScanCount::start(
            store,
            txn,
            EngineScan::RoomAncestryRecords,
            subject.as_bytes(),
        )?;
        enum RoomVisit {
            Enter(EntityId),
            Leave(EntityId),
        }

        let mut seen = BTreeSet::new();
        let mut active = BTreeSet::new();
        let mut pending = vec![RoomVisit::Enter(*subject)];
        let mut rooms = BTreeSet::new();
        while let Some(visit) = pending.pop() {
            let id = match visit {
                RoomVisit::Enter(id) => id,
                RoomVisit::Leave(id) => {
                    active.remove(&id);
                    continue;
                }
            };
            if active.contains(&id) {
                return Err(Error::EntityNotFound);
            }
            if !seen.insert(id) {
                continue;
            }
            let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(store, txn, &id)? else {
                continue;
            };
            let h =
                EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("room ancestor"))?;
            if h.entity_type == ENTITY_TYPE_CONVERSATION {
                rooms.insert(id);
                continue;
            }
            active.insert(id);
            pending.push(RoomVisit::Leave(id));
            for kind in [
                EdgeKind::ChildOf,
                EdgeKind::PartOf,
                EdgeKind::Parent,
                EdgeKind::RepliesTo,
                EdgeKind::SpawnedBy,
                EdgeKind::BelongsTo,
            ] {
                pending.extend(
                    counted_edge_ids(store, txn, &id, kind, false)?
                        .into_iter()
                        .map(RoomVisit::Enter),
                );
            }
            if h.entity_type == ENTITY_TYPE_CLAIM {
                let body =
                    crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
                if let crate::claim::ClaimSubject::Entity(subject) = body.subject {
                    pending.push(RoomVisit::Enter(subject));
                }
            }
        }
        walk.rows(seen.len());
        walk.defer(store);
        rooms_all.extend(rooms);
    }
    Ok(rooms_all)
}
