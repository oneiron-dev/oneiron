//! The private-thread walk every audience read meets (FIX 2951), split
//! from its parent, which re-exports it.
use super::*;
use crate::registry::{ENTITY_TYPE_SUMMARY, ENTITY_TYPE_TASK};

/// Whether every one of `viewers` reads each private thread (FIX 2951) the
/// revision `raw` of `id`, or its current row, sits in: the root each TURN
/// up its MESSAGE and spawn edges or a claim's subject names, and those of
/// every record a summary, merge or reaction draws its words from, each at
/// that TURN under the CONTENT rule, which a viewer added from a later turn
/// on does not meet, the root included (FIX 5545). The turn a TURN answers
/// or quotes (`RepliesTo`) is its place, not a source of its words: that
/// turn and its own ancestry are read under the CURRENT rule, so a reply
/// after a viewer's add reads to it though it answers a turn from before.
/// The quoted words themselves are the target's own read. A TURN's `Parent`
/// stays in its own thread or on the trunk, which names none, so it is not
/// walked. A TASK also reaches the thread turns that bind it and the turns
/// its consult refs name (FIX 3124). The turn its spec's `thread_ref` names
/// is its place, not a source of its words, read under the CURRENT rule
/// (FIX 5872): a TASK pointing at a turn from before a viewer's add still
/// reads to that viewer. A declared root that is gone
/// or does not resolve denies, and with no viewers so does any private
/// thread. No read is exempt: an owner's, a host's and an unbound one meet
/// it too. With `current`, a turn read for its words is checked under the
/// CURRENT rule as well, whether each viewer is in its thread now: how a
/// member's personal read checks the room's other members (FIX 5545).
pub(crate) fn private_threads_readable_raw_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    raw: &[u8],
    viewers: &[EntityId],
    current: bool,
) -> Result<bool> {
    private_threads_readable_with_read_in(
        vault,
        &vault.store.read(),
        txn,
        id,
        raw,
        viewers,
        current,
    )
}

/// [`private_threads_readable_raw_in`] walking the ancestry `dbs` reads: a
/// session's composed view, so a MESSAGE a stretch stages under a private
/// TURN, or a TURN of a thread it opened, meets that thread's audience
/// (FIX 3122). Both the row base holds now and the one the view composes
/// are walked, so an overlay row never stands in for a base restriction.
/// Task bindings, summary covers and the audience itself read base.
pub(crate) fn private_threads_readable_with_read_in(
    vault: &Vault,
    dbs: &crate::store::StoreRead<'_>,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    raw: &[u8],
    viewers: &[EntityId],
    current: bool,
) -> Result<bool> {
    let Some(ThreadWalk { placed, reached }) = thread_walk_in(vault, dbs, txn, id, raw)? else {
        return Ok(false);
    };
    for (root, turn) in placed {
        let readable = if current {
            crate::workspace_roster::thread_root_readable_with_read_in(
                vault, dbs, txn, root, viewers,
            )?
        } else {
            crate::workspace_roster::thread_turn_readable_with_read_in(
                vault, dbs, txn, root, turn, viewers,
            )?
        };
        if !readable {
            return Ok(false);
        }
    }
    for root in reached {
        if !crate::workspace_roster::thread_root_readable_with_read_in(
            vault, dbs, txn, root, viewers,
        )? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// The private thread turns the revision `raw` of `id`, or its current
/// row, draws its words from, as [`private_threads_readable_raw_in`] walks
/// them (FIX 6411): each turn read for its words, with its thread's root,
/// which a viewer reads under the CONTENT rule. `None` where that walk
/// denies every viewer: a TASK binding whose turn is gone, or an epoch
/// summary whose sources do not read. The roots reached as a place alone
/// are not listed; a read meets them under the CURRENT rule, as they stand.
pub(crate) fn private_thread_word_turns_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    raw: &[u8],
) -> Result<Option<BTreeSet<(EntityId, EntityId)>>> {
    Ok(thread_walk_in(vault, &vault.store.read(), txn, id, raw)?.map(|walk| walk.placed))
}

/// What one walk of a record's ancestry found: each private thread turn
/// read for its words, by its root, and each root reached as a place alone.
struct ThreadWalk {
    placed: BTreeSet<(EntityId, EntityId)>,
    reached: BTreeSet<EntityId>,
}

/// The walk [`private_threads_readable_with_read_in`] judges, through
/// `dbs`; `None` where it denies every viewer. Every record it reaches is
/// read, however many (rule 5): past its threshold row the walk asks
/// whether everything is okay, counted on every way out, a deny and an
/// error included. No count denies it.
fn thread_walk_in(
    vault: &Vault,
    dbs: &crate::store::StoreRead<'_>,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    raw: &[u8],
) -> Result<Option<ThreadWalk>> {
    let mut count = ScanCount::start(
        &vault.store,
        txn,
        EngineScan::PrivateThreadAncestryRecords,
        id.as_bytes(),
    )?;
    let mut seen = BTreeMap::from([(id, true)]);
    let walk = thread_walk_seen_in(vault, dbs, txn, id, raw, &mut seen);
    count.rows(seen.len());
    count.defer(&vault.store);
    walk
}

/// The walk [`thread_walk_in`] counts, each record it reaches in `seen`,
/// by whether it was walked as a source of the words read.
fn thread_walk_seen_in(
    vault: &Vault,
    dbs: &crate::store::StoreRead<'_>,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    raw: &[u8],
    seen: &mut BTreeMap<EntityId, bool>,
) -> Result<Option<ThreadWalk>> {
    // Each pending record is walked as a source of the words read (`true`)
    // or as a place alone (`false`).
    let mut pending = vec![(id, Some(raw.to_vec()), true)];
    if let Some(live) = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, &id)?
        && live.as_slice() != raw
    {
        pending.push((id, Some(live), true));
    }
    if crate::store::ManifestDbs::is_union(dbs)
        && let Some(live) = crate::ports::EntityStoreRead::port_entity_raw(dbs, txn, &id)?
        && live.as_slice() != raw
    {
        pending.push((id, Some(live), true));
    }
    // A record walked as a place is walked again once it is reached as a
    // source; one walked as a source is not walked again.
    let mut placed = BTreeSet::new();
    let mut reached = BTreeSet::new();
    while let Some((id, revision, source)) = pending.pop() {
        let bytes = match revision {
            Some(bytes) => bytes,
            None if seen.get(&id).is_some_and(|walked| *walked || !source) => continue,
            None => {
                seen.insert(id, source);
                match crate::ports::EntityStoreRead::port_entity_raw(dbs, txn, &id)? {
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
        let body = bytes.get(ENTITY_METADATA_HEADER_LEN..).unwrap_or_default();
        // FIX 3124: a TASK sits in every thread a room turn binds it into
        // and every thread its own typed refs name. A binding whose turn is
        // gone denies; it never leaves the TASK public.
        if h.entity_type == ENTITY_TYPE_TASK {
            let bound = match crate::workspace_roster::task_binding_turns_in(vault, txn, id) {
                Ok(turns) => turns,
                Err(Error::EntityNotFound) => return Ok(None),
                Err(e) => return Err(e),
            };
            for turn in bound {
                if !crate::vault::live_entity_row_in_txn(dbs, txn, &turn)?.is_live() {
                    return Ok(None);
                }
                pending.push((turn, None, source));
            }
            // FIX 5872: its `thread_ref` is a place.
            let (place, refs) = crate::task_verb::room_thread_context_refs(body);
            pending.extend(place.map(|id| (id, None, false)));
            pending.extend(refs.into_iter().map(|id| (id, None, source)));
        }
        let kinds: &[EdgeKind] = if h.entity_type == ENTITY_TYPE_TURN {
            if let Some(binding) = crate::workspace_roster::thread_binding(body)? {
                if source {
                    placed.insert((binding.root, id));
                } else {
                    reached.insert(binding.root);
                }
            }
            // FIX 5545: the turn answered is a place.
            let answered = counted_edge_ids(dbs, txn, &id, EdgeKind::RepliesTo, false)?;
            pending.extend(answered.into_iter().map(|id| (id, None, false)));
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
            let next = counted_edge_ids(dbs, txn, &id, *kind, false)?;
            pending.extend(next.into_iter().map(|id| (id, None, source)));
        }
        let mut covers = vec![crate::scope_summary::body_covers_in_txn(
            vault,
            txn,
            &id,
            h.entity_type,
            body,
        )];
        if h.entity_type == ENTITY_TYPE_CLAIM
            && let Ok(claim) = crate::claim::decode_claim_body(body, true)
        {
            if let crate::claim::ClaimSubject::Entity(subject) = &claim.subject {
                pending.push((*subject, None, source));
            }
            covers.extend([
                crate::scope_summary::merge_word_sources_in_txn(vault, txn, &claim),
                conversation_summary_covers(&claim),
                reaction_covers(&claim),
            ]);
        }
        // FIX 6409: an epoch summary's words are its `DerivedFrom` sources',
        // each walked as a scope summary's covers are; one whose sources do
        // not resolve names no root here, as a cover does not.
        if h.entity_type == ENTITY_TYPE_SUMMARY {
            match crate::scope_summary::word_sources_in(vault, txn, &id, &bytes) {
                Ok(crate::scope_summary::WordSources::From(sources)) => {
                    pending.extend(sources.into_iter().map(|id| (id, None, source)));
                }
                Ok(_) => {}
                // A walk that cannot read them omits this row alone.
                Err(_) => return Ok(None),
            }
        }
        // A cover that does not resolve names no root here; the audience
        // and room reads that resolve covers deny it themselves.
        for covered in covers.into_iter().flat_map(|covers| covers.ok().flatten()) {
            pending.extend(covered.into_iter().map(|id| (id, None, source)));
        }
    }
    Ok(Some(ThreadWalk { placed, reached }))
}
