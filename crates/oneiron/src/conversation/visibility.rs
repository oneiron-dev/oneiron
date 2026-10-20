//! The audience predicate shared by all ScopedRead paths.
use super::*;
use crate::conversation_dag::edge_ids;
use crate::limits::MAX_ANCESTOR_DEPTH;
use crate::{
    EdgeKind,
    registry::{
        ENTITY_TYPE_CLAIM, ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_MESSAGE, ENTITY_TYPE_RELATIONSHIP,
        ENTITY_TYPE_TASK, ENTITY_TYPE_TURN,
    },
};
use std::collections::{BTreeMap, BTreeSet};

/// Immutable ledger snapshots, keyed by the version read in the caller's
/// transaction. Reusing a ScopedRead after a kick cannot reuse stale authority.
#[derive(Default)]
pub(crate) struct AudienceCache {
    rows: BTreeMap<(EntityId, u64), Vec<MembershipRow>>,
    ledger_reads: usize,
}
impl AudienceCache {
    pub(crate) fn ledger_reads(&self) -> usize {
        self.ledger_reads
    }
}
impl AudienceCache {
    pub(crate) fn readable(
        &mut self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        id: EntityId,
        audience: &[EntityId],
    ) -> Result<bool> {
        self.readable_at_depth(vault, txn, id, audience, None, 0)
    }
    /// [`Self::readable`] over the exact revision being served, which for a
    /// pinned or indexed read may be older than the current row. With
    /// `current`, `audience` stands in each private thread the row sits in
    /// under the CURRENT rule, whether it is in the thread now, rather than
    /// per turn (FIX 5545): a member's own read of a room or thread checks
    /// its other members so ([`private_threads_readable_with_read_in`]).
    /// `personal` is that member: in a room it holds a seat in now, the row
    /// meets its own membership window alone, never another member's, so a
    /// join from now on narrows no one else's own read (FIX 5667).
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn readable_raw(
        &mut self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        id: EntityId,
        raw: &[u8],
        audience: &[EntityId],
        current: bool,
        personal: Option<EntityId>,
    ) -> Result<bool> {
        if !crate::vault::live_entity_row_in_txn(&vault.store, txn, &id)?.is_live()
            || vault.archive_tombstone_in_txn(txn, &id)?.is_some()
        {
            return Ok(false);
        }
        self.readable_raw_at_depth(vault, txn, id, raw, audience, current, personal, 0)
    }
    fn covers_readable(
        &mut self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        covers: Result<Option<Vec<EntityId>>>,
        audience: &[EntityId],
        personal: Option<EntityId>,
        depth: usize,
    ) -> Result<bool> {
        let covers = match covers {
            Ok(None) => return Ok(true),
            Ok(Some(covers)) => covers,
            Err(
                Error::EntityNotFound
                | Error::Record(
                    RecordError::InvalidScopeSummary(_) | RecordError::InvalidConversationDag(_),
                ),
            ) => return Ok(false),
            Err(error) => return Err(error),
        };
        if covers.is_empty() {
            return Ok(false);
        }
        for id in covers {
            if !self.readable_at_depth(vault, txn, id, audience, personal, depth + 1)? {
                return Ok(false);
            }
        }
        Ok(true)
    }
    fn readable_at_depth(
        &mut self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        id: EntityId,
        audience: &[EntityId],
        personal: Option<EntityId>,
        depth: usize,
    ) -> Result<bool> {
        if depth > 64
            || !crate::vault::live_entity_row_in_txn(&vault.store, txn, &id)?.is_live()
            || vault.archive_tombstone_in_txn(txn, &id)?.is_some()
        {
            return Ok(false);
        }
        let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, &id)?
        else {
            return Ok(false);
        };
        // `readable` meets each private thread turn by turn; a cover, at a
        // later depth, walks none. A cover meets its room's windows as the
        // row it covers does.
        self.readable_raw_at_depth(vault, txn, id, &raw, audience, false, personal, depth)
    }
    #[expect(clippy::too_many_arguments)]
    fn readable_raw_at_depth(
        &mut self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        id: EntityId,
        raw: &[u8],
        audience: &[EntityId],
        current: bool,
        personal: Option<EntityId>,
        depth: usize,
    ) -> Result<bool> {
        let h = EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("audience header"))?;
        // The room of the revision served and the room of the current row
        // both bind: an older revision about a private channel stays that
        // channel's, and a later move cannot widen the current read.
        let live = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, &id)?;
        let revisions = if live.as_deref() == Some(raw) {
            vec![None]
        } else {
            vec![Some(raw), None]
        };
        // Each audience member must also stand in each private thread the
        // row sits in (FIX 2951); a summary's or claim's covers are walked
        // there, so it runs once per row.
        if depth == 0 && !private_threads_readable_raw_in(vault, txn, id, raw, audience, current)? {
            return Ok(false);
        }
        // FIX 5638: the row itself, never a cover, may read to an Owner or
        // Admin off the room through its own private thread.
        let record = (depth == 0).then_some((id, raw));
        let mut rooms = BTreeSet::new();
        for revision in revisions {
            match room_for_revision_in(vault, txn, id, revision) {
                Ok(room) => rooms.extend(room),
                // Missing ancestry denies this candidate, not unrelated query hits.
                Err(Error::EntityNotFound) => return Ok(false),
                Err(error) => return Err(error),
            }
        }
        for room in rooms {
            if audience.is_empty() {
                return Ok(false);
            }
            match body::body_in(vault, txn, room) {
                Ok(_) => {}
                Err(
                    Error::EntityNotFound | Error::Record(RecordError::InvalidConversationBody(_)),
                ) => {
                    return Ok(false);
                }
                Err(error) => return Err(error),
            }
            if crate::workspace_roster::project_room_audience_in(vault, txn, room, &[])?.is_some() {
                if !project_audience_readable_in(
                    vault,
                    txn,
                    room,
                    audience,
                    h.occurred_start,
                    record,
                )? {
                    return Ok(false);
                }
            } else {
                let revision = membership::revision_in(&vault.store, txn, room)?;
                if !self.rows.contains_key(&(room, revision)) {
                    if self.rows.len() >= 1024 {
                        self.rows.clear();
                    }
                    self.rows.insert(
                        (room, revision),
                        membership::rows_in(&vault.store, txn, room)?,
                    );
                    self.ledger_reads = self.ledger_reads.saturating_add(1);
                }
                let rows = self
                    .rows
                    .get(&(room, revision))
                    .ok_or(Error::CorruptedIndex("audience snapshot"))?;
                // A seat's own read meets its own window alone (FIX 5667):
                // another member's join from now on never narrows it. A
                // reader with no seat here, a host or one on a Ready join,
                // meets every member's, as a held turn does.
                let mut seat = None;
                if let Some(reader) = personal
                    && membership::windows_rows(rows, reader)?
                        .last()
                        .is_some_and(|window| window.to.is_none())
                {
                    seat = Some(reader);
                }
                let checked = if seat.is_some() {
                    seat.as_slice()
                } else {
                    audience
                };
                for person in checked {
                    // An unplaced speaker stays in the audience under the
                    // cut its entry fact froze (ILDF2 P5): never dropped,
                    // never wider than from its entry into this room. A live
                    // Ready receipt for the room is current standing too
                    // (OF-417); it is re-proved here, never cached, and so
                    // is a private thread's Owner or Admin (FIX 5638).
                    if !membership::windows_rows(rows, *person)?
                        .iter()
                        .any(|w| w.contains(h.occurred_start))
                        && !attendee::speaker_entry_covers_in(
                            vault,
                            txn,
                            room,
                            *person,
                            h.occurred_start,
                        )?
                        && !crate::workspace_roster::room_join_audience_in(
                            vault, txn, room, *person,
                        )?
                        && !privileged_thread_reader_in(vault, txn, room, record, *person)?
                    {
                        return Ok(false);
                    }
                }
            }
        }
        let body = raw
            .get(ENTITY_METADATA_HEADER_LEN..)
            .ok_or(Error::CorruptedIndex("audience body"))?;
        let covers = crate::scope_summary::body_covers_in_txn(vault, txn, &id, h.entity_type, body);
        if !self.covers_readable(vault, txn, covers, audience, personal, depth)? {
            return Ok(false);
        }
        if h.entity_type == ENTITY_TYPE_CLAIM {
            let claim = crate::claim::decode_claim_body(body, true)?;
            let covers = crate::scope_summary::merge_word_sources_in_txn(vault, txn, &claim);
            if !self.covers_readable(vault, txn, covers, audience, personal, depth)? {
                return Ok(false);
            }
            let covers = conversation_summary_covers(&claim);
            if !self.covers_readable(vault, txn, covers, audience, personal, depth)? {
                return Ok(false);
            }
            let covers = reaction_covers(&claim);
            if !self.covers_readable(vault, txn, covers, audience, personal, depth)? {
                return Ok(false);
            }
            if let Some(relationship) = claim.rel {
                if audience.is_empty() {
                    return Ok(false);
                }
                let rel = match require_kind(vault, txn, relationship, ENTITY_TYPE_RELATIONSHIP) {
                    Ok(rel) => rel,
                    Err(
                        Error::EntityNotFound
                        | Error::Record(RecordError::InvalidConversationBody(_)),
                    ) => {
                        return Ok(false);
                    }
                    Err(error) => return Err(error),
                };
                let mut participants = edge_ids(
                    &vault.store,
                    txn,
                    &relationship,
                    EdgeKind::ParticipatesIn,
                    true,
                    MAX_ANCESTOR_DEPTH,
                )?;
                // Relationship participant ids are a read-path feed, not a
                // replacement for scope/tier authorization or room windows.
                if let Ok(value) = decode::<serde_json::Value>(&rel[ENTITY_METADATA_HEADER_LEN..])
                    && let Some(ids) = value.get("participant_ids")
                {
                    let body_ids: Vec<EntityId> = serde_json::from_value(ids.clone())
                        .map_err(|_| invalid("relationship participants"))?;
                    participants.extend(body_ids);
                }
                if audience.iter().any(|person| !participants.contains(person)) {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }
}

/// Whether `audience` reads a row of the project room `room` that occurred
/// at `at`. A speaker's entry fact there (FIX 1388/1389) is held to its cut
/// ([`attendee::speaker_entry_covers_in`]), as in an ordinary room: it is no
/// actor, and its entry is never project participation. Every other id
/// stands in the PROJECT roster as an actor, or reads `record`, the row
/// itself, as its private thread's Owner or Admin
/// ([`privileged_thread_reader_in`], FIX 5638).
fn project_audience_readable_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    audience: &[EntityId],
    at: u64,
    record: Option<(EntityId, &[u8])>,
) -> Result<bool> {
    let mut actors = Vec::with_capacity(audience.len());
    for id in audience {
        let fact = crate::task_verb::read_attendee_entry_in(vault, txn, *id)?;
        let entry = fact.is_some_and(|fact| {
            fact.container == room && matches!(fact.attendee, ContainerAttendee::Speaker { .. })
        });
        if !entry {
            actors.push(*id);
        } else if !attendee::speaker_entry_covers_in(vault, txn, room, *id, at)? {
            return Ok(false);
        }
    }
    let readable = crate::workspace_roster::project_room_audience_in(vault, txn, room, &actors)?;
    if readable == Some(true) || record.is_none() {
        return Ok(readable == Some(true));
    }
    for actor in actors {
        if crate::workspace_roster::project_room_audience_in(vault, txn, room, &[actor])?
            != Some(true)
            && !privileged_thread_reader_in(vault, txn, room, record, actor)?
        {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Whether `viewer` reads `record`, a row of `room` and the revision of it
/// served, as the vault's Owner or an Admin in the audience of the private
/// thread it sits in, with no standing in the room (FIX 5638): that
/// revision and the row as it stands are each a TURN of one private thread
/// of `room`, or a MESSAGE part of one, by their own place alone, never a
/// cover's, a quote's or the room's, and the viewer reads that thread
/// ([`crate::workspace_roster::privileged_private_thread_reader_in`]). It
/// stands in for the room's windows alone: the private thread check before
/// them still holds the viewer to the rule its read names. `false` with no
/// `record`.
fn privileged_thread_reader_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    record: Option<(EntityId, &[u8])>,
    viewer: EntityId,
) -> Result<bool> {
    let Some((id, raw)) = record else {
        return Ok(false);
    };
    let Some(live) = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, &id)? else {
        return Ok(false);
    };
    let (Some(root), Some(now)) = (
        thread_placed_in(vault, txn, id, raw)?,
        thread_placed_in(vault, txn, id, &live)?,
    ) else {
        return Ok(false);
    };
    Ok(root == now
        && crate::workspace_roster::privileged_private_thread_reader_in(
            vault, txn, room, root, viewer,
        )?)
}

/// The root of the thread the revision `raw` of `id` is placed in by its
/// own place: a TURN's own binding, or for a MESSAGE, the binding of the
/// one live TURN it is part of. `None` for any other record, a trunk TURN,
/// and a MESSAGE part of no one TURN.
fn thread_placed_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    raw: &[u8],
) -> Result<Option<EntityId>> {
    let h = EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("audience header"))?;
    let root_of = |body: &[u8]| -> Result<Option<EntityId>> {
        Ok(crate::workspace_roster::thread_binding(body)?.map(|binding| binding.root))
    };
    match h.entity_type {
        ENTITY_TYPE_TURN => root_of(raw.get(ENTITY_METADATA_HEADER_LEN..).unwrap_or_default()),
        ENTITY_TYPE_MESSAGE => {
            let turns = edge_ids(
                &vault.store,
                txn,
                &id,
                EdgeKind::PartOf,
                false,
                MAX_ANCESTOR_DEPTH,
            )?;
            let [turn] = turns[..] else {
                return Ok(None);
            };
            match crate::vault::live_entity_row_in_txn(&vault.store, txn, &turn)? {
                crate::vault::LiveEntityRow::Live {
                    entity_type: ENTITY_TYPE_TURN,
                    body,
                } => root_of(body.as_slice()),
                _ => Ok(None),
            }
        }
        _ => Ok(None),
    }
}

/// A reaction (or its echo binding) is readable only together with the record
/// it is about, so it can never broaden that record's audience; `None` for any
/// other claim.
fn reaction_covers(claim: &crate::ClaimBody) -> Result<Option<Vec<EntityId>>> {
    if claim.predicate == crate::reaction::PREDICATE_REACTION_OUTCOME {
        return crate::reaction::outcome_sources(claim).map(Some);
    }
    Ok(
        crate::reaction::is_reaction_claim_predicate(&claim.predicate).then(|| {
            match claim.subject {
                crate::claim::ClaimSubject::Entity(subject) => vec![subject],
                _ => Vec::new(),
            }
        }),
    )
}

/// The records a persisted `conversation.summary` claim covers, or `None` for
/// any other claim. A value that is not a map with a `covers` array of 16-byte
/// ids is malformed, and a malformed summary is denied like any other.
pub(crate) fn conversation_summary_covers(
    claim: &crate::ClaimBody,
) -> Result<Option<Vec<EntityId>>> {
    if claim.predicate != "conversation.summary" {
        return Ok(None);
    }
    let malformed = || Error::Record(RecordError::InvalidScopeSummary("summary coverage"));
    let rmpv::Value::Map(entries) = &claim.value else {
        return Err(malformed());
    };
    let Some((_, rmpv::Value::Array(covers))) =
        entries.iter().find(|(k, _)| k.as_str() == Some("covers"))
    else {
        return Err(malformed());
    };
    covers
        .iter()
        .map(|covered| {
            let rmpv::Value::Binary(raw) = covered else {
                return Err(malformed());
            };
            let bytes: [u8; 16] = raw.as_slice().try_into().map_err(|_| malformed())?;
            EntityId::from_bytes(bytes).map_err(|_| malformed())
        })
        .collect::<Result<Vec<_>>>()
        .map(Some)
}

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
    let mut seen = BTreeMap::from([(id, true)]);
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
        if seen.len() > MAX_ANCESTOR_DEPTH {
            return Err(state("private thread ancestry bound"));
        }
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
                Err(Error::EntityNotFound) => return Ok(false),
                Err(e) => return Err(e),
            };
            for turn in bound {
                if !crate::vault::live_entity_row_in_txn(dbs, txn, &turn)?.is_live() {
                    return Ok(false);
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
            let answered = edge_ids(
                dbs,
                txn,
                &id,
                EdgeKind::RepliesTo,
                false,
                MAX_ANCESTOR_DEPTH,
            )?;
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
            let next = edge_ids(dbs, txn, &id, *kind, false, MAX_ANCESTOR_DEPTH)?;
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
        // A cover that does not resolve names no root here; the audience
        // and room reads that resolve covers deny it themselves.
        for covered in covers.into_iter().flat_map(|covers| covers.ok().flatten()) {
            pending.extend(covered.into_iter().map(|id| (id, None, source)));
        }
    }
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

pub(crate) fn room_for_record_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    record: EntityId,
) -> Result<Option<EntityId>> {
    room_for_revision_in(vault, txn, record, None)
}

/// [`room_for_record_in`] starting from `revision` of `record` when given,
/// so a served older revision is placed by its own subject.
fn room_for_revision_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    record: EntityId,
    revision: Option<&[u8]>,
) -> Result<Option<EntityId>> {
    let mut pending = vec![record];
    let mut seen = BTreeSet::new();
    let mut room = None;
    while let Some(id) = pending.pop() {
        if !seen.insert(id) {
            continue;
        }
        if seen.len() > MAX_ANCESTOR_DEPTH {
            return Err(state("room ancestor depth bound"));
        }
        let raw = match revision.filter(|_| id == record) {
            Some(raw) => raw.to_vec(),
            None => crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, &id)?
                .ok_or(Error::EntityNotFound)?,
        };
        let h = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("room ancestor"))?;
        if h.entity_type == ENTITY_TYPE_CONVERSATION {
            if room.is_some_and(|r| r != id) {
                return Err(state("ambiguous room"));
            }
            room = Some(id);
            continue;
        }
        for kind in [
            EdgeKind::ChildOf,
            EdgeKind::PartOf,
            EdgeKind::Parent,
            EdgeKind::RepliesTo,
            EdgeKind::SpawnedBy,
            EdgeKind::BelongsTo,
        ] {
            pending.extend(edge_ids(
                &vault.store,
                txn,
                &id,
                kind,
                false,
                MAX_ANCESTOR_DEPTH,
            )?);
        }
        if h.entity_type == ENTITY_TYPE_CLAIM {
            let body = crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
            if let crate::claim::ClaimSubject::Entity(subject) = body.subject {
                pending.push(subject);
            }
        }
    }
    Ok(room)
}
impl Vault {
    /// The room audience is membership, never runtime presence.
    pub fn scoped_read_for_room(
        &self,
        actor: crate::claim::ScopedReadActorKey,
        room: EntityId,
    ) -> Result<crate::claim::ScopedRead<'_>> {
        Ok(self.scoped_read(actor).for_audience(&self.members(room)?))
    }
}
