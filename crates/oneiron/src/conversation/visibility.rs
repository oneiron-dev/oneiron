//! The audience predicate shared by all ScopedRead paths.
use super::*;
use crate::conversation_dag::edge_ids;
use crate::limits::MAX_ANCESTOR_DEPTH;
use crate::{
    EdgeKind,
    registry::{
        ENTITY_TYPE_CLAIM, ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_MESSAGE, ENTITY_TYPE_RELATIONSHIP,
        ENTITY_TYPE_TURN,
    },
};
use std::collections::{BTreeMap, BTreeSet};

mod private_sources;
pub(crate) use private_sources::{
    private_threads_readable_raw_in, private_threads_readable_with_read_in,
};

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
    /// Whether `reader`, an unbound agent or the system, reads the revision
    /// `raw` of `id` by its own entry alone, as a person's own read does
    /// (FIX 5861): the row as served and as it stands, and every record its
    /// words came from (a summary's covers, an epoch's sources, a merge
    /// header's, a reaction's record), each occurred inside one of
    /// `reader`'s own windows in every room it sits in where `reader` is on
    /// the roster. No other member's window binds it; a room it is not on,
    /// or whose ledger keeps no window for it, and the room's own record add
    /// nothing. A record whose header, sources or room roster cannot be read
    /// omits this row; one that is gone is the other gates' to refuse. The
    /// records and their ancestry are read through `dbs` as well as base
    /// (FIX 6487): a session's composed view, so a source or ancestor a
    /// stretch staged in its overlay meets the same window, and an overlay
    /// row never stands in for the base one. An epoch's sources resolve so
    /// too (FIX 6548), and a revision whose sources do not resolve there is
    /// one whose sources cannot be read, never its own words.
    pub(crate) fn own_entry_readable_raw(
        &self,
        vault: &Vault,
        dbs: &crate::store::StoreRead<'_>,
        txn: &heed::RoTxn<'_>,
        id: EntityId,
        raw: &[u8],
        reader: EntityId,
    ) -> Result<bool> {
        let mut pending = vec![(id, raw.to_vec())];
        for live in base_and_view_rows_in(vault, dbs, txn, id)? {
            if live.as_slice() != raw {
                pending.push((id, live));
            }
        }
        let mut seen = BTreeSet::from([id]);
        while let Some((id, bytes)) = pending.pop() {
            let Some(h) = EntityMetadataHeader::parse(&bytes) else {
                return Ok(false);
            };
            // The room's own record is the room, not its history.
            for room in rooms_of_revision_in(vault, dbs, txn, id, &bytes)? {
                if room == id {
                    continue;
                }
                match crate::workspace_roster::own_room_windows_in_txn(vault, txn, room, reader) {
                    Ok(None) => {}
                    Ok(Some(windows)) if windows.iter().any(|w| w.contains(h.occurred_start)) => {}
                    Ok(Some(_)) | Err(_) => return Ok(false),
                }
            }
            let mut sources =
                match crate::scope_summary::word_sources_through_in(vault, dbs, txn, &id, &bytes) {
                    Ok(crate::scope_summary::WordSources::From(sources)) => sources,
                    Ok(crate::scope_summary::WordSources::Own) => Vec::new(),
                    Ok(crate::scope_summary::WordSources::Unresolved) | Err(_) => {
                        return Ok(false);
                    }
                };
            if h.entity_type == ENTITY_TYPE_CLAIM
                && let Some(body) = bytes.get(ENTITY_METADATA_HEADER_LEN..)
                && let Ok(claim) = crate::claim::decode_claim_body(body, true)
                && let Ok(Some(covers)) = reaction_covers(&claim)
            {
                sources.extend(covers);
            }
            for source in sources {
                if seen.insert(source) {
                    for bytes in base_and_view_rows_in(vault, dbs, txn, source)? {
                        pending.push((source, bytes));
                    }
                }
            }
        }
        Ok(true)
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
                    // is a private thread's Owner or Admin with no seat here
                    // (FIX 5638): a seated one keeps its window (FIX 6268).
                    let windows = membership::windows_rows(rows, *person)?;
                    let seated = windows.last().is_some_and(|window| window.to.is_none());
                    if !windows.iter().any(|w| w.contains(h.occurred_start))
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
                        && (seated
                            || !privileged_thread_reader_in(vault, txn, room, record, *person)?)
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
/// Every room the revision `raw` of `record` sits in (FIX 5861), up the
/// edges and claim subjects [`room_for_revision_in`] walks: an ancestor that
/// is gone is passed over, never a refusal, and a record that reaches two
/// rooms sits in both. Each ancestor and edge is read on base and through
/// `dbs`, a session's composed view (FIX 6487).
fn rooms_of_revision_in(
    vault: &Vault,
    dbs: &crate::store::StoreRead<'_>,
    txn: &heed::RoTxn<'_>,
    record: EntityId,
    raw: &[u8],
) -> Result<BTreeSet<EntityId>> {
    let union = crate::store::ManifestDbs::is_union(dbs);
    let mut pending = vec![(record, raw.to_vec())];
    let mut seen = BTreeSet::from([record]);
    let mut rooms = BTreeSet::new();
    while let Some((id, bytes)) = pending.pop() {
        let Some(h) = EntityMetadataHeader::parse(&bytes) else {
            continue;
        };
        if h.entity_type == ENTITY_TYPE_CONVERSATION {
            rooms.insert(id);
            continue;
        }
        let mut next = Vec::new();
        for kind in [
            EdgeKind::ChildOf,
            EdgeKind::PartOf,
            EdgeKind::Parent,
            EdgeKind::RepliesTo,
            EdgeKind::SpawnedBy,
            EdgeKind::BelongsTo,
        ] {
            next.extend(edge_ids(
                &vault.store,
                txn,
                &id,
                kind,
                false,
                MAX_ANCESTOR_DEPTH,
            )?);
            if union {
                next.extend(edge_ids(dbs, txn, &id, kind, false, MAX_ANCESTOR_DEPTH)?);
            }
        }
        if h.entity_type == ENTITY_TYPE_CLAIM
            && let Some(body) = bytes.get(ENTITY_METADATA_HEADER_LEN..)
            && let Ok(claim) = crate::claim::decode_claim_body(body, true)
            && let crate::claim::ClaimSubject::Entity(subject) = claim.subject
        {
            next.push(subject);
        }
        for ancestor in next {
            if seen.insert(ancestor) {
                for bytes in base_and_view_rows_in(vault, dbs, txn, ancestor)? {
                    pending.push((ancestor, bytes));
                }
            }
        }
    }
    Ok(rooms)
}
/// The rows `id` holds on base and, when `dbs` composes a session's view
/// over it, in that view, each once (FIX 6487): an overlay row is read
/// beside the base one, never in its place. None for a record neither holds.
fn base_and_view_rows_in(
    vault: &Vault,
    dbs: &crate::store::StoreRead<'_>,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
) -> Result<Vec<Vec<u8>>> {
    let mut rows = Vec::new();
    if let Some(base) = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, &id)? {
        rows.push(base);
    }
    if crate::store::ManifestDbs::is_union(dbs)
        && let Some(view) = crate::ports::EntityStoreRead::port_entity_raw(dbs, txn, &id)?
        && !rows.contains(&view)
    {
        rows.push(view);
    }
    Ok(rows)
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
