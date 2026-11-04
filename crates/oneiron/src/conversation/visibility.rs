//! The audience predicate shared by all ScopedRead paths.
use super::*;
use crate::conversation_dag::counted_edge_ids;
use crate::scan_check::{EngineScan, ScanCount};
use crate::{
    EdgeKind,
    registry::{
        ENTITY_TYPE_CLAIM, ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_MESSAGE, ENTITY_TYPE_RELATIONSHIP,
        ENTITY_TYPE_TURN,
    },
};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Mutex;

mod covers;
mod gate_anchors;
mod private_sources;
pub(crate) use gate_anchors::{gate_claim_anchors_in, gate_claim_anchors_store_in};
pub(crate) use private_sources::{
    private_thread_word_turns_in, private_threads_readable_raw_in,
    private_threads_readable_with_read_in,
};

/// Immutable ledger snapshots, keyed by the version read in the caller's
/// transaction. Reusing a ScopedRead after a kick cannot reuse stale authority.
#[derive(Default)]
pub(crate) struct AudienceCache {
    rows: BTreeMap<(EntityId, u64), Vec<MembershipRow>>,
    ledger_reads: usize,
    /// Own-entry windows and answers kept for one committed snapshot
    /// ([`OwnEntryMemo`]).
    own_entry: Mutex<OwnEntryMemo>,
}

/// What [`AudienceCache::own_entry_readable_raw`] keeps for the one
/// committed snapshot `at` names. Both read only that snapshot and the
/// vault's fixed posture, never a clock, so one recall's rows share them.
#[derive(Default)]
struct OwnEntryMemo {
    /// An unbound reader's own windows per `(room, reader)`
    /// ([`crate::workspace_roster::own_room_windows_in_txn`]): every row that
    /// sits in a room shares them, and each still tests its own time.
    windows: HashMap<(EntityId, EntityId), Option<Vec<MembershipWindow>>>,
    /// Whole answers per `(row, reader, BLAKE3 of the revision served)`, over
    /// base rows only: a row judged again by a later stage of one recall.
    answers: HashMap<(EntityId, EntityId, [u8; 32]), bool>,
    /// The store (its environment's address) and snapshot kept, and whether
    /// that snapshot keeps anything.
    at: Option<(usize, usize, bool)>,
}

/// What [`AudienceCache::own_entry_readable_raw`]'s judgement found.
#[derive(Clone, Copy, PartialEq, Eq)]
enum OwnEntry {
    /// Every window and source admits the row.
    Reads,
    /// A window the row sits in does not admit it.
    Denied,
    /// A header, a room door or a source did not read: the row is omitted
    /// as before, and the memo keeps nothing for it.
    Omitted,
}

/// Whether a row that occurred at `at` stands inside one of `windows`: no
/// windows bind it at all (not on the roster, or a derived roster).
fn own_windows_admit(windows: &Option<Vec<MembershipWindow>>, at: u64) -> bool {
    windows
        .as_ref()
        .is_none_or(|windows| windows.iter().any(|w| w.contains(at)))
}

impl AudienceCache {
    pub(crate) fn ledger_reads(&self) -> usize {
        self.ledger_reads
    }

    /// Whether the own-entry memo may be served and kept for `txn`,
    /// emptied when `txn` reads another snapshot. As the policy fold's
    /// per-snapshot cache: a write never keeps any (its staged rows can move
    /// a roster under it, and an aborted write's id is reused), and a
    /// transaction keeps them only when a probe shows it reads the committed
    /// snapshot, which a write transaction (one past it) never does. The
    /// probe runs once per snapshot, on its own thread: a second read
    /// transaction on this one fails while `txn` lives. A poisoned lock
    /// keeps nothing.
    fn own_windows_keep(&self, vault: &Vault, txn: &heed::RoTxn<'_>) -> bool {
        if crate::store::active_write_txn_depth() > 0 {
            return false;
        }
        let Ok(mut own) = self.own_entry.lock() else {
            return false;
        };
        let store = std::ptr::from_ref(&vault.store.env) as usize;
        let id = txn.id();
        if let Some((kept_store, kept, keeps)) = own.at
            && (kept_store, kept) == (store, id)
        {
            return keeps;
        }
        own.windows.clear();
        own.answers.clear();
        let committed = std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    vault
                        .store
                        .env
                        .read_txn()
                        .ok()
                        .map(|committed| committed.id())
                })
                .join()
                .ok()
                .flatten()
        });
        let keeps = committed == Some(id);
        own.at = Some((store, id, keeps));
        keeps
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
        let Some(raw) = Self::live_raw(vault, txn, id)? else {
            return Ok(false);
        };
        // `readable` meets each private thread turn by turn; a cover walks
        // none ([`covers`]).
        self.readable_with_covers(vault, txn, id, &raw, audience, false, None)
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
        self.readable_with_covers(vault, txn, id, raw, audience, current, personal)
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
    /// too (FIX 6548); one whose sources resolve nowhere reads as before.
    pub(crate) fn own_entry_readable_raw(
        &self,
        vault: &Vault,
        dbs: &crate::store::StoreRead<'_>,
        txn: &heed::RoTxn<'_>,
        id: EntityId,
        raw: &[u8],
        reader: EntityId,
    ) -> Result<bool> {
        let keep = self.own_windows_keep(vault, txn);
        // A whole answer is kept over base rows only: a session's composed
        // view moves no snapshot id under its overlay rows.
        let key = (keep && !dbs.is_union()).then(|| (id, reader, *blake3::hash(raw).as_bytes()));
        if let Some(key) = &key
            && let Some(kept) = self
                .own_entry
                .lock()
                .ok()
                .and_then(|own| own.answers.get(key).copied())
        {
            return Ok(kept);
        }
        let judged = self.own_entry_judged(vault, dbs, txn, id, raw, reader, keep)?;
        let answer = judged == OwnEntry::Reads;
        // A row omitted because a header, a door or a source did not read is
        // never kept: only a judgement is (L09 11-04 14:02).
        if let Some(key) = key
            && judged != OwnEntry::Omitted
            && let Ok(mut own) = self.own_entry.lock()
        {
            own.answers.insert(key, answer);
        }
        Ok(answer)
    }

    /// [`Self::own_entry_readable_raw`]'s judgement, room windows kept when
    /// `keep` says the snapshot allows it.
    #[expect(clippy::too_many_arguments)]
    fn own_entry_judged(
        &self,
        vault: &Vault,
        dbs: &crate::store::StoreRead<'_>,
        txn: &heed::RoTxn<'_>,
        id: EntityId,
        raw: &[u8],
        reader: EntityId,
        keep: bool,
    ) -> Result<OwnEntry> {
        let mut pending = vec![(id, raw.to_vec())];
        for live in base_and_view_rows_in(vault, dbs, txn, id)? {
            if live.as_slice() != raw {
                pending.push((id, live));
            }
        }
        let mut seen = BTreeSet::from([id]);
        while let Some((id, bytes)) = pending.pop() {
            let Some(h) = EntityMetadataHeader::parse(&bytes) else {
                return Ok(OwnEntry::Omitted);
            };
            // The room's own record is the room, not its history.
            for room in rooms_of_revision_in(vault, dbs, txn, id, &bytes)? {
                if room == id {
                    continue;
                }
                let kept = keep
                    .then(|| {
                        let own = self.own_entry.lock().ok()?;
                        own.windows
                            .get(&(room, reader))
                            .map(|windows| own_windows_admit(windows, h.occurred_start))
                    })
                    .flatten();
                let admits = match kept {
                    Some(admits) => admits,
                    None => {
                        // A door that errs omits the row, and keeps nothing.
                        let Ok(windows) = crate::workspace_roster::own_room_windows_in_txn(
                            vault, txn, room, reader,
                        ) else {
                            return Ok(OwnEntry::Omitted);
                        };
                        let admits = own_windows_admit(&windows, h.occurred_start);
                        if keep && let Ok(mut own) = self.own_entry.lock() {
                            own.windows.insert((room, reader), windows);
                        }
                        admits
                    }
                };
                if !admits {
                    return Ok(OwnEntry::Denied);
                }
            }
            let mut sources =
                match crate::scope_summary::word_sources_through_in(vault, dbs, txn, &id, &bytes) {
                    Ok(crate::scope_summary::WordSources::From(sources)) => sources,
                    Ok(_) => Vec::new(),
                    Err(_) => return Ok(OwnEntry::Omitted),
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
        Ok(OwnEntry::Reads)
    }
    /// The row's own rules at `depth` under the row asked about, its covers
    /// aside: they are walked on the heap ([`covers`], FIX 9113). A cover
    /// meets its room's windows as the row it covers does.
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
            let turns = counted_edge_ids(&vault.store, txn, &id, EdgeKind::PartOf, false)?;
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
    if claim.predicate == crate::store::reaction_predicate::PREDICATE_REACTION_OUTCOME {
        return crate::reaction::outcome_sources(claim).map(Some);
    }
    Ok(
        crate::claim::reaction_record::is_reaction_claim_predicate(&claim.predicate).then(|| {
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
/// so a served older revision is placed by its own subject. Every ancestor
/// is read, however many (rule 5): past its threshold row the walk asks
/// whether everything is okay, counted on every way out, and a record
/// already seen ends a cycle.
fn room_for_revision_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    record: EntityId,
    revision: Option<&[u8]>,
) -> Result<Option<EntityId>> {
    let mut walk = ScanCount::start(
        &vault.store,
        txn,
        EngineScan::RoomAncestryRecords,
        record.as_bytes(),
    )?;
    let mut seen = BTreeSet::new();
    let room = room_walk_in(vault, txn, record, revision, &mut seen);
    walk.rows(seen.len());
    walk.defer(&vault.store);
    room
}

/// The walk [`room_for_revision_in`] counts, each record it reaches in
/// `seen`.
fn room_walk_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    record: EntityId,
    revision: Option<&[u8]>,
    seen: &mut BTreeSet<EntityId>,
) -> Result<Option<EntityId>> {
    let mut pending = vec![record];
    let mut room = None;
    while let Some(id) = pending.pop() {
        if !seen.insert(id) {
            continue;
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
            pending.extend(counted_edge_ids(&vault.store, txn, &id, kind, false)?);
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
            next.extend(counted_edge_ids(&vault.store, txn, &id, kind, false)?);
            if union {
                next.extend(counted_edge_ids(dbs, txn, &id, kind, false)?);
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
