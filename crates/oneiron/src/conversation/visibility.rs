//! The audience predicate shared by all ScopedRead paths.
use super::*;
use crate::conversation_dag::edge_ids;
use crate::limits::MAX_ANCESTOR_DEPTH;
use crate::{
    EdgeKind,
    registry::{
        ENTITY_TYPE_CLAIM, ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_RELATIONSHIP, ENTITY_TYPE_TASK,
        ENTITY_TYPE_TURN,
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
        self.readable_at_depth(vault, txn, id, audience, 0)
    }
    /// [`Self::readable`] over the exact revision being served, which for a
    /// pinned or indexed read may be older than the current row.
    pub(crate) fn readable_raw(
        &mut self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        id: EntityId,
        raw: &[u8],
        audience: &[EntityId],
    ) -> Result<bool> {
        if !crate::vault::live_entity_row_in_txn(&vault.store, txn, &id)?.is_live()
            || vault.archive_tombstone_in_txn(txn, &id)?.is_some()
        {
            return Ok(false);
        }
        self.readable_raw_at_depth(vault, txn, id, raw, audience, 0)
    }
    fn covers_readable(
        &mut self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        covers: Result<Option<Vec<EntityId>>>,
        audience: &[EntityId],
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
            if !self.readable_at_depth(vault, txn, id, audience, depth + 1)? {
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
        self.readable_raw_at_depth(vault, txn, id, &raw, audience, depth)
    }
    fn readable_raw_at_depth(
        &mut self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        id: EntityId,
        raw: &[u8],
        audience: &[EntityId],
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
        if depth == 0 && !private_threads_readable_raw_in(vault, txn, id, raw, audience)? {
            return Ok(false);
        }
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
            if let Some(readable) =
                crate::workspace_roster::project_room_audience_in(vault, txn, room, audience)?
            {
                if !readable {
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
                for person in audience {
                    // An unplaced speaker stays in the audience under the
                    // cut its entry fact froze (ILDF2 P5): never dropped,
                    // never wider than from its entry into this room. A live
                    // Ready receipt for the room is current standing too
                    // (OF-417); it is re-proved here, never cached.
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
        if !self.covers_readable(vault, txn, covers, audience, depth)? {
            return Ok(false);
        }
        if h.entity_type == ENTITY_TYPE_CLAIM {
            let claim = crate::claim::decode_claim_body(body, true)?;
            let covers = crate::scope_summary::merge_word_sources_in_txn(vault, txn, &claim);
            if !self.covers_readable(vault, txn, covers, audience, depth)? {
                return Ok(false);
            }
            let covers = conversation_summary_covers(&claim);
            if !self.covers_readable(vault, txn, covers, audience, depth)? {
                return Ok(false);
            }
            if !self.covers_readable(vault, txn, reaction_covers(&claim), audience, depth)? {
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
/// up its MESSAGE, reply, quote and spawn edges or a claim's subject names,
/// and those of every record a summary, merge or reaction draws its words
/// from. A TURN's `Parent` stays in its own thread or on the trunk, which
/// names none, so it is not walked. A TASK also reaches the thread turns
/// that bind it and the turns its thread and consult refs name (FIX 3124).
/// A declared root that is gone or does not resolve denies, and with no
/// viewers so does any private thread. No read is exempt: an owner's, a
/// host's and an unbound one meet it too.
pub(crate) fn private_threads_readable_raw_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    raw: &[u8],
    viewers: &[EntityId],
) -> Result<bool> {
    private_threads_readable_with_read_in(vault, &vault.store.read(), txn, id, raw, viewers)
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
) -> Result<bool> {
    let mut pending = vec![(id, Some(raw.to_vec()))];
    if let Some(live) = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, &id)?
        && live.as_slice() != raw
    {
        pending.push((id, Some(live)));
    }
    if crate::store::ManifestDbs::is_union(dbs)
        && let Some(live) = crate::ports::EntityStoreRead::port_entity_raw(dbs, txn, &id)?
        && live.as_slice() != raw
    {
        pending.push((id, Some(live)));
    }
    let mut seen = BTreeSet::from([id]);
    let mut roots = BTreeSet::new();
    while let Some((id, revision)) = pending.pop() {
        let bytes = match revision {
            Some(bytes) => bytes,
            None if !seen.insert(id) => continue,
            None => match crate::ports::EntityStoreRead::port_entity_raw(dbs, txn, &id)? {
                Some(bytes) => bytes,
                None => continue,
            },
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
                pending.push((turn, None));
            }
            pending.extend(
                crate::task_verb::room_thread_context_refs(body)
                    .into_iter()
                    .map(|id| (id, None)),
            );
        }
        let kinds: &[EdgeKind] = if h.entity_type == ENTITY_TYPE_TURN {
            if let Some(binding) = crate::workspace_roster::thread_binding(body)? {
                roots.insert(binding.root);
            }
            &[EdgeKind::RepliesTo, EdgeKind::SpawnedBy]
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
            pending.extend(next.into_iter().map(|id| (id, None)));
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
                pending.push((*subject, None));
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
            pending.extend(covered.into_iter().map(|id| (id, None)));
        }
    }
    for root in roots {
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
