//! One-time open backfill: NOTE dependencies for pre-N1 NOTE-review CLAIMs.
//!
//! N1 records a dependency CLAIM -> NOTE for every NOTE a NOTE review cites,
//! so deleting the NOTE withdraws the CLAIM through the dependent walk.
//! CLAIMs the review learnt before N1 carry no such edge, so deleting their
//! NOTE leaves them live (Engine ANSWER N1-OLD-CLAIMS = A). This pass runs
//! once at vault open, after the row-deletion-fence backfill whose fences it
//! reads: it pages every CLAIM, records N1's edge for each live NOTE ref,
//! and withdraws the CLAIM when a cited NOTE was removed (Engine ANSWER
//! N1B-DELETED-REF-TYPE = A: a witnessed NOTE plus a removal marker
//! withdraws; a removed ref with no witness stays live and is counted; an
//! archived NOTE is counted, never linked nor withdrawn). A stale NOTE (its
//! own source withdrew it) withdraws the CLAIM too, counted apart, as the
//! walk does for a CLAIM written after N1 (Engine ANSWER
//! STALE-SOURCE-OLD-ROWS = A); the registration refuses a stale source, so
//! linking one would fail the open.
//! A signed CLAIM's birth copy is linked and withdrawn with it.
//!
//! Marker [`NOTE_CLAIM_DEPENDENCY_BACKFILL`]: `()` key, Raw value. In
//! progress the value is tag `1`, the last visited CLAIM id (16 bytes) and
//! the eight counters (each u64 BE); complete it is tag `2` and the eight
//! counters. Counters in order: scanned, linked, withdrawn, undecodable,
//! missing_without_marker, deleted_ref_type_unknown, archived, stale_note.
//! A signed history that does not resolve also counts as undecodable.
//! A marker value that does not decode restarts the pass; its effects are
//! idempotent.

use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::{DeletionMarker, EntityStoreRead, TombstoneStoreRead};
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_NOTE};
use crate::settings::CarriedWorlds;
use crate::side_table::{self, Named, Raw, SideTable};
use crate::store::Store;

/// CLAIM ids one backfill write visits.
const BACKFILL_BATCH: usize = 256;

/// Marker value tag: in progress (cursor + counters follow).
const IN_PROGRESS_TAG: u8 = 1;

/// Marker value tag: complete (counters follow).
const COMPLETE_TAG: u8 = 2;

/// Marker that the one-time NOTE-dependency backfill ran. Key: ().
const NOTE_CLAIM_DEPENDENCY_BACKFILL: SideTable<(), Vec<u8>, Raw> =
    SideTable::new(&side_table::NOTE_CLAIM_DEPENDENCY_BACKFILL);

/// Presence of the NOTE review's row for an id (witness w2), read without
/// decoding the review record this module does not own.
const NOTE_REVIEW_SEEN_PRESENT: SideTable<EntityId, rmpv::Value, Named> =
    SideTable::new(&side_table::DREAMER_NOTE_REVIEW_SEEN);

/// The eight counters the marker carries, in stored order.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct BackfillCounts {
    scanned: u64,
    linked: u64,
    withdrawn: u64,
    undecodable: u64,
    missing_without_marker: u64,
    deleted_ref_type_unknown: u64,
    archived: u64,
    stale_note: u64,
}

impl BackfillCounts {
    fn encode_into(&self, out: &mut Vec<u8>) {
        for count in [
            self.scanned,
            self.linked,
            self.withdrawn,
            self.undecodable,
            self.missing_without_marker,
            self.deleted_ref_type_unknown,
            self.archived,
            self.stale_note,
        ] {
            out.extend_from_slice(&count.to_be_bytes());
        }
    }

    fn decode(raw: &[u8]) -> Option<Self> {
        if raw.len() != 64 {
            return None;
        }
        let mut counts = [0u64; 8];
        for (slot, chunk) in counts.iter_mut().zip(raw.chunks_exact(8)) {
            *slot = u64::from_be_bytes(chunk.try_into().ok()?);
        }
        let [
            scanned,
            linked,
            withdrawn,
            undecodable,
            missing,
            unknown,
            archived,
            stale_note,
        ] = counts;
        Some(Self {
            scanned,
            linked,
            withdrawn,
            undecodable,
            missing_without_marker: missing,
            deleted_ref_type_unknown: unknown,
            archived,
            stale_note,
        })
    }
}

/// The marker's reading.
enum BackfillState {
    /// No marker, or one that does not decode (the pass restarts).
    NotStarted,
    /// Stopped after `after`; resume past it with `counts`.
    InProgress {
        after: EntityId,
        counts: BackfillCounts,
    },
    /// Ran to the end with `counts`.
    Complete { counts: BackfillCounts },
}

fn read_state(store: &Store, txn: &heed::RoTxn<'_>) -> Result<BackfillState> {
    let Some(raw) = NOTE_CLAIM_DEPENDENCY_BACKFILL.get_bytes(store, txn, &())? else {
        return Ok(BackfillState::NotStarted);
    };
    let Some(state) = decode_state(&raw) else {
        tracing::warn!(
            "the NOTE-dependency backfill marker does not decode; the pass restarts from the first CLAIM"
        );
        return Ok(BackfillState::NotStarted);
    };
    Ok(state)
}

fn decode_state(raw: &[u8]) -> Option<BackfillState> {
    let (tag, rest) = raw.split_first()?;
    match (*tag, rest.len()) {
        (IN_PROGRESS_TAG, 80) => {
            let after = EntityId::from_bytes(rest[..16].try_into().ok()?).ok()?;
            Some(BackfillState::InProgress {
                after,
                counts: BackfillCounts::decode(&rest[16..])?,
            })
        }
        (COMPLETE_TAG, 64) => Some(BackfillState::Complete {
            counts: BackfillCounts::decode(rest)?,
        }),
        _ => None,
    }
}

/// What one evidence ref is to this pass.
enum NoteRef {
    /// A stored NOTE, neither removed nor archived: link it.
    LiveNote,
    /// A NOTE that was removed (a stored header or a deletion witness), or a
    /// stored NOTE its own source withdrew (stale).
    RemovedNote,
    /// Anything else: counted by kind where the rule counts it.
    Other,
}

/// The consolidation evidence refs of `body`, or `None` when the CLAIM
/// carries no consolidation evidence at all. A stamped body's writer slot
/// (`candidate_evidence`) is read; a stamp without one carries none, as a
/// body without evidence does. A malformed envelope is the caller's
/// undecodable error.
fn consolidation_refs(body: &crate::claim::ClaimBody) -> Result<Option<Vec<EntityId>>> {
    use crate::write_envelope::{
        WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY, WRITE_ENVELOPE_EVIDENCE_CANDIDATE_KEY,
    };

    let Some(evidence) = body.evidence.as_ref() else {
        return Ok(None);
    };
    let slot = match evidence.as_map() {
        Some(entries)
            if entries
                .iter()
                .any(|(key, _)| key.as_str() == Some(WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY)) =>
        {
            let Some(candidate) = entries
                .iter()
                .find(|(key, _)| key.as_str() == Some(WRITE_ENVELOPE_EVIDENCE_CANDIDATE_KEY))
                .map(|(_, value)| value)
            else {
                return Ok(None);
            };
            candidate
        }
        _ => evidence,
    };
    match crate::dreamer_consolidation::decode_consolidation_evidence(slot) {
        Ok(Some(envelope)) => Ok(Some(envelope.refs)),
        Ok(None) => Ok(None),
        Err(error) => Err(error),
    }
}

impl Vault {
    /// One-time open backfill for N1-OLD-CLAIMS = A: every CLAIM the NOTE
    /// review learnt before N1 gets N1's dependency on each live NOTE it
    /// cites, or is withdrawn when a cited NOTE was removed. Runs after the
    /// row-deletion-fence backfill, whose fences this pass reads; skips an
    /// archived image; a completed vault pays one marker read and no scan.
    pub(crate) fn backfill_note_claim_dependencies_on_open(&self) -> Result<()> {
        let (mut after, mut counts) = {
            let txn = self.store.env.read_txn()?;
            if self.store.archived_in_txn(&txn)? {
                return Ok(());
            }
            match read_state(&self.store, &txn)? {
                BackfillState::Complete { .. } => return Ok(()),
                BackfillState::NotStarted => (None, BackfillCounts::default()),
                BackfillState::InProgress { after, counts } => (Some(after), counts),
            }
        };
        loop {
            let complete = self.with_write_txn_grouped(|wtxn| {
                let ids: Vec<EntityId> = self
                    .store
                    .port_entity_ids_by_type(&*wtxn, ENTITY_TYPE_CLAIM, after)?
                    .take(BACKFILL_BATCH)
                    .collect::<Result<Vec<_>>>()?;
                for id in &ids {
                    counts.scanned += 1;
                    self.backfill_one_claim_in_txn(wtxn, id, &mut counts)?;
                }
                if ids.len() < BACKFILL_BATCH {
                    let mut value = vec![COMPLETE_TAG];
                    counts.encode_into(&mut value);
                    NOTE_CLAIM_DEPENDENCY_BACKFILL.put(&self.store, wtxn, &(), &value)?;
                    Ok(true)
                } else {
                    let Some(last) = ids.last().copied() else {
                        return Err(Error::CorruptedIndex("backfill page"));
                    };
                    after = Some(last);
                    let mut value = vec![IN_PROGRESS_TAG];
                    value.extend_from_slice(last.as_bytes());
                    counts.encode_into(&mut value);
                    NOTE_CLAIM_DEPENDENCY_BACKFILL.put(&self.store, wtxn, &(), &value)?;
                    Ok(false)
                }
            })?;
            if complete {
                tracing::info!(
                    scanned = counts.scanned,
                    linked = counts.linked,
                    withdrawn = counts.withdrawn,
                    undecodable = counts.undecodable,
                    missing_without_marker = counts.missing_without_marker,
                    deleted_ref_type_unknown = counts.deleted_ref_type_unknown,
                    archived = counts.archived,
                    stale_note = counts.stale_note,
                    "the NOTE-dependency backfill ran once over the vault's CLAIMs"
                );
                return Ok(());
            }
        }
    }

    /// The signed birth the trusted pin names for a MACHINE CLAIM, or `None`
    /// for an unsigned CLAIM. A signed history that does not resolve counts as
    /// undecodable and returns `None` rather than failing the open.
    fn signed_birth_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        claim: &EntityId,
        counts: &mut BackfillCounts,
    ) -> Result<Option<EntityId>> {
        if self
            .store
            .vault_meta
            .get(txn, &crate::claim::history_projection::pin_key(*claim))?
            .is_none()
        {
            return Ok(None);
        }
        match crate::claim::history_projection::machine_history_rows(&self.store, txn, *claim)
            .and_then(|rows| rows.birth.event_id())
        {
            Ok(id) => Ok(Some(id)),
            Err(_) => {
                counts.undecodable += 1;
                Ok(None)
            }
        }
    }

    /// Visits one CLAIM: links each live NOTE ref, or withdraws the CLAIM
    /// when any NOTE ref was removed, with the signed birth copy in either case.
    /// A header-only shell, an already-stale CLAIM and a CLAIM with no
    /// consolidation evidence are skipped; a body or envelope that does not
    /// decode is counted undecodable.
    fn backfill_one_claim_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        claim: &EntityId,
        counts: &mut BackfillCounts,
    ) -> Result<()> {
        let Some(raw) = self
            .store
            .port_entity_with_raw(wtxn, claim, |raw| Ok(raw.to_vec()))?
        else {
            return Ok(());
        };
        if raw.len() == ENTITY_METADATA_HEADER_LEN {
            return Ok(());
        }
        if raw.len() < ENTITY_METADATA_HEADER_LEN {
            return Err(Error::CorruptedIndex("backfill CLAIM row"));
        }
        if crate::ports::stale_in_txn(&self.store, wtxn, claim)? {
            return Ok(());
        }
        let body = match crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true) {
            Ok(body) => body,
            Err(_) => {
                counts.undecodable += 1;
                return Ok(());
            }
        };
        let refs = match consolidation_refs(&body) {
            Ok(Some(refs)) => refs,
            Ok(None) => return Ok(()),
            Err(_) => {
                counts.undecodable += 1;
                return Ok(());
            }
        };
        let mut withdraw = false;
        let mut live_notes = Vec::new();
        for id in &refs {
            match self.classify_note_ref_in_txn(wtxn, id, counts)? {
                NoteRef::LiveNote => live_notes.push(*id),
                NoteRef::RemovedNote => withdraw = true,
                NoteRef::Other => {}
            }
        }
        let birth = if withdraw || !live_notes.is_empty() {
            self.signed_birth_in_txn(&*wtxn, claim, counts)?
        } else {
            None
        };
        if withdraw {
            let write = crate::secret_custody::CustodyWrite::of(self);
            crate::ports::withdraw_dependent_for_backfill_in_txn(
                &write,
                wtxn,
                claim,
                &CarriedWorlds::default(),
            )?;
            if let Some(birth) = birth
                && !crate::ports::stale_in_txn(&self.store, wtxn, &birth)?
            {
                crate::ports::withdraw_dependent_for_backfill_in_txn(
                    &write,
                    wtxn,
                    &birth,
                    &CarriedWorlds::default(),
                )?;
            }
            counts.withdrawn += 1;
            return Ok(());
        }
        for note in &live_notes {
            crate::ports::record_derived_edge_in_txn(&self.store, wtxn, claim, note)?;
            if let Some(birth) = birth {
                crate::ports::record_derived_edge_in_txn(&self.store, wtxn, &birth, note)?;
            }
            counts.linked += 1;
        }
        Ok(())
    }

    /// Classifies one evidence ref: a stored NOTE is linked, removed,
    /// archived or stale, read from the one deletion state the dependency
    /// registration judges, so a link is never refused; a row-less ref is
    /// missing without a marker, or removed and judged by its NOTE
    /// witnesses. Anything that is not a NOTE is `Other`.
    fn classify_note_ref_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        counts: &mut BackfillCounts,
    ) -> Result<NoteRef> {
        if let Some(raw) = self
            .store
            .port_entity_with_raw(txn, id, |raw| Ok(raw.to_vec()))?
        {
            let header = EntityMetadataHeader::parse(&raw)
                .ok_or(Error::CorruptedIndex("backfill ref header"))?;
            if header.entity_type != ENTITY_TYPE_NOTE {
                return Ok(NoteRef::Other);
            }
            // `deleted` is an archive or `removed_in_txn`; the archive goes first.
            let state = self.store.port_deletion_state(txn, id)?;
            if state.archived {
                counts.archived += 1;
                return Ok(NoteRef::Other);
            }
            if state.deleted {
                return Ok(NoteRef::RemovedNote);
            }
            if state.stale {
                counts.stale_note += 1;
                return Ok(NoteRef::Other);
            }
            return Ok(NoteRef::LiveNote);
        }
        if !crate::ports::removed_in_txn(&self.store, txn, id)? {
            counts.missing_without_marker += 1;
            return Ok(NoteRef::Other);
        }
        if self.removed_ref_is_note_in_txn(txn, id)? {
            return Ok(NoteRef::RemovedNote);
        }
        counts.deleted_ref_type_unknown += 1;
        Ok(NoteRef::Other)
    }

    /// Whether a removed ref with no stored row was a NOTE: (w1) its captured
    /// deletion scope's entity type, read under the request id its
    /// hard-delete marker's v2 value carries, or (w2) the NOTE review's
    /// stored row for it. A missing capture, a capture that does not decode
    /// or a marker value with no request is no witness, never an error; a
    /// marker alone never says NOTE.
    fn removed_ref_is_note_in_txn(&self, txn: &heed::RoTxn<'_>, id: &EntityId) -> Result<bool> {
        if let Some(marker) =
            self.store
                .port_deletion_marker(txn, DeletionMarker::HardDelete, id)?
        {
            let decoded = crate::deletion::decode_tombstone_value(&marker);
            if let Some(request) = decoded.request_id {
                let witnessed = crate::deletion::tombstone_scope::deleted_record_scope_in(
                    &self.store,
                    txn,
                    id,
                    &request,
                )
                .ok()
                .flatten()
                .and_then(|scope| scope.entity_type)
                    == Some(ENTITY_TYPE_NOTE);
                if witnessed {
                    return Ok(true);
                }
            }
        }
        Ok(NOTE_REVIEW_SEEN_PRESENT.contains(&self.store, txn, id)?)
    }
}
