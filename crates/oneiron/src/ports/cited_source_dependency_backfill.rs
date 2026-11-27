//! One-time open backfill: cited-source dependencies for pre-S1 CLAIMs.
//!
//! S1 records a dependency citing -> source for every verified source with no
//! MESSAGE span (an inline-text TURN or a cited CLAIM), so deleting the source
//! withdraws the citing row through the dependent walk. A row written before S1
//! by any of the five callers carries no such edge (Engine ANSWER S1-OLD-ROWS
//! = A). This pass runs once at vault open: it pages every CLAIM, records S1's
//! edge for each live cited source, and withdraws the citing row when a cited
//! source was removed (Engine ANSWER S1B rules: a removal marker withdraws; an
//! absent source with no marker stays live and is counted; locators that do
//! not decode stay live and are counted; an archived source is counted, never
//! linked nor withdrawn). A stale source (its own source withdrew it) withdraws
//! its citing row as a removed one does, counted under stale_source (Engine
//! ANSWER STALE-SOURCE-OLD-ROWS = A): the citing row copied the words that
//! withdrawal took, as the walk judges a row written after S1. The pass
//! withdraws through the dependent walk, so a row it linked to a source
//! earlier in the pass follows that source when the pass withdraws it later.
//!
//! Marker [`CITED_SOURCE_DEPENDENCY_BACKFILL`]: `()` key, Raw value. In
//! progress the value is tag `1`, the last visited CLAIM id (16 bytes) and
//! the seven counters (each u64 BE); complete it is tag `2` and the seven
//! counters. Counters in order: scanned, linked, withdrawn, undecodable,
//! missing_without_marker, archived, stale_source. A marker value that does
//! not decode restarts the pass; its effects are idempotent.

use crate::Vault;
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::{EntityStoreRead, TombstoneStoreRead};
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::side_table::{self, Raw, SideTable};
use crate::store::Store;

/// CLAIM ids one backfill write visits.
const BACKFILL_BATCH: usize = 256;

/// Marker value tag: in progress (cursor + counters follow).
const IN_PROGRESS_TAG: u8 = 1;

/// Marker value tag: complete (counters follow).
const COMPLETE_TAG: u8 = 2;

/// Marker that the one-time cited-source backfill ran. Key: ().
const CITED_SOURCE_DEPENDENCY_BACKFILL: SideTable<(), Vec<u8>, Raw> =
    SideTable::new(&side_table::CITED_SOURCE_DEPENDENCY_BACKFILL);

/// The seven counters the marker carries, in stored order.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct BackfillCounts {
    scanned: u64,
    linked: u64,
    withdrawn: u64,
    undecodable: u64,
    missing_without_marker: u64,
    archived: u64,
    stale_source: u64,
}

impl BackfillCounts {
    fn encode_into(&self, out: &mut Vec<u8>) {
        for count in [
            self.scanned,
            self.linked,
            self.withdrawn,
            self.undecodable,
            self.missing_without_marker,
            self.archived,
            self.stale_source,
        ] {
            out.extend_from_slice(&count.to_be_bytes());
        }
    }

    fn decode(raw: &[u8]) -> Option<Self> {
        if raw.len() != 56 {
            return None;
        }
        let mut counts = [0u64; 7];
        for (slot, chunk) in counts.iter_mut().zip(raw.chunks_exact(8)) {
            *slot = u64::from_be_bytes(chunk.try_into().ok()?);
        }
        let [
            scanned,
            linked,
            withdrawn,
            undecodable,
            missing,
            archived,
            stale_source,
        ] = counts;
        Some(Self {
            scanned,
            linked,
            withdrawn,
            undecodable,
            missing_without_marker: missing,
            archived,
            stale_source,
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
    let Some(raw) = CITED_SOURCE_DEPENDENCY_BACKFILL.get_bytes(store, txn, &())? else {
        return Ok(BackfillState::NotStarted);
    };
    let Some(state) = decode_state(&raw) else {
        tracing::warn!(
            "the cited-source backfill marker does not decode; the pass restarts from the first CLAIM"
        );
        return Ok(BackfillState::NotStarted);
    };
    Ok(state)
}

fn decode_state(raw: &[u8]) -> Option<BackfillState> {
    let (tag, rest) = raw.split_first()?;
    match (*tag, rest.len()) {
        (IN_PROGRESS_TAG, 72) => {
            let after = EntityId::from_bytes(rest[..16].try_into().ok()?).ok()?;
            Some(BackfillState::InProgress {
                after,
                counts: BackfillCounts::decode(&rest[16..])?,
            })
        }
        (COMPLETE_TAG, 56) => Some(BackfillState::Complete {
            counts: BackfillCounts::decode(rest)?,
        }),
        _ => None,
    }
}

/// What one cited source id is to this pass.
enum CitedSource {
    /// A stored source, neither removed nor archived nor stale: link it.
    Live,
    /// A source that was removed, by a stored row's deletion state or a
    /// row-less removal marker, or that its own source withdrew (stale).
    Removed,
    /// Anything else: counted by kind where the rule counts it.
    Other,
}

/// Whether `slot` carries locators at all: a map with a `"locators"` key. Any
/// other slot means "no locators", never undecodable.
fn has_locators(slot: &rmpv::Value) -> bool {
    slot.as_map().is_some_and(|entries| {
        entries
            .iter()
            .any(|(key, _)| key.as_str() == Some("locators"))
    })
}

/// The `body.evidence` locator slot: a stamped body's writer slot
/// (`candidate_evidence`); a stamp without one carries none, as a body without
/// evidence does.
fn evidence_slot(body: &crate::claim::ClaimBody) -> Option<&rmpv::Value> {
    use crate::write_envelope::{
        WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY, WRITE_ENVELOPE_EVIDENCE_CANDIDATE_KEY,
    };

    let evidence = body.evidence.as_ref()?;
    match evidence.as_map() {
        Some(entries)
            if entries
                .iter()
                .any(|(key, _)| key.as_str() == Some(WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY)) =>
        {
            entries
                .iter()
                .find(|(key, _)| key.as_str() == Some(WRITE_ENVELOPE_EVIDENCE_CANDIDATE_KEY))
                .map(|(_, value)| value)
        }
        _ => Some(evidence),
    }
}

/// The `scope.derived_evidence` locator slot, only for an edge-provenance
/// CLAIM.
fn derived_evidence_slot(body: &crate::claim::ClaimBody) -> Option<&rmpv::Value> {
    if body.predicate != crate::provenance::PREDICATE_EDGE_PROVENANCE {
        return None;
    }
    body.scope
        .as_ref()?
        .as_map()?
        .iter()
        .find(|(key, _)| key.as_str() == Some("derived_evidence"))
        .map(|(_, value)| value)
}

/// The kept cited sources of one CLAIM body: S1's empty-MESSAGE-spans and
/// non-self filter over every slot with locators, deduped. `None` when neither
/// slot carries locators. `Err` when the body, a slot's locators, or a kept
/// locator's shape does not decode; the caller counts it undecodable once.
fn cited_source_ids(raw_body: &[u8], citing: &EntityId) -> Result<Option<Vec<EntityId>>> {
    let body = crate::claim::decode_claim_body(raw_body, true)?;
    let mut slots = Vec::new();
    if let Some(slot) = evidence_slot(&body) {
        if has_locators(slot) {
            slots.push(slot);
        }
    }
    if let Some(slot) = derived_evidence_slot(&body) {
        if has_locators(slot) {
            slots.push(slot);
        }
    }
    if slots.is_empty() {
        return Ok(None);
    }
    let mut sources = Vec::new();
    for slot in slots {
        for (locator, _, messages) in crate::dreamer_consolidation::decode_verified_citations(slot)?
        {
            if !messages.is_empty() || locator.source_id == *citing {
                continue;
            }
            let claim_shaped =
                locator.claim_id == Some(locator.source_id) && locator.byte_range.is_none();
            let turn_shaped = locator.claim_id.is_none()
                && matches!(locator.byte_range, Some((start, end)) if start < end);
            if !(claim_shaped || turn_shaped) {
                return Err(Error::InvalidClaimBody("cited source shape"));
            }
            sources.push(locator.source_id);
        }
    }
    sources.sort();
    sources.dedup();
    Ok(Some(sources))
}

impl Vault {
    /// One-time open backfill for S1-OLD-ROWS = A: every CLAIM written before
    /// S1 from an inline TURN or a cited CLAIM gets S1's dependency on each
    /// live cited source, or is withdrawn when a cited source was removed.
    /// Runs after the row-deletion-fence backfill, whose fences this pass
    /// reads; skips an archived image; a completed vault pays one marker read
    /// and no scan.
    pub(crate) fn backfill_cited_source_dependencies_on_open(&self) -> Result<()> {
        let (mut after, mut counts) = {
            let txn = self.store.env.read_txn()?;
            if self.store.archived_in_txn(&txn)? {
                return Ok(());
            }
            match read_state(&self.store, &txn)? {
                BackfillState::Complete { counts: _counts } => return Ok(()),
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
                    CITED_SOURCE_DEPENDENCY_BACKFILL.put(&self.store, wtxn, &(), &value)?;
                    Ok(true)
                } else {
                    let Some(last) = ids.last().copied() else {
                        return Err(Error::CorruptedIndex("backfill page"));
                    };
                    after = Some(last);
                    let mut value = vec![IN_PROGRESS_TAG];
                    value.extend_from_slice(last.as_bytes());
                    counts.encode_into(&mut value);
                    CITED_SOURCE_DEPENDENCY_BACKFILL.put(&self.store, wtxn, &(), &value)?;
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
                    archived = counts.archived,
                    stale_source = counts.stale_source,
                    "the cited-source backfill ran once over the vault's CLAIMs"
                );
                return Ok(());
            }
        }
    }

    /// Visits one CLAIM: links each live cited source, or withdraws the CLAIM
    /// when any cited source was removed. A header-only shell, an already-stale
    /// CLAIM and a CLAIM with no locators are skipped; a body, a slot's
    /// locators, or a kept locator's shape that does not decode is counted
    /// undecodable once.
    fn backfill_one_claim_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        citing: &EntityId,
        counts: &mut BackfillCounts,
    ) -> Result<()> {
        let Some(raw) = self
            .store
            .port_entity_with_raw(wtxn, citing, |raw| Ok(raw.to_vec()))?
        else {
            return Ok(());
        };
        if raw.len() == ENTITY_METADATA_HEADER_LEN {
            return Ok(());
        }
        if raw.len() < ENTITY_METADATA_HEADER_LEN {
            return Err(Error::CorruptedIndex("backfill CLAIM row"));
        }
        if crate::ports::stale_in_txn(&self.store, wtxn, citing)? {
            return Ok(());
        }
        let sources = match cited_source_ids(&raw[ENTITY_METADATA_HEADER_LEN..], citing) {
            Ok(Some(sources)) => sources,
            Ok(None) => return Ok(()),
            Err(_) => {
                counts.undecodable += 1;
                return Ok(());
            }
        };
        let mut withdraw = false;
        let mut live = Vec::new();
        for id in &sources {
            match self.classify_source_in_txn(wtxn, id, counts)? {
                CitedSource::Live => live.push(*id),
                CitedSource::Removed => withdraw = true,
                CitedSource::Other => {}
            }
        }
        if withdraw {
            // Through the dependent walk: a CLAIM this pass linked to `citing`
            // earlier (its id sorts first) is withdrawn with it.
            super::integrity::withdraw_dependent_in_txn(
                &crate::secret_custody::CustodyWrite::of(self),
                wtxn,
                citing,
                &crate::settings::CarriedWorlds::default(),
            )?;
            counts.withdrawn += 1;
            return Ok(());
        }
        for source in &live {
            crate::ports::record_derived_edge_in_txn(&self.store, wtxn, citing, source)?;
            counts.linked += 1;
        }
        Ok(())
    }

    /// Classifies one cited source id: a stored source is linked, archived,
    /// or removed (deleted or stale), read from the one deletion state the
    /// dependency registration judges, so a link is never refused; a row-less
    /// id is removed or missing without a marker. The source's type comes from
    /// the citing row's own locator: no witness reads.
    fn classify_source_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        counts: &mut BackfillCounts,
    ) -> Result<CitedSource> {
        if self
            .store
            .port_entity_with_raw(txn, id, |_| Ok(()))?
            .is_some()
        {
            // `deleted` is an archive or `removed_in_txn`; the archive goes first.
            let state = self.store.port_deletion_state(txn, id)?;
            if state.archived {
                counts.archived += 1;
                return Ok(CitedSource::Other);
            }
            if state.deleted {
                return Ok(CitedSource::Removed);
            }
            if state.stale {
                counts.stale_source += 1;
                return Ok(CitedSource::Removed);
            }
            return Ok(CitedSource::Live);
        }
        if crate::ports::removed_in_txn(&self.store, txn, id)? {
            return Ok(CitedSource::Removed);
        }
        counts.missing_without_marker += 1;
        Ok(CitedSource::Other)
    }
}
