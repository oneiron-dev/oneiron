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
//! Only trusted slots are treated as verified (P1-1): the evidence slot only
//! with the S1 writers' stamp (a base agent, the Dreamer or the Coach, as a
//! System actor, which no public door can store), the attachment slot by its
//! reserved predicate. Locator bytes anywhere else are caller-supplied: the
//! row stays live, is never linked nor withdrawn, and is counted once under
//! untrusted_writer. A Live source is also re-checked against the locator's
//! stored binding (P1-2): a TURN span is recomputed over the current text,
//! a CLAIM binding against the current body and, on mismatch, the retained
//! revisions, whose value must equal the current one. A citation the source
//! no longer stands behind — a pre-redaction citation foremost — withdraws
//! the row as a removed source does, counted under rewritten_source as well
//! as withdrawn, and is never linked.
//!
//! Marker [`CITED_SOURCE_DEPENDENCY_BACKFILL`]: `()` key, Raw value. In
//! progress the value is tag `1`, the last visited CLAIM id (16 bytes) and
//! the nine counters (each u64 BE); complete it is tag `2` and the nine
//! counters. Counters in order: scanned, linked, withdrawn, undecodable,
//! missing_without_marker, archived, stale_source, untrusted_writer,
//! rewritten_source. A marker value that does not decode restarts the pass;
//! its effects are idempotent.

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

/// The nine counters the marker carries, in stored order.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct BackfillCounts {
    scanned: u64,
    linked: u64,
    withdrawn: u64,
    undecodable: u64,
    missing_without_marker: u64,
    archived: u64,
    stale_source: u64,
    untrusted_writer: u64,
    rewritten_source: u64,
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
            self.untrusted_writer,
            self.rewritten_source,
        ] {
            out.extend_from_slice(&count.to_be_bytes());
        }
    }

    fn decode(raw: &[u8]) -> Option<Self> {
        if raw.len() != 72 {
            return None;
        }
        let mut counts = [0u64; 9];
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
            untrusted_writer,
            rewritten_source,
        ] = counts;
        Some(Self {
            scanned,
            linked,
            withdrawn,
            undecodable,
            missing_without_marker: missing,
            archived,
            stale_source,
            untrusted_writer,
            rewritten_source,
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
        (IN_PROGRESS_TAG, 88) => {
            let after = EntityId::from_bytes(rest[..16].try_into().ok()?).ok()?;
            Some(BackfillState::InProgress {
                after,
                counts: BackfillCounts::decode(&rest[16..])?,
            })
        }
        (COMPLETE_TAG, 72) => Some(BackfillState::Complete {
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

/// Whether `body.evidence` is a write-envelope stamp (it carries the actor
/// key), as every `ClaimCandidate` write is. Unstamped evidence is caller
/// bytes `put_claim` stored verbatim, never an S1 writer's slot.
fn evidence_is_stamped(body: &crate::claim::ClaimBody) -> bool {
    body.evidence.as_ref().is_some_and(|evidence| {
        evidence.as_map().is_some_and(|entries| {
            entries.iter().any(|(key, _)| {
                key.as_str() == Some(crate::write_envelope::WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY)
            })
        })
    })
}

/// Whether `body`'s evidence stamp is an S1 writer's: stamped by a base
/// agent as a System actor. The promotion writers stamp the attempt's
/// authority, the Dreamer or the Coach (`dreamer_actor_for_attempt`). A
/// public door cannot store that combination: both are MACHINE rows the vault
/// seeds at open, naming one without its valid machine signature is refused
/// at the write chokepoint, and any other actor fails the check. Fail-closed
/// on a missing, doubled or malformed stamp field.
fn is_base_agent_stamp(body: &crate::claim::ClaimBody) -> Result<bool> {
    let Some(producer) = crate::claim::session_claim_producer(body) else {
        return Ok(false);
    };
    if !crate::dreamer_runner::authority::is_base_agent_actor(&producer)? {
        return Ok(false);
    }
    let Some(rmpv::Value::Map(entries)) = body.evidence.as_ref() else {
        return Ok(false);
    };
    let mut class = None;
    for (key, value) in entries {
        if key.as_str() != Some(crate::write_envelope::WRITE_ENVELOPE_EVIDENCE_ACTOR_CLASS_KEY) {
            continue;
        }
        if class.is_some() {
            return Ok(false);
        }
        class = value.as_u64();
    }
    Ok(class == Some(crate::edge::EdgeActorClass::System as u64))
}

/// The `body.evidence` locator slot: a stamped body's writer slot
/// (`candidate_evidence`); a stamp without one carries none. Unstamped
/// evidence is caller bytes, never a slot: no S1 writer stores the legacy
/// top-level form, so there is no fallback (P1-1).
fn evidence_slot(body: &crate::claim::ClaimBody) -> Option<&rmpv::Value> {
    use crate::write_envelope::{
        WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY, WRITE_ENVELOPE_EVIDENCE_CANDIDATE_KEY,
    };

    let evidence = body.evidence.as_ref()?;
    let entries = evidence.as_map()?;
    if !entries
        .iter()
        .any(|(key, _)| key.as_str() == Some(WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY))
    {
        return None;
    }
    entries
        .iter()
        .find(|(key, _)| key.as_str() == Some(WRITE_ENVELOPE_EVIDENCE_CANDIDATE_KEY))
        .map(|(_, value)| value)
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

/// One kept cited locator: its source, the binding the verifier computed
/// over the cited bytes, and the TURN byte range when turn-shaped (`None`
/// when claim-shaped).
struct CitedLocator {
    source: EntityId,
    hash: [u8; 32],
    byte_range: Option<(usize, usize)>,
}

/// What one CLAIM body gives the pass: its trusted cited locators, and
/// whether it also carries locator bytes no S1 writer could have put there.
struct CitingRow {
    /// Locator bytes outside the S1 writers' slots or stamps: counted once
    /// under `untrusted_writer`, never decoded, linked nor withdrawn.
    untrusted: bool,
    /// Trusted locators to link or withdraw over; empty means skip.
    locators: Vec<CitedLocator>,
}

/// The kept cited locators of one CLAIM body: S1's empty-MESSAGE-spans and
/// non-self filter over the trusted slots, deduped. A stamped evidence slot
/// is trusted only with the S1 writers' stamp (P1-1); unstamped top-level
/// locators are caller bytes and mark the row untrusted instead. The
/// attachment slot is trusted by its reserved predicate. `Err` when the body,
/// a trusted slot's locators, or a kept locator's shape does not decode; the
/// caller counts it undecodable once.
fn cited_source_ids(raw_body: &[u8], citing: &EntityId) -> Result<CitingRow> {
    let body = crate::claim::decode_claim_body(raw_body, true)?;
    let mut row = CitingRow {
        untrusted: false,
        locators: Vec::new(),
    };
    if evidence_is_stamped(&body) {
        if let Some(slot) = evidence_slot(&body) {
            if has_locators(slot) {
                if is_base_agent_stamp(&body)? {
                    decode_slot_locators(slot, citing, &mut row.locators)?;
                } else {
                    row.untrusted = true;
                }
            }
        }
    } else if let Some(evidence) = body.evidence.as_ref() {
        if has_locators(evidence) {
            row.untrusted = true;
        }
    }
    if let Some(slot) = derived_evidence_slot(&body) {
        if has_locators(slot) {
            decode_slot_locators(slot, citing, &mut row.locators)?;
        }
    }
    row.locators
        .sort_by(|a, b| (a.source, a.hash, a.byte_range).cmp(&(b.source, b.hash, b.byte_range)));
    row.locators
        .dedup_by(|a, b| a.source == b.source && a.hash == b.hash && a.byte_range == b.byte_range);
    Ok(row)
}

/// Decodes one trusted slot's verified citations into `out`: S1's
/// empty-MESSAGE-spans and non-self filter, then the production shape check.
/// `Err` when the slot's locators or a kept locator's shape does not decode.
fn decode_slot_locators(
    slot: &rmpv::Value,
    citing: &EntityId,
    out: &mut Vec<CitedLocator>,
) -> Result<()> {
    for (locator, hash, messages) in crate::dreamer_consolidation::decode_verified_citations(slot)?
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
        out.push(CitedLocator {
            source: locator.source_id,
            hash,
            byte_range: locator.byte_range,
        });
    }
    Ok(())
}

/// Recomputes one trusted locator's binding over `source_body` (a current or
/// retained source row body) with the verifier's own functions, exactly as
/// `verify_swarm_evidence_bytes` does: the cited bytes, hashed. Claim-shaped
/// binds the whole body; turn-shaped binds the cited span of `turn_text`.
fn recomputed_binding(
    locator: &CitedLocator,
    source_body: &[u8],
    turn_text: Option<&str>,
) -> Result<[u8; 32]> {
    let reference = crate::dreamer_consolidation::SwarmEvidenceRef {
        source_id: locator.source,
        claim_id: match locator.byte_range {
            None => Some(locator.source),
            Some(_) => None,
        },
        byte_range: locator.byte_range,
    };
    let bytes =
        crate::dreamer_consolidation::cited_evidence_bytes(reference, source_body, turn_text)?;
    Ok(crate::dreamer_consolidation::swarm_evidence_content_hash(
        &bytes,
    ))
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
                    self.backfill_one_cited_claim_in_txn(wtxn, id, &mut counts)?;
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
                    untrusted_writer = counts.untrusted_writer,
                    rewritten_source = counts.rewritten_source,
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
    fn backfill_one_cited_claim_in_txn(
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
        let row = match cited_source_ids(&raw[ENTITY_METADATA_HEADER_LEN..], citing) {
            Ok(row) => row,
            Err(_) => {
                counts.undecodable += 1;
                return Ok(());
            }
        };
        if row.untrusted {
            counts.untrusted_writer += 1;
        }
        if row.locators.is_empty() {
            return Ok(());
        }
        // Grouped by source (locators arrive sorted by source first): one
        // classification per source, one binding check per locator. Withdraw
        // wins over live, as before; a rewritten source withdraws the row as
        // a removed one does, counted under `rewritten_source` as well.
        let mut withdraw = false;
        let mut rewritten = false;
        let mut live = Vec::new();
        let mut position = 0;
        while position < row.locators.len() {
            let source = row.locators[position].source;
            let mut next = position + 1;
            while next < row.locators.len() && row.locators[next].source == source {
                next += 1;
            }
            let group = &row.locators[position..next];
            position = next;
            match self.classify_source_in_txn(wtxn, &source, counts)? {
                CitedSource::Live => {
                    if self.locators_name_current_source_in_txn(wtxn, &source, group)? {
                        live.push(source);
                    } else {
                        rewritten = true;
                    }
                }
                CitedSource::Removed => withdraw = true,
                CitedSource::Other => {}
            }
        }
        if withdraw || rewritten {
            // Through the dependent walk: a CLAIM this pass linked to `citing`
            // earlier (its id sorts first) is withdrawn with it.
            super::integrity::mark_one_stale_in_txn(
                &crate::secret_custody::CustodyWrite::of(self),
                wtxn,
                citing,
            )?;
            counts.withdrawn += 1;
            if rewritten {
                counts.rewritten_source += 1;
            }
            return Ok(());
        }
        for source in &live {
            crate::ports::record_derived_edge_in_txn(&self.store, wtxn, citing, source)?;
            counts.linked += 1;
        }
        Ok(())
    }

    /// Whether every locator in `group` (one Live source's trusted locators)
    /// still names the source as stored now (P1-2). Turn-shaped binds only
    /// the cited words, so a recompute over the current TURN text decides. A
    /// claim-shaped binding covers the whole stored body, so a mismatch
    /// falls through to the retained revisions (see
    /// [`Self::cited_version_retained_in_txn`]). Anything this check cannot
    /// judge — a kind the locator's shape never names, an unreadable row, a
    /// row no redaction door rewrites — reads as current, as S1 links what
    /// it never checked.
    fn locators_name_current_source_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        source: &EntityId,
        group: &[CitedLocator],
    ) -> Result<bool> {
        let Some(raw) = self
            .store
            .port_entity_with_raw(txn, source, |raw| Ok(raw.to_vec()))?
        else {
            // Classified Live above, in this same transaction: cannot vanish.
            // Defer to the link's own existence check below.
            return Ok(true);
        };
        let Some(header) = crate::batch::EntityMetadataHeader::parse(&raw) else {
            // Likewise: the link below refuses a headerless row, loudly.
            return Ok(true);
        };
        let body = raw.get(ENTITY_METADATA_HEADER_LEN..).unwrap_or(&[]);
        for locator in group {
            match locator.byte_range {
                Some(_) => {
                    if header.entity_type != crate::registry::ENTITY_TYPE_TURN {
                        continue;
                    }
                    let text = crate::dreamer_consolidation::decode_turn_body(body).text;
                    let Some(text) = text.as_deref() else {
                        continue;
                    };
                    match recomputed_binding(locator, body, Some(text)) {
                        Ok(current) if current == locator.hash => {}
                        _ => return Ok(false),
                    }
                }
                None => {
                    if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM {
                        continue;
                    }
                    if recomputed_binding(locator, body, None)? == locator.hash {
                        continue;
                    }
                    if crate::entity_doc::has_record_head(&self.store, txn, source)? {
                        continue;
                    }
                    if !self.cited_version_retained_in_txn(txn, source, locator, body)? {
                        return Ok(false);
                    }
                }
            }
        }
        Ok(true)
    }

    /// Whether `locator`'s stored binding matches some retained revision of
    /// `source` whose value equals the current one: a benign (metadata-only)
    /// change since the citation, not a redaction. A value-field redaction
    /// scrubs every retained revision, so a pre-redaction binding matches
    /// none. No history beyond the row itself, and a history read failure,
    /// read as retained (live), as S1 links what it cannot judge. A retained
    /// history that names no cited revision withdraws, whatever removed it
    /// (a redaction; also a history purge or a shallow sync document that
    /// dropped the cited revision: the privacy-safe direction), as does one
    /// whose cited value no longer stands.
    fn cited_version_retained_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        source: &EntityId,
        locator: &CitedLocator,
        current_body: &[u8],
    ) -> Result<bool> {
        let retained =
            match crate::vault::entity_revision::retained_rows_in_txn(&self.store, txn, source) {
                Ok(retained) => retained,
                Err(_) => return Ok(true),
            };
        if retained.len() <= 1 {
            return Ok(true);
        }
        for raw in &retained {
            let Some(body) = raw.get(ENTITY_METADATA_HEADER_LEN..) else {
                continue;
            };
            if recomputed_binding(locator, body, None)? != locator.hash {
                continue;
            }
            let Ok(then) = crate::claim::decode_claim_body(body, true) else {
                return Ok(false);
            };
            let Ok(now) = crate::claim::decode_claim_body(current_body, true) else {
                return Ok(false);
            };
            return Ok(then.value == now.value);
        }
        Ok(false)
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
