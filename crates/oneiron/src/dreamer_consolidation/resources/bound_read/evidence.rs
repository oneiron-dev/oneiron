//! Bound observation verification through the shared native evidence reader.
//!
//! The bound projection verifies one observation candidate with the same collapse
//! and meet rule native verification uses, over the same snapshot it was rebuilt
//! in. Whole turns and unmasked ranges bind directly to stored bytes. Masked
//! ranges map from served coordinates to stored coordinates through the native
//! lifted-key masking exactly, so no span is refused and none falls back.

use super::BoundBranchRead;
use crate::Vault;
use crate::batch::secret_scan::LiftedKeys;
use crate::claim::{ClaimSource, ScopedRead};
use crate::dreamer_consolidation::TurnText;
use crate::dreamer_consolidation::evidence::{
    EvidenceLocator, EvidenceReader, ExtractedCandidate, VerifiedCandidate,
};
use crate::dreamer_consolidation::provenance::PromotionCandidate;
use crate::dreamer_consolidation::support::invalid_consolidation;
use crate::entity_id::EntityId;
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::verbs::{CandidateOperand, TurnEvidence};
use oneiron_model::llm::ScopeResource;

/// What bound verification reads from its projection in one snapshot.
/// The adapter holds the bound maps with the live read that rebuilt them.
/// No transaction opens here and no row writes.
struct BoundEvidenceReader<'a> {
    /// Borrows the bound projection that holds pins, texts, and priors.
    bound: &'a BoundBranchRead,
    /// Borrows the live scoped read that rebuilt the projection.
    read: &'a ScopedRead<'a>,
    /// Borrows the caller transaction that holds the snapshot.
    txn: &'a heed::RoTxn<'a>,
}

impl EvidenceReader for BoundEvidenceReader<'_> {
    /// Verifies each reference against the bound projection in its snapshot.
    fn read_verified_refs(
        &self,
        refs: &[crate::dreamer_consolidation::SwarmEvidenceRef],
    ) -> crate::error::Result<Vec<crate::dreamer_consolidation::VerifiedSwarmEvidence>> {
        let mut verified = Vec::with_capacity(refs.len());
        for entry in refs {
            verified.push(self.verify_bound_reference(entry)?);
        }
        Ok(verified)
    }
    /// Returns the exact version the bound projection pinned for the source.
    fn read_source_version(&self, id: &EntityId) -> crate::error::Result<ScopeResource> {
        self.bound
            .sources
            .get(id)
            .map(|pin| pin.resource.clone())
            .ok_or_else(|| invalid_consolidation("unadmitted evidence source"))
    }
    /// Returns the message words the reference covers at the bound revisions.
    fn read_message_spans(
        &self,
        entry: &crate::dreamer_consolidation::SwarmEvidenceRef,
    ) -> crate::error::Result<Vec<crate::dreamer_consolidation::turn_text::MessageSpan>> {
        match self.bound.texts.get(&entry.source_id) {
            Some(text) if entry.claim_id.is_none() => text.spans(entry.byte_range),
            _ => Ok(Vec::new()),
        }
    }
    /// Returns the messages the frozen text the reference cites joins in order.
    fn read_projection(
        &self,
        entry: &crate::dreamer_consolidation::SwarmEvidenceRef,
    ) -> Vec<EntityId> {
        match self.bound.texts.get(&entry.source_id) {
            Some(text) if entry.claim_id.is_none() => text.projection(),
            _ => Vec::new(),
        }
    }
}

impl BoundEvidenceReader<'_> {
    /// Verifies one reference's admission, pinned bytes and native source classification.
    fn verify_bound_reference(
        &self,
        entry: &crate::dreamer_consolidation::SwarmEvidenceRef,
    ) -> crate::error::Result<crate::dreamer_consolidation::VerifiedSwarmEvidence> {
        if let Some(claim) = entry.claim_id {
            if claim != entry.source_id
                || entry.byte_range.is_some()
                || !self.bound.priors.contains_key(&claim)
            {
                return Err(invalid_consolidation("unadmitted branch claim evidence"));
            }
        } else if !self.bound.turns.contains_key(&entry.source_id) {
            return Err(invalid_consolidation("unlisted branch evidence"));
        }
        let pin = self
            .bound
            .sources
            .get(&entry.source_id)
            .ok_or_else(|| invalid_consolidation("unlisted branch evidence"))?;
        if !self.bound.scope.allows_read(&pin.resource) {
            return Err(invalid_consolidation("branch evidence read refused"));
        }
        let row = self
            .read
            .get_entities_parts_in_txn(self.txn, std::slice::from_ref(&entry.source_id))?
            .pop()
            .flatten()
            .ok_or_else(|| invalid_consolidation("branch evidence is not readable"))?;
        let (kind, learned_at, body) = row;
        if kind != pin.entity_type
            || learned_at != pin.learned_at
            || crate::dreamer_consolidation::resources::document_version(entry.source_id, &body)
                != pin.resource
        {
            return Err(invalid_consolidation("branch evidence revision changed"));
        }
        let trust = if entry.claim_id.is_some() {
            if kind != crate::registry::ENTITY_TYPE_CLAIM {
                return Err(invalid_consolidation("branch claim evidence type changed"));
            }
            let claim = crate::claim::decode_claim_body(&body, true)?;
            if !crate::claim::claim_evidence_admissible(&claim) {
                return Err(invalid_consolidation("generated claim cannot corroborate"));
            }
            crate::dreamer_consolidation::provenance::evidence_source_from_claim(&claim)
        } else {
            if kind != crate::registry::ENTITY_TYPE_TURN {
                return Err(invalid_consolidation("branch turn evidence type changed"));
            }
            crate::dreamer_consolidation::resources::native_turn_source(self.read.vault(), &body)?
        };
        let text = self
            .bound
            .texts
            .get(&entry.source_id)
            .and_then(TurnText::text);
        crate::dreamer_consolidation::verify_swarm_evidence_bytes(*entry, kind, &body, text, trust)
    }
}

/// One stored byte offset for each character offset of a text.
/// The tables below map served coordinates to stored coordinates exactly.
struct CharByteTables {
    /// Maps each stored character index to its byte offset with the end length.
    stored_to_bytes: Vec<usize>,
    /// Maps each shown character index to its byte offset with the end length.
    shown_to_bytes: Vec<usize>,
}

/// Builds the character to byte tables for stored and shown texts.
/// Each table holds one byte offset per character plus the text length.
fn char_byte_tables(stored: &str, shown: &str) -> CharByteTables {
    /// Maps each character index of the text to its byte offset with the end length.
    fn table(text: &str) -> Vec<usize> {
        let mut offsets: Vec<usize> = text.char_indices().map(|(at, _)| at).collect();
        offsets.push(text.len());
        offsets
    }
    CharByteTables {
        stored_to_bytes: table(stored),
        shown_to_bytes: table(shown),
    }
}

/// Maps one served byte range over shown text to stored bytes exactly.
/// Served ends inside handles widen to handle edges through the native masking.
/// Returns the stored byte range the verified citation binds.
fn map_masked_range(
    keys: &LiftedKeys,
    stored: &str,
    tables: &CharByteTables,
    start: u64,
    end: u64,
) -> crate::error::Result<(usize, usize)> {
    let start_byte =
        usize::try_from(start).map_err(|_| invalid_consolidation("invalid evidence byte range"))?;
    let end_byte =
        usize::try_from(end).map_err(|_| invalid_consolidation("invalid evidence byte range"))?;
    let start_char = tables
        .shown_to_bytes
        .iter()
        .position(|at| *at == start_byte)
        .ok_or_else(|| invalid_consolidation("evidence range splits UTF-8 text"))?;
    let end_char = tables
        .shown_to_bytes
        .iter()
        .position(|at| *at == end_byte)
        .ok_or_else(|| invalid_consolidation("evidence range splits UTF-8 text"))?;
    let masked = keys.masked_text(stored);
    let selection = masked
        .selection(start_char, end_char)
        .ok_or_else(|| invalid_consolidation("invalid evidence byte range"))?;
    let stored_start = tables
        .stored_to_bytes
        .get(selection.stored.start)
        .copied()
        .ok_or_else(|| invalid_consolidation("invalid evidence byte range"))?;
    let stored_end = tables
        .stored_to_bytes
        .get(selection.stored.end)
        .copied()
        .ok_or_else(|| invalid_consolidation("invalid evidence byte range"))?;
    Ok((stored_start, stored_end))
}

/// Maps a failure of bound evidence verification for its callers.
/// A claim-domain failure is the operand's and answers `BAD_REQUEST` with its reason.
/// Any other failure keeps the engine's own mapping, so a storage failure of a row read
/// answers as internal and never reads as a refusal of the request.
fn verification_error(error: crate::error::Error) -> MemoryError {
    if matches!(
        error,
        crate::error::Error::Claim(_) | crate::error::Error::InvalidClaimBody(_)
    ) {
        MemoryError::bad_request(error.to_string())
    } else {
        MemoryError::from(error)
    }
}

impl BoundBranchRead {
    /// Verifies one observation operand against this projection in the caller transaction.
    /// Whole turns bind whole stored text while unmasked ranges bind directly.
    /// Masked ranges map from served coordinates to stored coordinates exactly with no fallback.
    /// Times stamp through the one shared native clock rule from the caller milliseconds.
    pub(crate) fn verify_observation_candidate_in_txn(
        &self,
        memory: &Memory<'_>,
        read: &ScopedRead<'_>,
        txn: &heed::RoTxn<'_>,
        operand: &CandidateOperand,
        checked: &PromotionCandidate,
        now_ms: u64,
    ) -> MemoryResult<VerifiedCandidate> {
        let (occurred, learned_at) =
            crate::dreamer_consolidation::executor::extraction::claim_times(now_ms);
        let mut stamped = checked.clone();
        stamped.occurred = occurred;
        stamped.learned_at = learned_at;
        self.verify_observation_evidence_in_txn(memory, read, txn, operand, &stamped)
    }
    /// Verifies one observation operand's evidence against this projection in the caller transaction.
    /// Whole turns bind whole stored text while unmasked ranges bind directly.
    /// Masked ranges map from served coordinates to stored coordinates exactly with no fallback.
    /// The checked proposal verifies as is with no clock stamp, so rebuilds without a frozen clock share one rule.
    pub(crate) fn verify_observation_evidence_in_txn(
        &self,
        memory: &Memory<'_>,
        read: &ScopedRead<'_>,
        txn: &heed::RoTxn<'_>,
        operand: &CandidateOperand,
        checked: &PromotionCandidate,
    ) -> MemoryResult<VerifiedCandidate> {
        let mut locators = Vec::with_capacity(operand.evidence.len());
        for evidence in &operand.evidence {
            locators.push(self.stored_locator_in_txn(memory, read, txn, evidence)?);
        }
        let extracted =
            ExtractedCandidate::new(checked.clone(), locators).map_err(verification_error)?;
        let reader = BoundEvidenceReader {
            bound: self,
            read,
            txn,
        };
        crate::dreamer_consolidation::evidence::VerifiedCandidate::from_extracted_with_reader(
            &reader, extracted,
        )
        .map_err(verification_error)
    }
    /// Reads a verified candidate's evidence meet and observed-preference qualification in the caller transaction.
    /// The meet folds from the verified evidence set exactly as native verification folds it.
    /// A generated meet with a preference predicate qualifies only when the verified refs hold observed-preference support.
    /// Proposal times play no role here, so stamped and stamp-free verification share this one rule.
    pub(crate) fn observation_qualification_in_txn(
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        candidate: &VerifiedCandidate,
    ) -> MemoryResult<(ClaimSource, bool)> {
        let meet = candidate.evidence.meet();
        let predicate =
            crate::dreamer_consolidation::candidate_probe_body(&candidate.candidate)?.predicate;
        let observed = meet == ClaimSource::Generated
            && crate::claim::is_preference_predicate(&predicate)
            && crate::claim::observed_preference_support_in_txn(
                vault,
                txn,
                &candidate.evidence.refs(),
            )?;
        Ok((meet, observed))
    }
    /// Binds one turn evidence to its stored locator in the caller transaction.
    /// Whole turns cover whole stored text while spans map exactly when masked.
    fn stored_locator_in_txn(
        &self,
        memory: &Memory<'_>,
        read: &ScopedRead<'_>,
        txn: &heed::RoTxn<'_>,
        evidence: &TurnEvidence,
    ) -> MemoryResult<EvidenceLocator> {
        let turn = crate::dreamer_consolidation::extraction_pack::parse_reference(&evidence.turn)
            .map_err(|error| MemoryError::bad_request(error.to_string()))?;
        let stored = self
            .texts
            .get(&turn)
            .and_then(TurnText::text)
            .ok_or_else(|| MemoryError::bad_request("cited turn has no text"))?;
        let Some(span) = evidence.span else {
            return EvidenceLocator::turn_range(turn, 0, stored.len())
                .map_err(|error| MemoryError::bad_request(error.to_string()));
        };
        let text = self
            .texts
            .get(&turn)
            .ok_or_else(|| MemoryError::bad_request("cited turn has no text"))?;
        let keys = crate::snapshot_read::turn_lifted_keys_in_txn(memory, read, txn, &turn, text)?;
        let Some(keys) = keys else {
            let start = usize::try_from(span.start)
                .map_err(|_| MemoryError::bad_request("invalid evidence byte range"))?;
            let end = usize::try_from(span.end)
                .map_err(|_| MemoryError::bad_request("invalid evidence byte range"))?;
            return EvidenceLocator::turn_range(turn, start, end)
                .map_err(|error| MemoryError::bad_request(error.to_string()));
        };
        let (start, end) = stored_range_for_served_range(&keys, stored, span)
            .map_err(|error| MemoryError::bad_request(error.to_string()))?;
        EvidenceLocator::turn_range(turn, start, end)
            .map_err(|error| MemoryError::bad_request(error.to_string()))
    }
}

/// Maps one served byte range over a TURN's stored text to its stored bytes:
/// an end inside a handle widens to that handle's edge, through the native
/// lifted-key masking exactly. The bound extraction read and the derive
/// stager share this one rule.
pub(crate) fn stored_range_for_served_range(
    keys: &LiftedKeys,
    stored: &str,
    range: crate::snapshot_read::EvidenceRange,
) -> crate::error::Result<(usize, usize)> {
    let shown = keys.masked(stored).unwrap_or_else(|| stored.to_owned());
    let tables = char_byte_tables(stored, &shown);
    map_masked_range(keys, stored, &tables, range.start, range.end)
}
