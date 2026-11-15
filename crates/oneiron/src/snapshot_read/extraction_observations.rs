//! Pinned, bounded facts for the operands of one live extraction attempt.
//!
//! The page reports native equality, evidence, scope, graph and vector facts.
//! It never groups candidates, computes a strength, chooses a route or serves words.

mod facts;
mod paging;
mod tokens;
mod types;

pub use types::{
    CandidateObservation, ExtractionObservationsPage, ExtractionObservationsPageRequest,
    PriorObservation, ReplayObservation, SimilarityScore,
};

use self::facts::extraction_observation_facts;
use self::paging::{observation_facts_pin, page_observation_facts};
use super::extraction_inputs::{extraction_attempt_key, extraction_policy_pin};
use super::{ExtractionPolicy, extraction_reader_scope_in_txn, extraction_turn_read};
use crate::attempt_queue::AttemptId;
use crate::claim::{ClaimReadStatus, ScopedReadResult};
use crate::dreamer_consolidation::extraction_pack::{
    check_extraction_operands_in_txn, check_pack_candidates,
};
use crate::dreamer_runner::DreamerAttemptBinding;
use crate::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};

/// Reads bounded word-free facts through the owner's proof or a live Steward read grant.
///
/// # Errors
///
/// A missing read authority, an invalid attempt, operand, evidence pin or cursor,
/// a stale fact pin, an invalid stored vector, an oversized row, or a storage failure.
pub fn extraction_observations_page(
    memory: &Memory<'_>,
    input: &ExtractionObservationsPageRequest,
) -> MemoryResult<ScopedReadResult<ExtractionObservationsPage>> {
    bound_extraction_observations_page(memory, input, None)
}

/// Proves the Extraction binding in the page transaction before reading any fact rows.
///
/// # Errors
///
/// As [`extraction_observations_page`], and a stale binding or another attempt.
pub(crate) fn extraction_observations_page_bound(
    memory: &Memory<'_>,
    input: &ExtractionObservationsPageRequest,
    binding: &DreamerAttemptBinding,
) -> MemoryResult<ScopedReadResult<ExtractionObservationsPage>> {
    bound_extraction_observations_page(memory, input, Some(binding))
}

/// Serves both reader paths through the same transaction and native operand checks.
fn bound_extraction_observations_page(
    memory: &Memory<'_>,
    input: &ExtractionObservationsPageRequest,
    binding: Option<&DreamerAttemptBinding>,
) -> MemoryResult<ScopedReadResult<ExtractionObservationsPage>> {
    let vault = memory.vault();
    let attempt = extraction_attempt_key(&input.attempt)?;
    let attempt_id = AttemptId::from_bytes(attempt.as_bytes())?;
    let owner = if binding.is_none() {
        memory
            .embedded_owner("vault.consolidation.extraction.observations.page")
            .ok()
    } else {
        None
    };
    let read = memory.read_lane(ClaimReadStatus::Recorded)?;
    let turn_read = extraction_turn_read(&read, owner.as_ref())?;
    let _pins = read.prepare_point_read::<MemoryError>()?;
    let _turn_pins = turn_read
        .as_ref()
        .map(|read| read.prepare_point_read::<MemoryError>())
        .transpose()?;
    let turn_read = turn_read.as_ref().unwrap_or(&read);
    let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
    if let Some(binding) = binding {
        binding.check_in_txn(&txn)?;
        if attempt != binding.attempt() {
            return Err(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "an extraction binding reads its own attempt's observations only",
                &[],
            ));
        }
    }
    memory.prove_read_authority_in_txn(&txn)?;
    let reader_scope = extraction_reader_scope_in_txn(memory, &txn, owner.as_ref())?;
    read.read_projected_in_txn(&txn, &[], None, |txn, _| {
        let (branch, bound) = check_extraction_operands_in_txn(
            memory,
            &read,
            txn,
            reader_scope.as_ref(),
            attempt_id,
            &input.candidates,
            None,
        )?;
        let checked = check_pack_candidates(&input.candidates, &bound, attempt_id, &branch)
            .map_err(|error| MemoryError::bad_request(error.to_string()))?;
        // The pin covers exactly the key rules the tokens below hash under.
        let policy = ExtractionPolicy {
            prefilter: vault.prefilter_config_in_txn(txn)?,
            selection: vault.consolidation_selection_in_txn(txn)?,
            key_rules: bound.key_rules().clone(),
        };
        let policy_pin = extraction_policy_pin(&policy)?;
        let proposals = checked.rows.into_iter().map(|row| row.proposal).collect();
        let facts = extraction_observation_facts(
            memory,
            (&read, turn_read),
            txn,
            &bound,
            input,
            proposals,
        )?;
        let facts_pin = observation_facts_pin(input, &policy_pin, &facts)?;
        let bounds = vault.snapshot_read_settings_in_txn(txn)?;
        page_observation_facts(
            input,
            policy_pin,
            facts_pin,
            facts,
            bounds.page_rows,
            bounds.page_bytes,
        )
    })
}
