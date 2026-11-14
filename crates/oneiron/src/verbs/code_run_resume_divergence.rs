//! The input and answer of `vault.code_run.resume_divergence.answer` (L8-23), a host door: the
//! vault owner's answer to the inbox ask a resumed pending step raised when its re-entered program
//! changed an effect step, the ask's one-tap actions. A server runs it under the vault owner's
//! proof; an embedded handle runs it as its embedded owner. An agent never answers it.
//!
//! Refire releases the changed effect steps to run live once at their own seqs, which the run does
//! at its next entry over the held call; leave makes them answer the step `effect_changed_left`,
//! and the run goes on without them. The first answer settles the ask; a later one finds it
//! settled.

use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::memory::{MemoryError, MemoryResult};

#[doc(hidden)]
pub use oneiron_verb_wire::verbs::code_run_resume_divergence::{
    ResumeDivergenceAnswer, ResumeDivergenceAnswerOutcome, ResumeDivergenceAnswered,
    ResumeDivergenceChoice,
};

/// `vault.code_run.resume_divergence.answer` under the owner's proof.
///
/// # Errors
///
/// A `report_digest` that is not 64 lowercase hex digits; a proof that is not a live owner's.
pub fn answer_code_run_resume_divergence_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: ResumeDivergenceAnswer,
) -> MemoryResult<ResumeDivergenceAnswered> {
    let digest = input.report_digest;
    let valid = digest.len() == 64
        && digest
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'));
    if !valid {
        return Err(MemoryError::bad_request(
            "report_digest is not the 64 lowercase hex digits of an effect digest",
        ));
    }
    let outcome = vault.answer_code_run_resume_divergence(
        owner,
        input.run_ref,
        input.step_seq,
        &digest,
        input.choice,
    )?;
    Ok(ResumeDivergenceAnswered {
        run_ref: input.run_ref,
        step_seq: input.step_seq,
        report_digest: digest,
        choice: input.choice,
        outcome,
    })
}
