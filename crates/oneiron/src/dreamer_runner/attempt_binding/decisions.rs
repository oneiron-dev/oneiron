//! A conflict-settlement attempt's bound `ai.verdict` (brief S69D3).
//!
//! A conflict-settlement attempt asks Choice questions through the host's lent
//! decision ladder under [`CONFLICT_SETTLE_DIAL`](crate::dreamer_consolidation::CONFLICT_SETTLE_DIAL).
//! The verdict takes the caller's question, its Choice options and its state,
//! reads each evidence ref under the Dreamer's Steward read, and runs one
//! [`DecisionLadder::run`](crate::llm::decision::DecisionLadder::run) inside
//! [`DreamerDecisionLender::lend`]. The call owns its receipts and its spend:
//! the ladder's answer, its receipt and what its rungs spent belong to this
//! verdict alone, never to the host's other calls.
//!
//! The bound facet admits Choice only. A routine step, an image, misses, a
//! subgoal clock, a human ceiling and any other contract are refused before
//! any row is read. Each evidence ref resolves with the engine's read target,
//! live or pinned as `<ref>@<32 hex>`, and reads like a conflicts-page member:
//! the binding is proved in the same read transaction that judges the scope
//! and the rows, and any valid ref that does not read there is `FORBIDDEN`,
//! never silently dropped. A syntactically invalid ref stays a bad request.
//! The evidence transaction closes before the check and the lent call, so the
//! check and the ladder never run under a held snapshot. With no lent ladder
//! the verdict is `MODEL_UNAVAILABLE`.

use std::time::{Duration, Instant};

use serde_json::Value;

use super::DreamerAttemptBinding;
use crate::claim::ClaimReadStatus;
use crate::dreamer_consolidation::CONFLICT_SETTLE_DIAL;
use crate::llm::decision::{
    AnswerContract, DecisionBandPolicy, DecisionDial, DecisionLadder, DecisionRung, Reversibility,
    TypedDecision,
};
use crate::memory::{
    MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INTERNAL, MEMORY_CODE_MODEL_UNAVAILABLE,
    MEMORY_CODE_NOT_FOUND, MemoryError, MemoryResult,
};
use crate::model_decision::catalogue::AI_VERDICT;
use crate::retrieval_depth::RetrievalDeadline;
use crate::snapshot_read::{
    observation_reader_scope_for_actor_in_txn, observed_claim_reads_in_txn,
};
use crate::verbs::{AI_VERDICT_DEADLINE_MS, AiVerdict, AiVerdictRequest};

/// What the host lends a conflict-settlement attempt's bound verdicts: its
/// decision ladder and its learned bands for one call.
///
/// The lender holds the host's ladder and policy while the attempt holds its
/// lease. Each verdict runs its one decision inside [`Self::lend`], so the
/// host's seats, wording and bands stay the host's and the verdict's
/// receipts and spend stay the verdict's own.
pub trait DreamerDecisionLender: Send + Sync {
    /// Runs `decide` with the host's decision ladder and learned bands.
    ///
    /// The closure runs once per verdict and calls the ladder itself, so the
    /// verdict owns the decision's receipts and spend. The lender lends the
    /// ladder and the policy it enforces; it does not answer, cut state or
    /// keep receipts of its own.
    ///
    /// # Errors
    ///
    /// The decision's own failures, as the ladder reports them, and the
    /// host's own lending failures.
    fn lend(
        &self,
        decide: &mut dyn FnMut(
            &DecisionLadder<'_>,
            &DecisionBandPolicy,
        ) -> crate::Result<TypedDecision>,
    ) -> crate::Result<TypedDecision>;
}

impl DreamerAttemptBinding {
    /// Asks `input` through the host's lent ladder as the Dreamer under this
    /// binding.
    ///
    /// The question runs under [`CONFLICT_SETTLE_DIAL`](crate::dreamer_consolidation::CONFLICT_SETTLE_DIAL)
    /// with the request's ceiling capped at `big`, the request's
    /// reversibility, and a hard deadline of the request's milliseconds or
    /// [`AI_VERDICT_DEADLINE_MS`] when absent. Each evidence ref resolves with
    /// the engine's read target, live or pinned as `<ref>@<32 hex>`, then reads
    /// in the same read transaction that proves the binding, judges the Dreamer's
    /// Steward scope and reads the rows at their pins. The evidence transaction
    /// closes before the check and the lent call. The binding is checked again
    /// immediately before the lent call, and the lent call runs the ladder once.
    ///
    /// # Errors
    ///
    /// A bad request for a routine step, an image, misses, a subgoal clock,
    /// a human ceiling, a contract other than Choice, a deadline outside 1
    /// to 60000 milliseconds, a syntactically invalid evidence ref or revision,
    /// or a question that does not make a typed question. `FORBIDDEN` for a valid
    /// evidence ref that does not read for the Dreamer, including a
    /// syntactically valid id with no row, a short ref that does not resolve,
    /// and a pin that names no retained revision. `MODEL_UNAVAILABLE` when no
    /// host lends this attempt a decision ladder. The binding's refusals and the
    /// ladder's own errors.
    pub(crate) fn verdict(&self, input: AiVerdictRequest) -> MemoryResult<AiVerdict> {
        crate::request_limits::check_deadline_ms(input.deadline_ms)?;
        if input.routine {
            return Err(MemoryError::bad_request_with(
                "a conflict-settlement bound verdict is never a routine step",
                &["Ask a plain choice without routine."],
            ));
        }
        if input.image.is_some() {
            return Err(MemoryError::bad_request_with(
                "a conflict-settlement bound verdict reads no image",
                &["Ask without an image."],
            ));
        }
        if input.misses != 0 {
            return Err(MemoryError::bad_request_with(
                "a conflict-settlement bound verdict takes no misses",
                &["Send misses as zero."],
            ));
        }
        if input.until_ms.is_some() {
            return Err(MemoryError::bad_request_with(
                "a conflict-settlement bound verdict runs on its own deadline, never the subgoal clock",
                &["Ask without until_ms."],
            ));
        }
        if input.ceiling == Some(DecisionRung::Human) {
            return Err(MemoryError::bad_request_with(
                "ai.verdict never queues an owner ask",
                &["Name a ceiling below human, or ask the owner through ask."],
            ));
        }
        if !matches!(input.contract, AnswerContract::Choice { .. }) {
            return Err(MemoryError::bad_request_with(
                "a conflict-settlement bound verdict is a choice among its options",
                &["Ask a choice, not a yes-or-no, score, box or point."],
            ));
        }
        let deadline_ms = input.deadline_ms.unwrap_or(AI_VERDICT_DEADLINE_MS);
        let ceiling = input
            .ceiling
            .unwrap_or(DecisionRung::Big)
            .min(DecisionRung::Big);
        let dial = DecisionDial {
            ceiling,
            ..CONFLICT_SETTLE_DIAL
        };
        let reversibility: Reversibility = input.reversibility.into();
        let contract = input.contract;
        let key = serde_json::to_vec(&contract).map_err(|_| {
            MemoryError::new(
                MEMORY_CODE_INTERNAL,
                "ai.verdict did not finish on this server",
                &["Report this decision-ladder failure."],
            )
        })?;
        let question = AI_VERDICT
            .question(&[key.as_slice()], input.question, contract)
            .map_err(|_| {
                MemoryError::bad_request_with(
                    "the question does not make a typed question",
                    &["Word it in 1 to 16384 bytes, with 1 to 64 distinct options of 1 to 256 bytes each."],
                )
            })?;
        let evidence_refs = input.evidence;
        let caller_state = input.state.unwrap_or(Value::Null);
        let memory = self
            .vault
            .memory(self.stamp.actor, self.actor().actor_class());
        let mut targets = Vec::with_capacity(evidence_refs.len());
        for reference in &evidence_refs {
            let (base, mode) = match reference.rsplit_once('@') {
                Some((base, revision)) => {
                    let revision = crate::vault::RevisionRef::from_hex(revision).map_err(|_| {
                        MemoryError::bad_request_with(
                            format!("evidence {reference:?} names no revision after @"),
                            &["Name a revision as 32 hex digits after @, or name the live row."],
                        )
                    })?;
                    (base, crate::vault::ReadMode::Pinned(revision))
                }
                None => (reference.as_str(), crate::vault::ReadMode::Live),
            };
            if base.is_empty() {
                return Err(MemoryError::bad_request_with(
                    format!("evidence {reference:?} names no entity"),
                    &["Name an entity ref, optionally pinned as <ref>@<32 hex>."],
                ));
            }
            match memory.read_target(base, mode) {
                Ok(slot) => targets.push(slot),
                Err(error) if error.code.as_str() == MEMORY_CODE_NOT_FOUND => {
                    return Err(MemoryError::new(
                        MEMORY_CODE_FORBIDDEN,
                        format!("evidence {reference:?} does not read for the Dreamer attempt"),
                        &["Name only members the Dreamer's Steward read reaches."],
                    ));
                }
                Err(error) => return Err(error),
            }
        }
        let mut evidence = Vec::with_capacity(targets.len());
        for (reference, slot) in evidence_refs.iter().zip(&targets) {
            match slot {
                Some((id, _)) => evidence.push(*id),
                None => {
                    return Err(MemoryError::new(
                        MEMORY_CODE_FORBIDDEN,
                        format!("evidence {reference:?} does not read for the Dreamer attempt"),
                        &["Name only members the Dreamer's Steward read reaches."],
                    ));
                }
            }
        }
        let vault = &*self.vault;
        let state = {
            let read = memory.read_lane(ClaimReadStatus::Recorded)?;
            let _pins = read.prepare_point_read::<MemoryError>()?;
            let txn = self
                .vault
                .store
                .env
                .read_txn()
                .map_err(crate::Error::from)?;
            memory.prove_read_authority_in_txn(&txn)?;
            self.check_in_txn(&txn)?;
            let scope = observation_reader_scope_for_actor_in_txn(vault, &txn, self.stamp.actor)?
                .ok_or_else(|| {
                    MemoryError::new(
                        MEMORY_CODE_FORBIDDEN,
                        "the Dreamer attempt has no live Steward read reach",
                        &["Stand a Steward grant naming read for the Dreamer, then admit a new attempt."],
                    )
                })?;
            let scope = scope.as_ref();
            let mut members = Vec::with_capacity(targets.len());
            for ((reference, slot), id) in evidence_refs.iter().zip(&targets).zip(&evidence) {
                if !observed_claim_reads_in_txn(vault, &txn, &read, scope, *id)? {
                    return Err(MemoryError::new(
                        MEMORY_CODE_FORBIDDEN,
                        format!("evidence {reference:?} does not read for the Dreamer attempt"),
                        &["Name only members the Dreamer's Steward read reaches."],
                    ));
                }
                let view = match memory.read_named_view_in_txn(&read, &txn, *slot) {
                    Ok(named) => named.value,
                    Err(error) if error.code.as_str() == MEMORY_CODE_NOT_FOUND => {
                        return Err(MemoryError::new(
                            MEMORY_CODE_FORBIDDEN,
                            format!("evidence {reference:?} does not read for the Dreamer attempt"),
                            &["Name only members the Dreamer's Steward read reaches."],
                        ));
                    }
                    Err(error) => return Err(error),
                };
                let Some(view) = view else {
                    return Err(MemoryError::new(
                        MEMORY_CODE_FORBIDDEN,
                        format!("evidence {reference:?} does not read for the Dreamer attempt"),
                        &["Name only members the Dreamer's Steward read reaches."],
                    ));
                };
                members.push(serde_json::json!({
                    "ref": view.id_hex,
                    "kind": view.kind,
                    "body": view.body,
                }));
            }
            serde_json::json!({
                "state": caller_state,
                "evidence": members,
            })
        };
        let Some(lender) = self.lender.clone() else {
            return Err(MemoryError::new(
                MEMORY_CODE_MODEL_UNAVAILABLE,
                "no host lends this attempt a decision ladder",
                &["Run under a host that lends decisions, then ask again."],
            ));
        };
        let deadline = RetrievalDeadline::hard(Instant::now(), Duration::from_millis(deadline_ms));
        let principal = self.stamp.actor;
        let mut decide = |ladder: &DecisionLadder<'_>, policy: &DecisionBandPolicy| {
            ladder.run(
                &question,
                principal,
                &evidence,
                &state,
                dial,
                policy,
                reversibility,
                &deadline,
            )
        };
        self.check()?;
        let decision: TypedDecision = lender.lend(&mut decide).map_err(MemoryError::from)?;
        Ok(decision.into())
    }
}
