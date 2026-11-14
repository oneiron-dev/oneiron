//! A conflict-settlement attempt's bound settlement ask (`ai.verdict`).
//!
//! Each verdict is one of today's conflict-settlement asks, not a generic
//! Choice question. The caller offers rows of one open conflict and chooses
//! its wording, round and page. The question and learned bands are keyed by
//! the contested predicates and page, while model rungs see call-local labels.
//! The host lends its ladder and bands; the canonical answer, receipt and
//! spend belong to this call, just as on the parked settlement path.
//!
//! The marker must be one the bound conflicts page serves to the Dreamer.
//! The page's reader checks the marker and every member in the transaction
//! that proves the binding and prepares the ask. That snapshot closes before
//! the lease is checked again and the host's ladder is lent. The ask uses
//! outbound-effect reversibility and the settlement dial, lowered by a
//! requested ceiling. Without a lender it refuses `MODEL_UNAVAILABLE` after
//! validating the request and reading the conflict.

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::Value;

use super::DreamerAttemptBinding;
use crate::EntityId;
use crate::claim::ClaimReadStatus;
use crate::dreamer_consolidation::settle::MAX_KEEP_OPTIONS;
use crate::dreamer_consolidation::settle::decision_pages::{PageAnswer, run_ask};
use crate::dreamer_consolidation::settle::decision_projection::{
    AskPart, SettleAsk, settle_rows_in_txn,
};
use crate::dreamer_consolidation::{
    CONFLICT_SETTLE_DIAL, ConflictSettleDecisions, open_conflicts_in_txn,
};
use crate::llm::decision::{
    AnswerContract, DecisionBandPolicy, DecisionDial, DecisionLadder, DecisionRung, TypedDecision,
};
use crate::memory::{
    MEMORY_CODE_FORBIDDEN, MEMORY_CODE_MODEL_UNAVAILABLE, MemoryError, MemoryResult,
};
use crate::retrieval_depth::RetrievalDeadline;
use crate::snapshot_read::{conflict_reader_in_txn, conflict_served_in_txn};
use crate::verbs::{AI_VERDICT_DEADLINE_MS, AiVerdict, AiVerdictRequest, AiVerdictReversibility};

/// Describes the caller's position and prior answers for one paged settlement ask.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BoundSettlePage {
    round: usize,
    page: usize,
    pages: usize,
    page_answers: Vec<String>,
}

impl BoundSettlePage {
    /// Checks the page bounds and reads the preceding round's canonical answers.
    fn answers(&self) -> MemoryResult<Vec<PageAnswer>> {
        if self.pages == 0 || self.page >= self.pages {
            return Err(MemoryError::bad_request(
                "a settlement page needs pages >= 1 and a zero-based page below pages",
            ));
        }
        self.page_answers
            .iter()
            .map(|answer| match answer.as_str() {
                "hold_both" => Ok(PageAnswer::HoldBoth),
                "dismiss" => Ok(PageAnswer::Dismiss),
                other => other
                    .strip_prefix("keep:")
                    .and_then(|hex| EntityId::from_hex(hex).ok())
                    .map(PageAnswer::Keep)
                    .ok_or_else(|| {
                        MemoryError::bad_request(
                            "page_answers must contain hold_both, dismiss or keep:<32 hex>",
                        )
                    }),
            })
            .collect()
    }
}

/// Reads the marker and distinct offered row ids without resolving generic
/// evidence views. The marker may stand alone: a final round whose pages
/// kept no member offers no row, and asks among hold both, dismiss and
/// escalate beside the pages' answers, as the parked path asked.
fn settle_evidence_ids(references: &[String]) -> MemoryResult<Vec<EntityId>> {
    if references.len() < 2 {
        return Err(MemoryError::bad_request(
            "settlement evidence needs a conflict marker, then the rows the ask offers",
        ));
    }
    let ids: Vec<EntityId> = references
        .iter()
        .map(|reference| {
            EntityId::from_hex(reference).map_err(|_| {
                MemoryError::bad_request(
                    "settlement evidence must name its marker and rows as 32 hex digits",
                )
            })
        })
        .collect::<MemoryResult<_>>()?;
    let mut offered = BTreeSet::new();
    if ids[1..].iter().any(|id| !offered.insert(*id)) {
        return Err(MemoryError::bad_request(
            "settlement evidence must offer distinct conflict rows",
        ));
    }
    Ok(ids)
}

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
    /// Asks one conflict-settlement question as the Dreamer on the host's ladder.
    ///
    /// Evidence names a page-readable conflict marker followed by distinct
    /// offered rows, none in a final round whose pages kept no member. The
    /// Choice options must match the canonical settlement options for those
    /// rows in order. A null state makes an unpaged ask;
    /// a page state supplies its round, zero-based page, page count and prior
    /// page answers. The shared settlement ask supplies the predicate-keyed
    /// question, labelled state and model options, and outbound reversibility.
    /// Evidence sent to the ladder is the marker and every stored member,
    /// including members this page does not offer.
    ///
    /// The request may lower the settlement dial's ceiling but never reach
    /// Human. Its hard deadline is the request's milliseconds or
    /// [`AI_VERDICT_DEADLINE_MS`] when absent. The read transaction closes
    /// before the binding is checked again and the ladder is lent once.
    ///
    /// # Errors
    ///
    /// A bad request for unsupported verdict flags, another reversibility,
    /// invalid page state, invalid or duplicate row ids, rows outside the
    /// conflict, too many keep options, mismatched options, an invalid typed
    /// question or a deadline outside 1 to 60000 milliseconds. `FORBIDDEN`
    /// when the bound page would not serve the marker and every member.
    /// `MODEL_UNAVAILABLE` when no host lends a ladder, after request and
    /// read checks. The binding's refusals and the ladder's own errors.
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
        if input.reversibility != AiVerdictReversibility::OutboundEffect {
            return Err(MemoryError::bad_request(
                "a conflict-settlement ask requires outbound_effect reversibility",
            ));
        }
        let page: Option<BoundSettlePage> =
            serde_json::from_value(input.state.unwrap_or(Value::Null)).map_err(|error| {
                MemoryError::bad_request(format!("invalid settlement page state: {error}"))
            })?;
        let before = page
            .as_ref()
            .map(BoundSettlePage::answers)
            .transpose()?
            .unwrap_or_default();
        let part = AskPart {
            at: page
                .as_ref()
                .map(|page| (page.round, page.page, page.pages)),
            before: &before,
        };
        let offered = settle_evidence_ids(&input.evidence)?;
        let vault = &*self.vault;
        let memory = vault.memory(self.stamp.actor, self.actor().actor_class());
        let prepared = {
            let read = memory.read_lane(ClaimReadStatus::Recorded)?;
            let _pins = read.prepare_point_read::<MemoryError>()?;
            let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
            memory.prove_read_authority_in_txn(&txn)?;
            self.check_in_txn(&txn)?;
            let reader = conflict_reader_in_txn(&memory, &txn, None)?;
            read.read_projected_in_txn(&txn, &[], None, |txn, _| {
                let forbidden = || {
                    MemoryError::new(
                        MEMORY_CODE_FORBIDDEN,
                        "the conflict marker and every member must read for the Dreamer attempt's conflicts page",
                        &["Ask only about an open conflict served by the bound conflicts page."],
                    )
                };
                let conflict = open_conflicts_in_txn(vault, txn, None)?
                    .into_iter()
                    .find(|conflict| conflict.marker == offered[0])
                    .ok_or_else(forbidden)?;
                if !conflict_served_in_txn(vault, txn, &read, &reader, self.actor(), &conflict)? {
                    return Err(forbidden());
                }
                let rows = settle_rows_in_txn(vault, txn, &conflict)?;
                let rows = offered[1..]
                    .iter()
                    .map(|id| {
                        rows.iter().find(|row| row.id == *id).ok_or_else(|| {
                            MemoryError::bad_request(
                                "each offered member must be a settlement row of the conflict",
                            )
                        })
                    })
                    .collect::<MemoryResult<Vec<_>>>()?;
                if rows.iter().filter(|row| row.keep).count() > MAX_KEEP_OPTIONS {
                    return Err(MemoryError::bad_request(
                        "too many keepable rows for one settlement ask; page the ask",
                    ));
                }
                let ask = SettleAsk::over(&conflict, &input.question, &rows, &part).map_err(|_| {
                    MemoryError::bad_request(
                        "the settlement question does not make a typed question within its wording and option limits",
                    )
                })?;
                if input.contract != ask.question.contract {
                    return Err(MemoryError::bad_request(format!(
                        "settlement contract must match the expected options: {:?}",
                        ask.question.contract,
                    )));
                }
                let mut evidence = vec![conflict.marker];
                evidence.extend(conflict.members.iter().copied());
                Ok((ask, evidence))
            })?
            .value
        };
        let (ask, evidence) = prepared;
        let Some(lender) = self.lender.clone() else {
            return Err(MemoryError::new(
                MEMORY_CODE_MODEL_UNAVAILABLE,
                "no host lends this attempt a decision ladder",
                &["Run under a host that lends decisions, then ask again."],
            ));
        };
        let deadline_ms = input.deadline_ms.unwrap_or(AI_VERDICT_DEADLINE_MS);
        let deadline = RetrievalDeadline::hard(Instant::now(), Duration::from_millis(deadline_ms));
        let dial = DecisionDial {
            ceiling: input
                .ceiling
                .unwrap_or(CONFLICT_SETTLE_DIAL.ceiling)
                .min(CONFLICT_SETTLE_DIAL.ceiling),
            ..CONFLICT_SETTLE_DIAL
        };
        let mut decide = |ladder: &DecisionLadder<'_>, bands: &DecisionBandPolicy| {
            let decisions = ConflictSettleDecisions {
                ladder: ladder.clone(),
                principal: self.stamp.actor,
                dial,
                bands: bands.clone(),
                wording: input.question.clone(),
                deadline: &deadline,
            };
            run_ask(&decisions, vault, &ask, &evidence)
        };
        self.check()?;
        let decision = lender.lend(&mut decide).map_err(MemoryError::from)?;
        Ok(AiVerdict::from(decision))
    }
}
