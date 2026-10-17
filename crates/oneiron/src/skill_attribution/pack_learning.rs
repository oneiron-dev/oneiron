//! The manifest-to-learning bridge. Routing and anchoring are both required;
//! terminal success, loading, agreement and self-report alone teach nothing.

use std::collections::BTreeMap;

use crate::entity_id::EntityId;
use crate::learning::{
    Anchor, EvidenceSource, LearningCell, LearningEvidence, LearningPredicate, Observation,
};
use crate::receipt::{PackLearningContext, ReceiptRecord, attempt_pack_receipt};
use crate::{Error, Result, Vault};

use super::codec::evidence_after;
use super::late_credit::{CREDIT_RECEIPT, LateCreditReceipt, receipt_id, shares_in_txn};
use super::{
    AttemptOutcome, AttributionVerdict, FollowedState, attribution_judgments,
    judgment_displaced_in_txn,
};

/// An external observation that settles one attempt's output. The outcome
/// receipt is kept distinct from the attempt's own terminal self-report.
#[derive(Debug, Clone, PartialEq)]
pub struct AnchoredPackOutcome {
    pub receipt: String,
    pub anchor: Anchor,
    pub succeeded: bool,
    /// The anchored rubric axis; never inferred from a task's prose.
    pub axis: String,
    pub at: u64,
}

/// Projects only anchored, attributed outcomes into `learning.reliability`.
/// The returned credit receipt freezes direct subjects, actual-use chains,
/// shares and the execution context, so replay never re-learns a newer decay.
/// All learning heads and this receipt commit together and are idempotent.
pub fn project_anchored_pack_outcome(
    vault: &Vault,
    attempt_receipt: &str,
    outcome: &AnchoredPackOutcome,
    now: u64,
) -> Result<LateCreditReceipt> {
    let anchor = EvidenceSource::Anchored(outcome.anchor).admit()?;
    if !anchor.feeds(LearningPredicate::Reliability) {
        return Err(Error::InvalidClaimBody(
            "a pack outcome needs a correctness anchor",
        ));
    }
    if outcome.receipt.is_empty()
        || outcome.receipt.len() > 256
        || outcome.receipt.chars().any(char::is_control)
        || outcome.receipt == attempt_receipt
    {
        return Err(Error::InvalidClaimBody(
            "a pack outcome requires a distinct anchor receipt",
        ));
    }
    let receipt = attempt_pack_receipt(vault, attempt_receipt)?.ok_or(Error::InvalidClaimBody(
        "an anchored outcome must name a stamped attempt",
    ))?;
    if !matches!(receipt.outcome.as_str(), "completed" | "failed") {
        return Err(Error::InvalidClaimBody(
            "cancelled or abandoned work is not scored",
        ));
    }
    if outcome.axis.is_empty() || outcome.axis.len() > 256 || outcome.axis.contains('\0') {
        return Err(Error::InvalidClaimBody(
            "an anchored pack outcome requires a scored axis",
        ));
    }
    let fields = receipt.pack_attribution_fields()?;
    let evidence: Vec<_> = evidence_after(vault, 0)?
        .into_iter()
        .filter(|(_, row)| row.receipt_ref == attempt_receipt)
        .collect();
    let judgments: BTreeMap<_, _> = attribution_judgments(vault)?
        .into_iter()
        .map(|row| (row.sequence, row))
        .collect();
    let key = receipt_id(attempt_receipt, &outcome.receipt, &outcome.axis);
    vault.with_write_txn_grouped(|txn| {
        // A matched-fork check recorded for this run and axis counts as the
        // skill's contribution, though it landed after the receipt froze.
        let fields = super::contribution::with_recorded_checks_in_txn(
            &vault.store,
            txn,
            attempt_receipt,
            &outcome.axis,
            fields.clone(),
        )?;
        if let Some(previous) = CREDIT_RECEIPT.get(&vault.store, txn, &key)? {
            if previous.anchor != anchor
                || previous.succeeded != outcome.succeeded
                || previous.at != outcome.at
                || previous.axis != outcome.axis
            {
                return Err(Error::InvalidClaimBody(
                    "an anchored pack outcome cannot be rescored",
                ));
            }
            return Ok(previous);
        }
        let routed = super::codec::CURSOR
            .get(&vault.store, txn, &())?
            .unwrap_or(0);
        if evidence.iter().any(|(sequence, _)| *sequence > routed) {
            return Err(Error::InvalidClaimBody(
                "pack attribution is not yet routed",
            ));
        }
        let mut direct = BTreeMap::<EntityId, bool>::new();
        let mut contributing_skills = Vec::new();
        for (sequence, row) in &evidence {
            if outcome.succeeded {
                if row.outcome != AttemptOutcome::Succeeded || receipt.outcome != "completed" {
                    continue;
                }
                // A skill's effectiveness is its executor-qualified cell, not
                // a second actor score for the same skill-bearing run.
                if row.skill.is_none() {
                    direct.insert(row.actor, true);
                }
                let followed = matches!(row.followed_state, Some(FollowedState::Followed))
                    || row.followed_state.is_none() && row.followed_skill == Some(true);
                if let Some(skill) = row.skill
                    && followed
                    && fields
                        .contributions
                        .iter()
                        .any(|c| c.skill == skill && c.check.contributed)
                {
                    require_loaded_skill(vault, txn, &receipt, skill)?;
                    direct.insert(skill, true);
                    if !contributing_skills.contains(&skill) {
                        contributing_skills.push(skill);
                    }
                }
            } else if let Some(judgment) = judgments.get(sequence) {
                if judgment_displaced_in_txn(vault, txn, *sequence)? {
                    continue;
                }
                match judgment.verdict {
                    AttributionVerdict::SkillDefect => {
                        require_loaded_skill(vault, txn, &receipt, judgment.subject)?;
                        direct.insert(judgment.subject, false);
                    }
                    AttributionVerdict::ExecutionLapse => {
                        direct.insert(judgment.subject, false);
                    }
                    _ => {} // discovery, environment and unclear are not failures of a cell
                }
            }
        }
        // A team-pattern skill earns a win only with its own contribution check,
        // not merely because the team receipt named it.
        if outcome.succeeded
            && !direct.is_empty()
            && fields
                .contributions
                .iter()
                .any(|c| c.skill == fields.pattern && c.check.contributed)
        {
            require_loaded_skill(vault, txn, &receipt, fields.pattern)?;
            direct.insert(fields.pattern, true);
            if !contributing_skills.contains(&fields.pattern) {
                contributing_skills.push(fields.pattern);
            }
        }
        let shares = if outcome.succeeded && !direct.is_empty() {
            shares_in_txn(vault, txn, &fields, &contributing_skills)?
        } else {
            Vec::new()
        };
        let credit = LateCreditReceipt {
            receipt_id: key.clone(),
            attempt_receipt: attempt_receipt.to_owned(),
            outcome_receipt: outcome.receipt.clone(),
            anchor,
            succeeded: outcome.succeeded,
            axis: outcome.axis.clone(),
            at: outcome.at,
            attribution: fields.clone(),
            direct_subjects: direct.keys().copied().collect(),
            shares,
        };
        let mut observations: BTreeMap<EntityId, (bool, f64)> = direct
            .into_iter()
            .map(|(subject, success)| (subject, (success, 1.0)))
            .collect();
        for share in &credit.shares {
            observations
                .entry(share.subject)
                .or_insert((true, share.weight));
        }
        for (subject, (success, weight)) in observations {
            let cell = LearningCell::new(LearningPredicate::Reliability, subject)
                .executor(fields.executor.clone())
                .type_ref(fields.type_ref.clone())
                .axis(outcome.axis.clone());
            let mut learning = LearningEvidence::anchored(
                &credit.receipt_id,
                outcome.at,
                anchor,
                Observation::Success(success),
            );
            learning.weight = weight;
            learning.judge = Some(fields.judge.clone());
            learning.on_judge_model = fields.executor == fields.judge;
            learning.pack_attribution = Some(PackLearningContext {
                attempt_receipt: attempt_receipt.to_owned(),
                outcome_receipt: outcome.receipt.clone(),
                attribution: fields.clone(),
            });
            crate::learning::record_evidence_in_txn(vault, txn, &cell, &learning, now)?;
        }
        // If facts were unavailable, leave this receipt retryable rather than
        // sealing an empty result before attribution has caught up.
        if !credit.direct_subjects.is_empty() || !evidence.is_empty() {
            CREDIT_RECEIPT.put(&vault.store, txn, &key, &credit)?;
        }
        Ok(credit)
    })
}

pub(super) fn require_loaded_skill(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    receipt: &ReceiptRecord,
    skill: EntityId,
) -> Result<()> {
    let record = vault
        .get_skill_record_in_txn(txn, &skill)?
        .ok_or(Error::EntityNotFound)?;
    if !receipt.pack_manifest_skills().is_some_and(|manifest| {
        manifest
            .iter()
            .any(|wire| super::manifest_entry_names_skill(wire, &record))
    }) {
        return Err(Error::InvalidClaimBody(
            "a contributing skill needs its loaded revision",
        ));
    }
    Ok(())
}
