//! The reviewer-outcome bridge (FIX 8075, agent-mind §3.8: "Card outcomes
//! give it a reliability like any skill, and the loop revises it"): each
//! owner-labelled agent-health review receipt becomes one attributed outcome
//! of the `agent-health-review` skill revision whose policy raised its card,
//! in the skill reliability ledger that skill optimization reads.
//! Entry: `project_health_review_outcome_in_txn`.

use crate::dreamer_runner::maintenance::agent_health::{
    AGENT_HEALTH_REVIEW_SKILL_ID, HealthReviewReceipt,
};
use crate::skill_reliability::{
    RuleOutcomeSource, record_rule_outcome_in_txn, withdraw_rule_outcome_in_txn,
};
use crate::{Error, Result, Vault};

/// Projects one review receipt `held` on the card `card` (its handle), as the
/// pack bridge projects an anchored outcome: an owner's confirmed is a
/// success of the revision, an owner's dismissed a failure, and an owner's
/// unresolved or open withdraws it. A leader's, spawner's or recipient's
/// outcome is agreement and writes nothing; so does a receipt whose card no
/// revision seeded, and one whose revision no longer reads as the reviewer
/// skill. The row is keyed by the revision and the receipt id and carries
/// the receipt and its card, so a replay writes the same row.
///
/// # Errors
///
/// A malformed receipt id or card handle; storage errors.
pub(crate) fn project_health_review_outcome_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    card: &str,
    held: &HealthReviewReceipt,
) -> Result<()> {
    let Some(skill) = held.reviewer_revision else {
        return Ok(());
    };
    if !held.by_owner {
        return Ok(());
    }
    let valid = |id: &str| !id.is_empty() && id.len() <= 256 && !id.chars().any(char::is_control);
    if !valid(&held.receipt) || !valid(card) {
        return Err(Error::InvalidClaimBody(
            "a reviewer outcome requires its review receipt and card",
        ));
    }
    match vault.read_skill_record_in_txn(txn, &skill) {
        Ok(record) if record.skill_id == AGENT_HEALTH_REVIEW_SKILL_ID => {}
        Ok(_) | Err(Error::EntityNotFound | Error::InvalidClaimBody(_)) => return Ok(()),
        Err(error) => return Err(error),
    }
    let source = RuleOutcomeSource {
        receipt: held.receipt.clone(),
        card: card.to_owned(),
    };
    match held.label {
        Some(win) => record_rule_outcome_in_txn(vault, txn, &skill, &source, win, held.at),
        None => withdraw_rule_outcome_in_txn(vault, txn, &skill, &source).map(|_| ()),
    }
}
