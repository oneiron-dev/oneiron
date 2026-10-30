//! Reviewer outcome receipts (OF-568 L9, agent-mind §3.7: "Score the
//! reviewer"; "Health flags never move `learning.reliability`. Only anchored
//! outcomes do"). The reviewer of a T1 card is its deterministic evaluator,
//! `coach.agent_health.<signal>.v1`. Each outcome set on a card appends one
//! receipt that freezes what was judged: the evaluator, the dial and the
//! number, the DIAGNOSTICs, the evidence and the brief pin.
//!
//! An owner's verdict is an anchored outcome of the evaluator's diagnosis:
//! it moves that evaluator's `learning.reliability`, never the reviewed
//! agent's and never the Coach's own record. A leader's, spawner's or
//! recipient's outcome is agreement, not an anchor: its receipt carries no
//! label. Quiet, the TTL, expiry and the absence of a new finding are never
//! outcomes, and nothing here changes a card's tone, routing, recipients or
//! quiet.
//!
//! The learning row is written in a savepoint of the settlement's write: a
//! failed write rolls back alone, is logged and leaves its receipt
//! unprojected, and the settlement stands. The nightly review re-applies
//! every unprojected receipt. In the same savepoint, an owner's verdict is
//! one outcome of the `agent-health-review` skill revision whose policy
//! seeded the card (`policy`, `skill_attribution::health_review`): the
//! record skill optimization reads to revise the reviewer.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::{AgentHealthCard, AgentHealthOutcome, CARDS, HealthBriefPin, card_key, settle};
use crate::learning::{
    Anchor, LearningCell, LearningEvidence, LearningPredicate, Observation, TypeRef,
};
use crate::{EntityId, Result, Vault};

/// The reviewer cell's axis: a card outcome scores the evaluator's diagnosis.
const HEALTH_REVIEW_AXIS: &str = "health_review";
/// A reviewer receipt id's prefix: `health_review:` and 64 hex. The replay
/// judge reads such a receipt through [`Vault::health_review_receipt`].
pub const HEALTH_REVIEW_RECEIPT_PREFIX: &str = "health_review:";
const REVIEW_STATE_DOMAIN: &[u8] = b"oneiron.coach.agent_health.review_state.v1";

/// One outcome set on a card, with what it judged frozen as it stood then.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HealthReviewReceipt {
    /// The review state's id: `health_review:` and 64 hex. A re-settle of the
    /// same state reuses it, so its learning row is replaced, never doubled.
    pub receipt: String,
    /// The outcome set.
    pub outcome: AgentHealthOutcome,
    /// Who set it.
    pub by: EntityId,
    /// A live vault owner set it: only then is it an anchored verdict.
    pub by_owner: bool,
    /// When it was set.
    pub at: u64,
    /// The evaluator it judged, as the card named it.
    pub reviewer: String,
    /// The reviewer skill revision whose policy seeded the card's dials, as
    /// the card named it: the revision the outcome scores. `None` when the
    /// compiled seeds alone decided them.
    pub reviewer_revision: Option<EntityId>,
    /// The dial the number was held against.
    pub dial: i64,
    /// The number the card showed.
    pub measured: i64,
    /// The card's DIAGNOSTICs when it was set, newest last.
    pub diagnostics: Vec<EntityId>,
    /// The card's receipt and attempt ids when it was set, newest last.
    pub evidence: Vec<EntityId>,
    /// The brief the card's newest finding observed.
    pub observed_brief: Option<HealthBriefPin>,
    /// Whether the diagnosis was right: `Some` only for an owner's confirmed
    /// or dismissed.
    pub label: Option<bool>,
    /// Its effect on the evaluator's reliability is applied. A receipt with
    /// no effect starts applied.
    pub projected: bool,
}

/// What one receipt does to its evaluator's reliability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Effect {
    /// An anchored owner verdict: the diagnosis was right (true) or wrong.
    Label(bool),
    /// An owner left the state unresolved or open: its row goes.
    Withdraw,
    /// Agreement by a leader, spawner or recipient: no anchor.
    Unscored,
}

/// The label policy (OF-568 L9). An owner's confirmed says the diagnosis was
/// right; an owner's dismissal, the one-tap "wrong" among them, says it was
/// wrong; an owner's unresolved or open withdraws the state's row. Anyone
/// else's outcome is agreement, which learning never takes.
const fn review_effect(outcome: AgentHealthOutcome, by_owner: bool) -> Effect {
    if !by_owner {
        return Effect::Unscored;
    }
    match outcome {
        AgentHealthOutcome::Confirmed => Effect::Label(true),
        AgentHealthOutcome::Dismissed => Effect::Label(false),
        AgentHealthOutcome::Unresolved | AgentHealthOutcome::Open => Effect::Withdraw,
    }
}

/// The id of what `card` holds for review: its key, its evaluator, its
/// DIAGNOSTICs and evidence in sorted order, and its brief pin's TASK,
/// revision and digest. The pin's observation time is left out: every
/// review restamps it on the same brief.
fn review_state_id(card: &AgentHealthCard) -> String {
    let (subject, signal, task) = card_key(card.subject, card.signal, card.task);
    let mut hasher = blake3::Hasher::new();
    hasher.update(REVIEW_STATE_DOMAIN);
    hasher.update(&subject);
    hasher.update(&signal);
    hasher.update(&task);
    hasher.update(&(card.reviewer.len() as u64).to_le_bytes());
    hasher.update(card.reviewer.as_bytes());
    for ids in [&card.diagnostics, &card.evidence] {
        let mut sorted: Vec<&EntityId> = ids.iter().collect();
        sorted.sort_unstable();
        hasher.update(&(sorted.len() as u64).to_le_bytes());
        for id in sorted {
            hasher.update(id.as_bytes());
        }
    }
    match &card.observed_brief {
        Some(pin) => {
            hasher.update(&[1_u8]);
            hasher.update(pin.task.as_bytes());
            hasher.update(&pin.rev.to_le_bytes());
            hasher.update(pin.digest.as_bytes());
        }
        None => {
            hasher.update(&[0_u8]);
        }
    }
    format!(
        "{HEALTH_REVIEW_RECEIPT_PREFIX}{}",
        hasher.finalize().to_hex()
    )
}

/// Settles `card` and appends the outcome's receipt: the one settlement both
/// outcome doors run, the owner's and a recipient's. An identical retry (the
/// same state, outcome and actor) appends none. An owner's verdict then moves
/// the evaluator's reliability in a savepoint of `txn`, which never fails or
/// rolls back the settlement. The caller writes the card.
pub(super) fn settle_with_review_receipt_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    card: &mut AgentHealthCard,
    by: EntityId,
    by_owner: bool,
    outcome: AgentHealthOutcome,
    at: u64,
) {
    settle(card, by, outcome, at);
    let receipt = review_state_id(card);
    let retry = card
        .review_outcomes
        .iter()
        .rev()
        .find(|held| held.receipt == receipt)
        .is_some_and(|held| held.outcome == outcome && held.by == by);
    if !retry {
        let effect = review_effect(outcome, by_owner);
        card.review_outcomes.push(HealthReviewReceipt {
            receipt: receipt.clone(),
            outcome,
            by,
            by_owner,
            at,
            reviewer: card.reviewer.clone(),
            reviewer_revision: card.reviewer_revision,
            dial: card.dial,
            measured: card.measured,
            diagnostics: card.diagnostics.clone(),
            evidence: card.evidence.clone(),
            observed_brief: card.observed_brief.clone(),
            label: match effect {
                Effect::Label(label) => Some(label),
                Effect::Withdraw | Effect::Unscored => None,
            },
            projected: effect == Effect::Unscored,
        });
    }
    project_state(vault, txn, card, &receipt, at);
}

/// Applies the newest owner receipt of review state `receipt` on `card`
/// while it is unprojected, in a savepoint of `txn`. On any error the
/// savepoint rolls back alone, the receipt stays unprojected for the nightly
/// review, and the card and receipt are logged. Returns whether it applied.
fn project_state(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    card: &mut AgentHealthCard,
    receipt: &str,
    now: u64,
) -> bool {
    let handle = card.card_ref();
    let Some(held) = card
        .review_outcomes
        .iter_mut()
        .rev()
        .find(|held| held.by_owner && held.receipt == receipt)
    else {
        return false;
    };
    if held.projected {
        return false;
    }
    let applied = vault
        .store
        .env
        .nested_write_txn(txn)
        .map_err(crate::Error::from)
        .and_then(|mut savepoint| {
            project_receipt(vault, &mut savepoint, &handle, held, now)?;
            savepoint.commit().map_err(crate::Error::from)
        });
    match applied {
        Ok(()) => {
            held.projected = true;
            true
        }
        Err(error) => {
            tracing::warn!(
                card = %handle,
                receipt = %receipt,
                kind = ?error.kind(),
                "agent-health review receipt not projected"
            );
            false
        }
    }
}

/// One owner receipt's effect on its evaluator's cell and on its reviewer
/// revision's outcome, in `txn`. `card` is its card's handle.
fn project_receipt(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    card: &str,
    held: &HealthReviewReceipt,
    now: u64,
) -> Result<()> {
    let cell = reviewer_cell(&held.reviewer)?;
    match review_effect(held.outcome, held.by_owner) {
        Effect::Label(label) => {
            // The cell's subject must exist: this seeds the Coach's actor on
            // a vault whose Coach has not run yet.
            vault.coach_authority_in_txn(txn)?;
            let evidence = LearningEvidence::anchored(
                held.receipt.clone(),
                held.at,
                Anchor::OwnerVerdict,
                Observation::Success(label),
            );
            crate::learning::record_evidence_in_txn(vault, txn, &cell, &evidence, now)?;
        }
        Effect::Withdraw => {
            crate::learning::evidence::withdraw_evidence_in_txn(
                vault,
                txn,
                &cell,
                &held.receipt,
                now,
            )?;
        }
        Effect::Unscored => {}
    }
    crate::skill_attribution::health_review::project_health_review_outcome_in_txn(
        vault, txn, card, held,
    )
}

/// The evaluator's `learning.reliability` cell, one per evaluator string:
/// the Coach's actor as subject, since a cell's subject is an entity, the
/// evaluator as executor, the `health_review` axis, and the root type for
/// every tree version. It is never the Coach's own record
/// (`coach_reliability_cell`, whose executor is the Coach) and never the
/// reviewed agent's.
fn reviewer_cell(reviewer: &str) -> Result<LearningCell> {
    Ok(LearningCell::new(
        LearningPredicate::Reliability,
        crate::dreamer_runner::authority::coach_actor_id()?,
    )
    .executor(reviewer)
    .type_ref(TypeRef::root(0))
    .axis(HEALTH_REVIEW_AXIS))
}

/// Re-applies every unprojected owner receipt on every card, read whole, the
/// newest of each review state alone, each in its own savepoint: the nightly
/// review runs it first. Returns the receipts it applied. The work is
/// collected under a read transaction first, and the writer opens only when
/// some card holds an unprojected owner receipt (FIX 8083).
///
/// # Errors
///
/// Storage errors reading or writing the cards. A learning write's own
/// failure is logged and left for the next night.
pub(super) fn reproject_pending(vault: &Vault, now: u64) -> Result<u64> {
    let work: Vec<([u8; 16], [u8; 1], [u8; 16])> = {
        let rtxn = vault.store.env.read_txn()?;
        let mut work = Vec::new();
        for (key, card) in CARDS.scan(&vault.store, &rtxn)? {
            if card
                .review_outcomes
                .iter()
                .any(|held| held.by_owner && !held.projected)
            {
                work.push(key);
            }
        }
        work
    };
    if work.is_empty() {
        return Ok(0);
    }
    vault.with_write_txn_grouped(|txn| {
        let mut applied = 0;
        for key in &work {
            let Some(mut card) = CARDS.get(&vault.store, txn, key)? else {
                continue;
            };
            let pending: BTreeSet<String> = card
                .review_outcomes
                .iter()
                .filter(|held| held.by_owner && !held.projected)
                .map(|held| held.receipt.clone())
                .collect();
            let mut changed = false;
            for receipt in &pending {
                if project_state(vault, txn, &mut card, receipt, now) {
                    applied += 1;
                    changed = true;
                }
            }
            if changed {
                CARDS.put(&vault.store, txn, key, &card)?;
            }
        }
        Ok(applied)
    })
}

impl Vault {
    /// The card that holds reviewer receipt `receipt` (`health_review:` and
    /// 64 hex), and its newest copy of that receipt: what the replay judge
    /// replays a reviewer revision on. Every card is read. `None` when no card
    /// holds it, or the id has another prefix.
    ///
    /// # Errors
    ///
    /// Storage errors reading the cards.
    pub fn health_review_receipt(
        &self,
        receipt: &str,
    ) -> Result<Option<(AgentHealthCard, HealthReviewReceipt)>> {
        if !receipt.starts_with(HEALTH_REVIEW_RECEIPT_PREFIX) {
            return Ok(None);
        }
        let rtxn = self.store.env.read_txn()?;
        for (_, card) in CARDS.scan(&self.store, &rtxn)? {
            let held = card
                .review_outcomes
                .iter()
                .rev()
                .find(|held| held.receipt == receipt)
                .cloned();
            if let Some(held) = held {
                return Ok(Some((card, held)));
            }
        }
        Ok(None)
    }
}
