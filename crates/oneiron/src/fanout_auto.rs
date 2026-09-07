//! ES-07: the learned AUTO-mode decider behind ONE-1719's fan-out seam.
//!
//! ONE-1719 landed the fan-out admission primitive with an injected
//! `FanoutAutoDecider` and deliberately no production decider. This module is
//! that decider and nothing else: it turns one `auto`-rung fan-out ask into a
//! closed [`FanoutAskVerdict`] and maps that verdict onto ONE-1719's
//! pause-never-kill disposition.
//!
//! # The order is fixed
//!
//! 1. A blank scope or a blank question is rejected BEFORE any storage read.
//!    [`LearningFanoutAutoDecider::new`] refuses one at the construction door,
//!    and the wrapper repeats the check as a defensive floor for a hand-built
//!    context.
//! 2. ED-06's typed standing-policy read answers next. An ACCEPTED row that
//!    covers the ask short-circuits to its ruling. A proposed row, an amend
//!    posture, a band-less or over-ceiling budget row, and an `Err` all
//!    escalate — a row this engine cannot read is uncertainty, not absence.
//! 3. Only when the typed read returns no row at all does the classifier
//!    enter. An absent classifier escalates, a history-read failure escalates,
//!    and otherwise the injected [`FanoutAskClassifier`] rules once and its
//!    verdict is returned verbatim.
//!
//! # What this module is not
//!
//! It owns no storage. Rows, receipts, aggregation, proposal, and acceptance
//! all belong to ED-06 (`crate::edit_distance::escalation`); everything here
//! is a thin private conversion around that public API.
//!
//! It bundles no model. There is no provider client, no prompt template, no
//! credential, no retry loop, and no engine-side training state:
//! [`FanoutAskClassifier`] is an injected trait implementation and the engine
//! accepts only the closed verdict vocabulary, so a host that cannot decode a
//! token surfaces as a classifier error rather than as a guess.
//!
//! It never resumes, dispatches, or deletes a plan. `Deny` and
//! `EscalateToHuman` both land on ONE-1719's existing approval surface, which
//! stays the only door that releases a frozen plan digest. Applying an
//! amendment would move that digest, so an amend posture escalates instead of
//! releasing the plan in place.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::edit_distance::escalation::{
    EscalationReceipt, EscalationRuling, EscalationStats, EscalationTrigger, StandingPolicy,
    StandingPolicyStatus, escalation_stats, maybe_propose_standing_policy, record_escalation,
    standing_policy_for,
};
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use crate::outbound_chokepoint::{
    FanoutAutoDecider, FanoutAutoDisposition, FanoutEstimate, FanoutPlan,
};
use crate::vault::Vault;

#[cfg(test)]
mod tests;

// ---------------------------------------------------------------------------
// The verdict vocabulary
// ---------------------------------------------------------------------------

/// What an ES-07 ask resolves to.
///
/// Closed at three arms with pinned wire tokens `allow`, `deny`, and
/// `escalate-to-human`. A host may serialize the classifier's inputs however
/// it likes, but the engine decodes only these three: an unknown token is a
/// decode failure in the host adapter, which reaches this module as a
/// classifier error and therefore escalates.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FanoutAskVerdict {
    /// The fan-out may start as asked.
    Allow,
    /// The fan-out should not start. Still surfaced, never a silent kill.
    Deny,
    /// Nobody here is entitled to rule; a human sees it.
    EscalateToHuman,
}

/// Why this fan-out is being asked about, carrying the magnitude a budget ask
/// cannot be judged without.
///
/// A separate shape from ED-06's [`EscalationTrigger`] for one reason: it
/// makes the budget magnitude impossible to omit. It converts to ED's closed
/// trigger before every storage call and mints no second storage schema.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum FanoutAskTrigger {
    /// The classifier was not confident enough to rule.
    Unsure,
    /// The ask fell outside standing policy.
    Policy,
    /// The ask exceeded a budget, by this much.
    Budget {
        /// The ask's own magnitude, compared against a standing row's ceiling.
        magnitude: u64,
    },
}

impl FanoutAskTrigger {
    /// ED-06's closed trigger for this ask.
    const fn escalation_trigger(self) -> EscalationTrigger {
        match self {
            Self::Unsure => EscalationTrigger::Unsure,
            Self::Policy => EscalationTrigger::Policy,
            Self::Budget { .. } => EscalationTrigger::Budget,
        }
    }

    /// The ask's magnitude band; `None` on the two triggers that have no
    /// magnitude, which is also what ED's ledger rejects a band on.
    const fn budget_magnitude(self) -> Option<u64> {
        match self {
            Self::Unsure | Self::Policy => None,
            Self::Budget { magnitude } => Some(magnitude),
        }
    }
}

/// `EntityId` carries no serde impl of its own, so the context spells it as
/// the same lower-hex string every other wire surface in the engine uses.
mod task_ref_hex {
    use serde::{Deserialize, Deserializer, Serializer};

    use crate::entity_id::EntityId;

    pub(super) fn serialize<S: Serializer>(
        id: &EntityId,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&id.to_hex())
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<EntityId, D::Error> {
        let hex = String::deserialize(deserializer)?;
        EntityId::from_hex(&hex).map_err(serde::de::Error::custom)
    }
}

/// The caller-supplied half of one ask: who it is about, where its policy
/// lives, why it fired, and what a human would be asked.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FanoutAskContext {
    /// Parent task whose AUTO decision is being learned; never a per-peer TASK
    /// minted here.
    #[serde(with = "task_ref_hex")]
    pub task_ref: EntityId,
    /// Stable ED policy scope supplied by the caller, because policy residence
    /// is a product decision. This module never synthesizes one out of
    /// `plan_ref`, `brief_ref`, `actor_ref`, or a compound string.
    pub scope: String,
    /// Which reason fired, with a budget ask's magnitude attached.
    pub trigger: FanoutAskTrigger,
    /// What the human would be asked.
    pub question: String,
}

// ---------------------------------------------------------------------------
// The classifier seam
// ---------------------------------------------------------------------------

/// One past human ruling, flattened for a classifier that has no business
/// decoding ED-01's Δ.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FanoutHistoryRuling {
    /// A human approved the ask.
    Approve,
    /// A human denied it.
    Deny,
    /// A human changed it.
    Amend,
}

/// One `(scope, trigger)` pair's ruling history, as the classifier sees it.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct FanoutDecisionHistory {
    /// Approvals recorded for the exact `(scope, trigger)` key.
    pub approve: u32,
    /// Denials recorded for the exact key.
    pub deny: u32,
    /// Amendments recorded for the exact key.
    pub amend: u32,
    /// ED-06's `last_rulings`, bounded by that lane's own
    /// `ESCALATION_LAST_RULINGS_BOUND`: the newest eight, oldest-to-newest.
    pub last_rulings: Vec<FanoutHistoryRuling>,
}

/// The only classifier-facing carrier for ONE-1719's crate-internal plan and
/// estimate.
///
/// Fields stay private and the accessors expose four projections only, so a
/// host never reads — and can never be handed — the plan representation
/// itself.
pub struct FanoutClassifierView<'a> {
    plan: &'a FanoutPlan,
    estimate: &'a FanoutEstimate,
}

impl<'a> FanoutClassifierView<'a> {
    /// Borrows one frozen plan and the estimate ONE-1719 already metered.
    const fn new(plan: &'a FanoutPlan, estimate: &'a FanoutEstimate) -> Self {
        Self { plan, estimate }
    }

    /// Unique canonical destination peers in the plan's edges.
    ///
    /// The estimate's per-peer breakdown is keyed by the peer that RECEIVES,
    /// so this equals `per_peer_counts().len()` — the parent endpoint sending
    /// the consults is never counted as one of them.
    #[must_use]
    pub fn peer_count(&self) -> u64 {
        let peers: BTreeSet<&str> = self
            .plan
            .edges
            .iter()
            .map(|edge| edge.to_peer_ref.as_str())
            .collect();
        peers.len() as u64
    }

    /// The metered total, widened without re-estimating anything.
    #[must_use]
    pub const fn total_count(&self) -> u64 {
        self.estimate.total_count as u64
    }

    /// The metered per-peer breakdown, in the estimate's canonical map order.
    #[must_use]
    pub fn per_peer_counts(&self) -> Vec<(String, u64)> {
        self.estimate
            .per_peer
            .iter()
            .map(|(peer, count)| (peer.clone(), u64::from(*count)))
            .collect()
    }

    /// Lower-hex of the digest ONE-1719 already froze. It reads the existing
    /// bytes and never rehashes, so nothing here can move an approved digest.
    #[must_use]
    pub fn plan_digest(&self) -> String {
        bytes_to_hex_lower(&self.estimate.plan_digest)
    }
}

/// The injected ES-07 classifier.
///
/// Provider-neutral by construction: it sees the ask, the four view
/// projections, and the normalized history, and answers with the closed
/// vocabulary. Where the answer comes from is entirely the host's business.
pub trait FanoutAskClassifier {
    /// Rules on one ask.
    ///
    /// # Errors
    ///
    /// Any failure — no model available, a transport problem, or a token
    /// outside [`FanoutAskVerdict`] that the host adapter could not decode.
    /// Every one of them escalates to a human.
    fn classify(
        &self,
        context: &FanoutAskContext,
        view: &FanoutClassifierView<'_>,
        history: &FanoutDecisionHistory,
    ) -> Result<FanoutAskVerdict>;
}

// ---------------------------------------------------------------------------
// The decision
// ---------------------------------------------------------------------------

/// Rules on one fan-out ask.
///
/// Returns a verdict rather than a `Result` on purpose: every uncertain branch
/// already has a defined, user-visible outcome, and there is no failure here
/// that should reach a caller as an error instead of as a human ask.
///
/// The evaluation order is the module's whole contract:
///
/// | condition | classifier invoked? | result |
/// |---|---:|---|
/// | blank `scope` or blank `question` | no | `EscalateToHuman`, before any storage read |
/// | accepted standing approval covers the ask | no | `Allow` |
/// | accepted standing denial covers the ask | no | `Deny` |
/// | standing budget row with no band ceiling | no | `EscalateToHuman` |
/// | standing budget row whose ceiling is under the ask | no | `EscalateToHuman` |
/// | standing row proposed, or an amend posture | no | `EscalateToHuman` |
/// | typed standing read returns `Err` | no | `EscalateToHuman` |
/// | no standing row, classifier absent | no | `EscalateToHuman` |
/// | no standing row, history read fails | no | `EscalateToHuman` |
/// | no standing row, classifier rules | once | the classifier's verdict |
/// | no standing row, classifier errors | once | `EscalateToHuman` |
pub(crate) fn classify_fan_out_ask(
    vault: &Vault,
    context: &FanoutAskContext,
    plan: &FanoutPlan,
    estimate: &FanoutEstimate,
    inner: Option<&dyn FanoutAskClassifier>,
) -> FanoutAskVerdict {
    // The defensive floor: a hand-built blank context never reaches storage.
    if is_blank(&context.scope) || is_blank(&context.question) {
        return FanoutAskVerdict::EscalateToHuman;
    }

    let trigger = context.trigger.escalation_trigger();
    let Ok(standing) = standing_policy_for(vault, &context.scope, trigger) else {
        // A row that cannot be decoded is uncertainty about an authoritative
        // answer. No fallback scan looks for a second one.
        return FanoutAskVerdict::EscalateToHuman;
    };
    if let Some(row) = standing {
        return standing_verdict(&row, context.trigger.budget_magnitude());
    }

    let Some(classifier) = inner else {
        return FanoutAskVerdict::EscalateToHuman;
    };
    let Ok(stats) = escalation_stats(vault, &context.scope, trigger) else {
        return FanoutAskVerdict::EscalateToHuman;
    };

    let view = FanoutClassifierView::new(plan, estimate);
    classifier
        .classify(context, &view, &decision_history(&stats))
        .unwrap_or(FanoutAskVerdict::EscalateToHuman)
}

/// What an existing standing row is worth to this ask.
///
/// A proposed row suppresses nothing: a proposal exists only after N agreeing
/// human rulings, and holding the ask open until the owner accepts (or the
/// pattern breaks) is the graduation posture rather than a regression.
fn standing_verdict(row: &StandingPolicy, ask_band: Option<u64>) -> FanoutAskVerdict {
    if !matches!(row.status, StandingPolicyStatus::Accepted) {
        return FanoutAskVerdict::EscalateToHuman;
    }
    // ED owns the band comparison. Asking it is how a band-less row and an
    // over-ceiling ask fail closed without this module re-deriving a ceiling.
    if !row.covers_ask(ask_band) {
        return FanoutAskVerdict::EscalateToHuman;
    }
    match &row.ruling {
        EscalationRuling::Approve => FanoutAskVerdict::Allow,
        EscalationRuling::Deny => FanoutAskVerdict::Deny,
        // Applying an amendment would change ONE-1719's frozen plan digest, so
        // an amend posture can neither release nor refuse THIS plan.
        EscalationRuling::Amend(_) => FanoutAskVerdict::EscalateToHuman,
    }
}

/// ED-06's folded history, flattened for the classifier.
fn decision_history(stats: &EscalationStats) -> FanoutDecisionHistory {
    FanoutDecisionHistory {
        approve: stats.approve,
        deny: stats.deny,
        amend: stats.amend,
        last_rulings: stats.last_rulings.iter().map(history_ruling).collect(),
    }
}

fn history_ruling(ruling: &EscalationRuling) -> FanoutHistoryRuling {
    match ruling {
        EscalationRuling::Approve => FanoutHistoryRuling::Approve,
        EscalationRuling::Deny => FanoutHistoryRuling::Deny,
        EscalationRuling::Amend(_) => FanoutHistoryRuling::Amend,
    }
}

/// The ONE mapping into ONE-1719's closed disposition.
///
/// Exhaustive by construction, with no catch-all arm: a fourth verdict would
/// be a compile error here rather than a silent `SurfaceHuman`. There is
/// deliberately no `FanoutAutoDisposition::Deny` to map onto — the primitive
/// can proceed or surface, and a denial stays visible and recoverable on the
/// same approval row an escalation lands on.
const fn disposition_of(verdict: FanoutAskVerdict) -> FanoutAutoDisposition {
    match verdict {
        FanoutAskVerdict::Allow => FanoutAutoDisposition::Allow,
        FanoutAskVerdict::Deny | FanoutAskVerdict::EscalateToHuman => {
            FanoutAutoDisposition::SurfaceHuman
        }
    }
}

fn is_blank(value: &str) -> bool {
    value.trim().is_empty()
}

// ---------------------------------------------------------------------------
// The ONE-1719 adapter
// ---------------------------------------------------------------------------

/// The production `auto`-rung decider ONE-1719 asks.
pub struct LearningFanoutAutoDecider<'a> {
    vault: &'a Vault,
    context: FanoutAskContext,
    classifier: Option<&'a dyn FanoutAskClassifier>,
}

impl<'a> LearningFanoutAutoDecider<'a> {
    /// Binds one ask context and an optional classifier to a vault.
    ///
    /// The classifier is optional because an accepted standing row answers
    /// without one; absence is resolved only after the storage read finds no
    /// standing row.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] for a blank scope or a blank question. Both
    /// are rejected at this door so an unusable ask cannot reach storage.
    pub fn new(
        vault: &'a Vault,
        context: FanoutAskContext,
        classifier: Option<&'a dyn FanoutAskClassifier>,
    ) -> Result<Self> {
        if is_blank(&context.scope) {
            return Err(Error::InvalidConfig(
                "a fan-out ask needs a non-blank policy scope".to_owned(),
            ));
        }
        if is_blank(&context.question) {
            return Err(Error::InvalidConfig(
                "a fan-out ask needs a non-blank question".to_owned(),
            ));
        }
        Ok(Self {
            vault,
            context,
            classifier,
        })
    }
}

impl FanoutAutoDecider for LearningFanoutAutoDecider<'_> {
    fn decide(
        &self,
        plan: &FanoutPlan,
        estimate: &FanoutEstimate,
    ) -> Result<FanoutAutoDisposition> {
        // Delegated unconditionally: an accepted standing row has to survive a
        // missing classifier, so classifier absence cannot be decided here.
        Ok(disposition_of(classify_fan_out_ask(
            self.vault,
            &self.context,
            plan,
            estimate,
            self.classifier,
        )))
    }
}

// ---------------------------------------------------------------------------
// Recording a human ruling
// ---------------------------------------------------------------------------

/// What a human may rule on a surfaced fan-out ask.
///
/// Approve or deny only. Changing a plan is a NEW plan and a new digest
/// through ONE-1719, never a hidden in-place amendment of a frozen one.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FanoutEscalationRuling {
    /// Rule the ask runnable.
    Approve,
    /// Rule against it. The plan stays paused and visible.
    Deny,
}

impl FanoutEscalationRuling {
    fn escalation_ruling(self) -> EscalationRuling {
        match self {
            Self::Approve => EscalationRuling::Approve,
            Self::Deny => EscalationRuling::Deny,
        }
    }
}

/// What ED-06's proposal projector said after the ruling committed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FanoutProposalOutcome {
    /// The pattern has not formed yet. Not a failure.
    NotProposed,
    /// ED proposed a standing row. Acceptance is a separate owner action
    /// through ED's own `accept_standing_policy`; nothing here auto-accepts.
    Proposed(EntityId),
    /// The projector failed AFTER the receipt committed, rendered as text. No
    /// new error variant is minted for it: the caller still holds the receipt.
    Failed(String),
}

/// One applied human ruling.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppliedFanoutEscalationRuling {
    /// The committed escalation receipt. Present on every `Ok`, including one
    /// carrying [`FanoutProposalOutcome::Failed`].
    pub receipt_ref: EntityId,
    /// Proposed only; never accepted here.
    pub proposal: FanoutProposalOutcome,
}

/// Records one human ruling on an escalated fan-out ask.
///
/// This is learning, not operation. It writes ONE receipt through ED-06's
/// existing ledger and then asks ED whether the updated history earns a
/// PROPOSED standing row. It mints no receipt kind and no policy schema, and
/// it never resumes, dispatches, or deletes a plan: applying the ruling to the
/// paused plan is the caller's second step through ONE-1719's approval surface
/// (`Approve` -> approve-and-resume the frozen digest, `Deny` -> keep-paused
/// at zero dispatch).
///
/// Once the receipt commits the answer is always `Ok`. A projector failure is
/// reported as [`FanoutProposalOutcome::Failed`] rather than swallowing the
/// committed receipt, so the caller can always name the partial state. Nothing
/// is retried, duplicated, or made exactly-once here.
///
/// # Errors
///
/// [`Error::InvalidConfig`] for a blank scope, question, or rationale, plus
/// whatever ED's ledger write returns. Those are the only `Err` paths, and all
/// of them mean nothing persisted.
pub fn apply_escalation_ruling(
    vault: &Vault,
    context: &FanoutAskContext,
    ruling: FanoutEscalationRuling,
    rationale: String,
) -> Result<AppliedFanoutEscalationRuling> {
    if is_blank(&context.scope) || is_blank(&context.question) {
        return Err(Error::InvalidConfig(
            "a fan-out ruling needs the ask's non-blank scope and question".to_owned(),
        ));
    }
    if is_blank(&rationale) {
        return Err(Error::InvalidConfig(
            "a fan-out ruling needs a non-blank rationale".to_owned(),
        ));
    }

    let trigger = context.trigger.escalation_trigger();
    let receipt_ref = record_escalation(
        vault,
        EscalationReceipt {
            task_ref: context.task_ref,
            scope: context.scope.clone(),
            trigger,
            question: context.question.clone(),
            ruling: ruling.escalation_ruling(),
            rationale,
            budget_band: context.trigger.budget_magnitude(),
        },
    )?;

    // Past this point the ruling is durable, so no branch may return `Err`.
    let proposal = match maybe_propose_standing_policy(vault, &context.scope, trigger) {
        Ok(None) => FanoutProposalOutcome::NotProposed,
        Ok(Some(row_ref)) => FanoutProposalOutcome::Proposed(row_ref),
        Err(error) => FanoutProposalOutcome::Failed(error.to_string()),
    };

    Ok(AppliedFanoutEscalationRuling {
        receipt_ref,
        proposal,
    })
}
