//! Public domain types: triggers, rulings, policy rows, stats.

use crate::edit_distance::delta::AmendmentDelta;
use crate::entity_id::EntityId;

// ---------------------------------------------------------------------------
// Triggers, rulings, status
// ---------------------------------------------------------------------------

/// Why the engine stopped and asked.
///
/// Closed by canon at three arms, and deliberately without an "other": a fourth
/// reason to escalate is a canon change, and an escape hatch here would let one
/// land as data. The pattern key is `(scope, trigger)` precisely because these
/// three are not interchangeable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum EscalationTrigger {
    /// The classifier was not confident enough to rule.
    Unsure,
    /// The ask fell outside standing policy.
    Policy,
    /// The ask exceeded a budget. The only trigger with a magnitude, and
    /// therefore the only one whose standing policy carries a band ceiling.
    Budget,
}

impl EscalationTrigger {
    /// Every arm — the closed enum made iterable, so a fourth trigger cannot be
    /// added without every site here seeing it.
    pub const ALL: [Self; 3] = [Self::Unsure, Self::Policy, Self::Budget];

    /// The pinned on-disk token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unsure => "unsure",
            Self::Policy => "policy",
            Self::Budget => "budget",
        }
    }

    /// Inverse of [`Self::as_str`]; `None` for a token this engine never wrote.
    #[must_use]
    pub fn from_token(token: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|arm| arm.as_str() == token)
    }

    /// The pinned key byte. Never zero, so a truncated or zero-filled key can
    /// never decode as a valid trigger.
    pub(super) const fn key_byte(self) -> u8 {
        match self {
            Self::Unsure => 1,
            Self::Policy => 2,
            Self::Budget => 3,
        }
    }
}

/// What the human ruled.
///
/// [`Self::Amend`] carries ED-01's Δ rather than a second amendment encoding:
/// one delta language lane-wide, so an escalation amendment and an inbox
/// approve-with-edit are the same artifact to every downstream reader.
#[derive(Debug, Clone, PartialEq)]
pub enum EscalationRuling {
    /// Run it as asked.
    Approve,
    /// Do not run it.
    Deny,
    /// Run it changed, by this much.
    Amend(AmendmentDelta),
}

impl EscalationRuling {
    /// The pinned on-disk token.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Deny => "deny",
            Self::Amend(_) => "amend",
        }
    }

    /// The Δ an amendment carries; `None` for the other two arms.
    #[must_use]
    pub const fn delta(&self) -> Option<&AmendmentDelta> {
        match self {
            Self::Amend(delta) => Some(delta),
            Self::Approve | Self::Deny => None,
        }
    }
}

/// Whether a standing policy is merely offered or actually in force.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StandingPolicyStatus {
    /// Earned and surfaced; suppresses nothing until the owner taps it.
    Proposed,
    /// The owner accepted it. Only these short-circuit an ask.
    Accepted,
}

impl StandingPolicyStatus {
    /// The pinned receipt/wire token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Accepted => "accepted",
        }
    }
}

// ---------------------------------------------------------------------------
// The public records
// ---------------------------------------------------------------------------

/// One ruled escalation, as [`record_escalation`] takes it.
#[derive(Debug, Clone, PartialEq)]
pub struct EscalationReceipt {
    /// The task the ask was about.
    pub task_ref: EntityId,
    /// The scope the ask fell in, stamped at record time. Free-form, trimmed,
    /// and the axis every aggregation and standing policy is keyed on.
    pub scope: String,
    /// Which of the three reasons fired.
    pub trigger: EscalationTrigger,
    /// What the engine asked.
    pub question: String,
    /// What the human ruled.
    pub ruling: EscalationRuling,
    /// Why they ruled it.
    pub rationale: String,
    /// The ask's magnitude band. `Some` only on an [`EscalationTrigger::Budget`]
    /// ask; a band on any other trigger is rejected at the door, because an
    /// aggregation that silently ignored it would let a meaningless number look
    /// like evidence.
    pub budget_band: Option<u64>,
}

/// A standing answer for one `(scope, trigger)` pair.
#[derive(Debug, Clone, PartialEq)]
pub struct StandingPolicy {
    /// The row's own handle — what [`accept_standing_policy`] takes.
    pub row_ref: EntityId,
    /// The scope it governs.
    pub scope: String,
    /// The trigger it governs.
    pub trigger: EscalationTrigger,
    /// Proposed, or accepted by the owner.
    pub status: StandingPolicyStatus,
    /// The ruling every citing escalation agreed on.
    pub ruling: EscalationRuling,
    /// For an [`EscalationTrigger::Budget`] row, the largest band EVERY citing
    /// ruling covered; `None` when the row is band-less, which never covers a
    /// banded ask. Always `None` on the other triggers, which have no
    /// magnitude.
    pub budget_band_ceiling: Option<u64>,
    /// Receipt ids of the rulings that earned this row. A standing policy that
    /// could not say what it was learned from would be an assertion.
    pub cited_receipts: Vec<String>,
}

impl StandingPolicy {
    /// Whether this row answers an ask of `ask_band` without escalating.
    ///
    /// A [`StandingPolicyStatus::Proposed`] row covers nothing: it has been
    /// offered, not accepted. On `unsure` / `policy` the `(scope, trigger)` key
    /// stands and the band is not consulted. On `budget` both band-less sides
    /// fail closed — a row with no ceiling covers no banded ask, and an
    /// unmeasured ask clears no ceiling.
    #[must_use]
    pub const fn covers_ask(&self, ask_band: Option<u64>) -> bool {
        if !matches!(self.status, StandingPolicyStatus::Accepted) {
            return false;
        }
        match self.trigger {
            EscalationTrigger::Unsure | EscalationTrigger::Policy => true,
            EscalationTrigger::Budget => match (self.budget_band_ceiling, ask_band) {
                (Some(ceiling), Some(band)) => band <= ceiling,
                _ => false,
            },
        }
    }
}

/// One `(scope, trigger)` pair's ruling history.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct EscalationStats {
    /// Approvals recorded.
    pub approve: u32,
    /// Denials recorded.
    pub deny: u32,
    /// Amendments recorded.
    pub amend: u32,
    /// Newest [`ESCALATION_LAST_RULINGS_BOUND`] retained, returned
    /// oldest-to-newest.
    pub last_rulings: Vec<EscalationRuling>,
}
