//! Derived posture, stats views, fold counters, and rebuild ordering key.

use super::scope::RampScope;
use crate::entity_id::EntityId;
use crate::identity_topology::ProposalOutcome;

/// A scope's posture on the ramp.
///
/// DERIVED on every read from the consent registry and the scope's counters,
/// never stored: the standing grant IS the authority, so a second stored copy
/// of "is this graduated" could only ever disagree with it. Marked
/// `#[non_exhaustive]` for ED-05, which adds snooze / manual-pin states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RampState {
    /// Every op still rides the propose lane. Also the inert state of a scope
    /// the ramp does not govern.
    Propose,
    /// The streak crossed the floor: an offer is surfaced, and until the owner
    /// taps it every op still rides the propose lane.
    Offered,
    /// A standing grant is live; ops in this bound run auto.
    Graduated,
}

impl RampState {
    /// The pinned wire string for this state.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Propose => "proposed",
            Self::Offered => "offered",
            Self::Graduated => "auto",
        }
    }

    /// Parses a pinned state string.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "proposed" => Some(Self::Propose),
            "offered" => Some(Self::Offered),
            "auto" => Some(Self::Graduated),
            _ => None,
        }
    }
}

/// One scope's running outcome statistics.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ScopeOutcomeStats {
    /// The scope these counters belong to.
    pub scope: RampScope,
    /// Consecutive approved-untouched rulings. Any amendment, any rejection,
    /// and any demotion zero it: the ramp measures a CLEAN streak.
    pub untouched_streak: u32,
    /// Lifetime amended-approval count.
    pub amended: u32,
    /// Lifetime rejection count.
    pub rejected: u32,
    /// The most recent ruling, if any.
    pub last_outcome: Option<ProposalOutcome>,
    /// When the counters last moved, in the caller's clock.
    pub updated_at: u64,
    /// The derived posture.
    pub state: RampState,
}

/// Why a scope was demoted back to the propose lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DemotionReason {
    /// A ruling in the graduated scope rejected the op.
    Rejected,
    /// A ruling in the graduated scope amended the op before approving.
    Amended,
    /// The agent's own call, absent a triggering ruling.
    AgentJudgment,
}

impl DemotionReason {
    /// The pinned wire/receipt string for this reason.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Rejected => "rejected",
            Self::Amended => "amended",
            Self::AgentJudgment => "agent_judgment",
        }
    }

    /// Parses a pinned reason string.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "rejected" => Some(Self::Rejected),
            "amended" => Some(Self::Amended),
            "agent_judgment" => Some(Self::AgentJudgment),
            _ => None,
        }
    }

    /// The demotion a ruling triggers, or `None` when the ruling was clean.
    pub(super) const fn for_outcome(outcome: ProposalOutcome) -> Option<Self> {
        match outcome {
            ProposalOutcome::ApprovedUntouched => None,
            ProposalOutcome::ApprovedAmended => Some(Self::Amended),
            ProposalOutcome::Rejected => Some(Self::Rejected),
        }
    }
}

/// The counters, decoupled from the tuple that keys them, so folding is one
/// function whichever direction the rows arrive from.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct Counters {
    pub(super) untouched_streak: u32,
    pub(super) amended: u32,
    pub(super) rejected: u32,
    pub(super) last_outcome: Option<ProposalOutcome>,
    pub(super) updated_at: u64,
}

impl Counters {
    /// Folds one ruling. Saturating because a scope ruled `u32::MAX` times has
    /// long since said whatever it had to say; wrapping would silently reset a
    /// streak into a fresh graduation offer.
    pub(super) fn apply_outcome(&mut self, outcome: ProposalOutcome, at: u64) {
        match outcome {
            ProposalOutcome::ApprovedUntouched => {
                self.untouched_streak = self.untouched_streak.saturating_add(1);
            }
            ProposalOutcome::ApprovedAmended => {
                self.amended = self.amended.saturating_add(1);
                self.untouched_streak = 0;
            }
            ProposalOutcome::Rejected => {
                self.rejected = self.rejected.saturating_add(1);
                self.untouched_streak = 0;
            }
        }
        self.last_outcome = Some(outcome);
        self.updated_at = at;
    }

    /// Folds one demotion: the clean streak restarts from zero, because the
    /// evidence that earned the offer has been contradicted.
    pub(super) fn apply_demotion(&mut self, at: u64) {
        self.untouched_streak = 0;
        self.updated_at = at;
    }
}

/// The order a rebuild folds in — by construction the order incremental
/// maintenance wrote in.
///
/// `(watermark, rank, id)`:
/// - `watermark` is the identity-topology causality clock. A ledger ruling
///   carries its own `seq`; a ramp row stamps the clock it read at write time,
///   so it sorts after every ruling that preceded it and before every ruling
///   that followed. Caller-supplied wall time is DATA, never order — the
///   resolve door takes `now` from its caller, so two rulings in one second (or
///   a clock that steps backwards) must still fold in ledger order.
/// - `rank` separates ledger rulings from this module's rows at an equal
///   watermark: a row stamped `seq` was written AFTER ruling `seq`, which is
///   exactly the demotion a ruling triggers inside its own transaction.
/// - `id` breaks the remaining ties in mint order — the resolution event id
///   (matching `fold_identity_topology_log`'s own `(seq, event_id)` order), or
///   the time-ordered ramp row id.
type FoldKey = (u64, u8, EntityId);

pub(super) const FOLD_RANK_LEDGER: u8 = 0;

pub(super) const FOLD_RANK_RAMP_ROW: u8 = 1;

/// One durable act the rebuild refolds: a ruling (`outcome` present) or a
/// demotion (`outcome` absent).
#[derive(Debug, Clone)]
pub(super) struct RampFoldEvent {
    pub(super) key: FoldKey,
    pub(super) scope: RampScope,
    /// The act's wall time — carried as DATA into `updated_at`, never as order.
    pub(super) at: u64,
    pub(super) outcome: Option<ProposalOutcome>,
}
