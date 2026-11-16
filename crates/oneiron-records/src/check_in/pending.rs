//! Moved from `crates/oneiron/src/check_in/pending.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::check_in::act_class::ActClass;
use crate::check_in::mode::CheckInMode;
use crate::check_in::policy::CheckInScope;
use crate::check_in::policy::ClassWait;
use crate::check_in::resolve::WaitReason;
use oneiron_contracts::entity_id::EntityId;
pub use oneiron_verb_wire::check_in::pending::HolderKind;
use serde::Deserialize;
use serde::Serialize;

/// The BLAKE3 natural key of an ask: the asker, the verb, the act class,
/// where the effect sits and the effect's digest (P23-SHAPE Q2 = A). Two
/// opens with one key are the same saved call.
pub fn open_key_of(
    asker: EntityId,
    verb: &str,
    act: ActClass,
    scope: &CheckInScope,
    effect_digest: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("oneiron.check_in.open_key.v1");
    hasher.update(asker.as_bytes());
    for part in [
        Some(verb),
        Some(act.as_str()),
        scope.world_ref.as_deref(),
        scope.project_ref.as_deref(),
    ] {
        match part {
            Some(text) => {
                hasher.update(&[1]);
                hasher.update(&(text.len() as u64).to_be_bytes());
                hasher.update(text.as_bytes());
            }
            None => {
                hasher.update(&[0]);
            }
        }
    }
    hasher.update(effect_digest);
    *hasher.finalize().as_bytes()
}

/// A rung of the ladder above rung 1 (ARCH-0082 #ladder).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Rung {
    /// Rung 2: the parent of a spawned child, the person behind a companion,
    /// the binder of a house agent.
    Grantor,
    /// Rung 3: the next holders up the grant chain, all holders of a role at
    /// once.
    ChainHolders,
    /// Rung 4: the Owner role, where the chain ends.
    Owner,
}

impl Rung {
    /// The rung's number on canon's ladder.
    #[must_use]
    pub const fn number(self) -> u8 {
        match self {
            Self::Grantor => 2,
            Self::ChainHolders => 3,
            Self::Owner => 4,
        }
    }

    /// The rung above this one; `None` above the Owner.
    #[must_use]
    pub const fn next(self) -> Option<Self> {
        match self {
            Self::Grantor => Some(Self::ChainHolders),
            Self::ChainHolders => Some(Self::Owner),
            Self::Owner => None,
        }
    }

    /// The receipt token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Grantor => "grantor",
            Self::ChainHolders => "chain_holders",
            Self::Owner => "owner",
        }
    }
}

/// One holder a rung asks, pinned when the ask enters the rung.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RungHolder {
    pub principal: EntityId,
    pub kind: HolderKind,
}

/// The wait a person rung captured when the ask entered it (P22-SHAPE Q5).
/// A policy change applies only to rungs entered after it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CapturedWait {
    /// The act class's effective wait per person rung, and its source.
    pub floor: ClassWait,
    /// The wait this rung runs: the floor, or the asker's longer wait.
    pub secs: u64,
    pub due_at: u64,
}

/// A holder's "give me until <time>" on one rung, receipted. `by` is `None`
/// once the holder's erase scrubbed it; the extension stands.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Extension {
    pub until: u64,
    pub by: Option<EntityId>,
    pub at: u64,
}

/// One rung the ask entered.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RungEntry {
    pub rung: Rung,
    pub entered_at: u64,
    /// The holders pinned on entry; empty on a skipped rung.
    pub holders: Vec<RungHolder>,
    /// The missing link of a skipped rung.
    pub skipped: Option<String>,
    /// The person wait; `None` on a rung with no person holder.
    pub wait: Option<CapturedWait>,
    /// The latest extension a holder gave on this rung.
    pub extension: Option<Extension>,
}

impl RungEntry {
    /// When the rung's wait ends: the extension, else the captured wait. A
    /// rung with no person holder is due when it is entered.
    #[must_use]
    pub fn due_at(&self) -> u64 {
        match (&self.extension, &self.wait) {
            (Some(extension), _) => extension.until,
            (None, Some(wait)) => wait.due_at,
            (None, None) => self.entered_at,
        }
    }
}

/// An objection to a delay window, admitted by canon's PR 4 producer. `by`
/// is `None` once the objector's erase scrubbed it; the objection stands.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Objection {
    pub by: Option<EntityId>,
    pub at: u64,
}

/// A delay window the act's proof is (ARCH-0082 #no-answer): silence at its
/// end is the proof, and an objection holds it. Its notice and objections
/// come from canon's PR 4 producer; this row keeps them.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DelayWindow {
    pub notice_at: u64,
    pub ends_at: u64,
    pub objections: Vec<Objection>,
}

/// A holder's answer.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HolderAnswer {
    Approve,
    Deny,
}

impl HolderAnswer {
    /// The receipt token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Deny => "deny",
        }
    }
}

/// Where a pending check-in stands. Every state but `Open` is final, and
/// each is receipted (canon's table "When nobody answers").
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PendingState {
    /// On a rung, or past the last rung while its delay window runs.
    Open,
    /// The first valid answer landed; every other holder reads who gave it
    /// (`None` once that holder's erase scrubbed it).
    Answered {
        answer: HolderAnswer,
        by: Option<EntityId>,
        rung: Rung,
        at: u64,
    },
    /// The asker's `until` passed: the ask let go, and nothing happens.
    LetGo { at: u64 },
    /// The chain is exhausted and the act may not proceed on silence: it
    /// holds, and the agent goes on with other work.
    Held { at: u64 },
    /// The chain is exhausted, the act is undoable and its mode is
    /// `AskWhenUnsure`: it may proceed with this undo plan (ARCH-0076, a
    /// reversible step takes the answer). Running it is 2e.
    ProceedWithUndo { at: u64, undo_plan: String },
    /// The delay window ended in silence: that is the proof.
    WindowPassed { at: u64 },
    /// The delay window ended with an objection standing: it holds.
    ObjectionHeld { at: u64 },
}

/// Why a settled check-in's act may run (Engine ruling P23-SHAPE Q3 = A).
/// Three final states make it eligible, each on its own basis; every other
/// state makes nothing eligible, so silence is never a yes outside canon's
/// two no-answer rows (ARCH-0082 "When nobody answers").
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EligibleBasis {
    /// A holder approved the exact effect.
    Approved,
    /// The chain ended in silence on an undoable act asked when unsure: it
    /// runs with the undo plan the asker gave.
    ProceedWithUndo,
    /// The delay window ended in silence: that is the proof.
    WindowPassed,
}

impl EligibleBasis {
    /// The receipt token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Approved => "approved",
            Self::ProceedWithUndo => "proceed_with_undo",
            Self::WindowPassed => "window_passed",
        }
    }
}

/// A pending check-in.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PendingCheckIn {
    pub id: EntityId,
    pub asker: EntityId,
    /// The asker's grant on this vault link, by its ref.
    pub grant_ref: String,
    /// The exact verb that waits.
    pub verb: String,
    pub act: ActClass,
    pub scope: CheckInScope,
    /// The digest of the exact effect; an answer over any other settles
    /// nothing.
    pub effect_digest: [u8; 32],
    /// The mode the check-in resolved to.
    pub mode: CheckInMode,
    pub reason: WaitReason,
    pub opened_at: u64,
    /// The asker's longer wait per person rung, beside `until`.
    pub asker_wait_secs: Option<u64>,
    /// The asker's cutoff: at it the ask lets go.
    pub until: Option<u64>,
    /// The domain undo the caller gave at open; without one an exhausted
    /// chain holds.
    pub undo_plan: Option<String>,
    pub delay_window: Option<DelayWindow>,
    /// Every rung the ask entered, in order; the last is the current one.
    pub rungs: Vec<RungEntry>,
    /// When the ask passed the last rung while its delay window still ran.
    pub chain_exhausted_at: Option<u64>,
    pub state: PendingState,
    /// The receipts written so far; the next receipt's sequence.
    pub transitions: u32,
    /// When the act this row held ran, on its eligible basis: it runs once.
    #[serde(default)]
    pub consumed_at: Option<u64>,
    /// The logical call that opened the row through `vault.check_in.open`,
    /// when its host bound one (2f; P23-SHAPE Q2 = A). The act's own gate
    /// that resends under it is PR 3's.
    #[serde(default)]
    pub invocation: Option<[u8; 16]>,
}

impl PendingCheckIn {
    /// The rung the ask is on.
    #[must_use]
    pub fn current_rung(&self) -> Option<&RungEntry> {
        self.rungs.last()
    }

    /// The basis on which the act this row holds may run, or `None`: an
    /// allow-list over the states (P23-SHAPE Q3 = A). A denial, a let-go, a
    /// hold, a standing objection or an open ask makes nothing eligible. It
    /// says nothing of whether the act already ran (`consumed_at`).
    #[must_use]
    pub fn eligible_basis(&self) -> Option<EligibleBasis> {
        match &self.state {
            PendingState::Answered {
                answer: HolderAnswer::Approve,
                ..
            } => Some(EligibleBasis::Approved),
            PendingState::ProceedWithUndo { .. } => Some(EligibleBasis::ProceedWithUndo),
            PendingState::WindowPassed { .. } => Some(EligibleBasis::WindowPassed),
            PendingState::Open
            | PendingState::Answered {
                answer: HolderAnswer::Deny,
                ..
            }
            | PendingState::LetGo { .. }
            | PendingState::Held { .. }
            | PendingState::ObjectionHeld { .. } => None,
        }
    }

    /// The row's natural key: its asker, verb, act class, scope and effect
    /// digest.
    #[must_use]
    pub fn open_key(&self) -> [u8; 32] {
        open_key_of(
            self.asker,
            &self.verb,
            self.act,
            &self.scope,
            &self.effect_digest,
        )
    }

    /// Whether a repeat open of the same saved call returns this row: while
    /// it is open, and once settled until its act ran. A let-go ask (the
    /// asker stopped waiting) and a spent one are asked afresh; a denial, a
    /// hold or a standing objection stays the answer, so a repeat never asks
    /// the ladder again.
    #[must_use]
    pub fn answers_a_repeat(&self) -> bool {
        !matches!(self.state, PendingState::LetGo { .. }) && self.consumed_at.is_none()
    }

    /// The next instant a transition is due, for the host that wakes it:
    /// the earliest of `until`, the window's end and the current rung's
    /// end. `None` once the state is final.
    #[must_use]
    pub fn next_due_at(&self) -> Option<u64> {
        if self.state != PendingState::Open {
            return None;
        }
        let rung = if self.chain_exhausted_at.is_some() {
            None
        } else {
            self.current_rung().map(RungEntry::due_at)
        };
        [
            self.until,
            self.delay_window.as_ref().map(|window| window.ends_at),
            rung,
        ]
        .into_iter()
        .flatten()
        .min()
    }
}
