//! One check-in: power, mode and rung 0, then the unsure test (ARCH-0082
//! #composing and #ladder).

use super::act_class::{ActClass, ModelCheck};
use super::mode::CheckInMode;
use super::role_preset::{RoleDefault, RolePreset};
use crate::error::Result;

/// Rung 1, the decision-model check of `AskWhenUnsure` (ARCH-0076 Q3). It
/// only chooses between go and ask; it never grants.
pub trait UnsureTest {
    /// `true`: sure, the act goes. `false`: unsure, it asks.
    ///
    /// # Errors
    ///
    /// Any failure, including "no model available". Check-in asks on it.
    fn is_sure(&self) -> Result<bool>;
}

/// One act to check in.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CheckInRequest<'a> {
    pub act: ActClass,
    /// The role the actor holds on this vault link.
    pub role: RolePreset,
    /// Whether the actor's grant names the power for `act` (step 1).
    pub holds_power: bool,
    /// The mode the explicit rows give, already composed from vault down to
    /// thread with any parent narrowing (steps 3 and 4). `None`: no row.
    pub explicit_mode: Option<CheckInMode>,
    /// A standing row, standing grant or past ruling that covers this exact
    /// act (rung 0), by its ref.
    pub standing_row: Option<&'a str>,
}

/// Where a resolved mode came from. A receipt names it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModeSource {
    /// No explicit row: the role's shipped default decided.
    RoleDefault,
    /// The role lacks the power, which a named Grant gives with no row: the
    /// act asks.
    ExtraPowerDefault,
    /// The explicit rows decided.
    ExplicitRows,
    /// A catastrophe row: `AlwaysAsk` for every role but Owner. Only an
    /// explicit Owner row moves it, which the change path builds.
    CatastropheRow,
    /// The fixed F row: nobody answers their own ask.
    FixedRow,
}

/// What a check-in resolves to before any rung runs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolvedMode {
    Mode {
        mode: CheckInMode,
        source: ModeSource,
    },
    /// The actor acts on its own proof. The act's accepted proofs still apply
    /// where it runs (the veto window for vault delete and erase).
    OwnProof,
    /// No power; the actor may open a proposal to a holder.
    Propose,
    /// No power and no proposal path.
    Absent,
}

/// Why an act goes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GoReason {
    /// The mode is `NeverAsk`.
    NeverAsk,
    /// Rung 0: this standing row covers the act.
    StandingRow(String),
    /// Rung 1: the unsure test was sure.
    Sure,
    /// The actor acts on its own proof.
    OwnProof,
}

#[doc(hidden)]
pub use oneiron_records::check_in::resolve::WaitReason;

/// The answer to one check-in.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CheckInAnswer {
    Go(GoReason),
    /// The act waits for a proof from the ladder above rung 1. This answer is
    /// pure; the caller opens the durable pending check-in, which holds the
    /// handle, the rungs and the waits (`open_pending_check_in_in_txn`).
    Wait(WaitReason),
    Propose,
    Absent,
}

/// Steps 1 to 5 of ARCH-0082 #composing: the power, the role's default, the
/// explicit rows, and the catastrophe and fixed rows.
#[must_use]
pub fn resolve_mode(request: &CheckInRequest<'_>) -> ResolvedMode {
    let cell = request.role.default_for(request.act);
    if !request.holds_power {
        // Any actor, in any role, may open an erase proposal.
        return if cell == RoleDefault::Propose || request.act == ActClass::Erase {
            ResolvedMode::Propose
        } else {
            ResolvedMode::Absent
        };
    }
    let (default, source) = match cell {
        RoleDefault::OwnProof
        | RoleDefault::OwnProofWithVetoWindow
        | RoleDefault::NotApplicable => return ResolvedMode::OwnProof,
        RoleDefault::Mode(mode) | RoleDefault::IfNamed(mode) => (mode, ModeSource::RoleDefault),
        RoleDefault::Propose | RoleDefault::NoVerb => {
            (CheckInMode::AlwaysAsk, ModeSource::ExtraPowerDefault)
        }
    };
    let row = request.act.row();
    if row.fixed {
        return ResolvedMode::Mode {
            mode: CheckInMode::AlwaysAsk,
            source: ModeSource::FixedRow,
        };
    }
    if row.catastrophe {
        return ResolvedMode::Mode {
            mode: CheckInMode::AlwaysAsk,
            source: ModeSource::CatastropheRow,
        };
    }
    match request.explicit_mode {
        Some(mode) => ResolvedMode::Mode {
            mode,
            source: ModeSource::ExplicitRows,
        },
        None => ResolvedMode::Mode {
            mode: default,
            source,
        },
    }
}

/// One check-in: [`resolve_mode`], then [`check_in_with_mode`].
#[must_use]
pub fn check_in(request: &CheckInRequest<'_>, unsure: &dyn UnsureTest) -> CheckInAnswer {
    match resolve_mode(request) {
        ResolvedMode::Mode { mode, source } => {
            // No stop-asking row reaches a catastrophe or fixed row.
            let standing = match source {
                ModeSource::CatastropheRow | ModeSource::FixedRow => None,
                _ => request.standing_row,
            };
            check_in_with_mode(request.act, mode, standing, unsure)
        }
        ResolvedMode::OwnProof => CheckInAnswer::Go(GoReason::OwnProof),
        ResolvedMode::Propose => CheckInAnswer::Propose,
        ResolvedMode::Absent => CheckInAnswer::Absent,
    }
}

/// The ladder's first rungs under a mode the caller resolved from its own
/// rows, as fan-out admission does from its manifest rows. `NeverAsk` goes;
/// otherwise rung 0's standing row goes; otherwise `AlwaysAsk` waits and
/// `AskWhenUnsure` asks the unsure test, where the act lets the model decide.
/// The catastrophe rule lives in [`resolve_mode`].
#[must_use]
pub fn check_in_with_mode(
    act: ActClass,
    mode: CheckInMode,
    standing_row: Option<&str>,
    unsure: &dyn UnsureTest,
) -> CheckInAnswer {
    if mode == CheckInMode::NeverAsk {
        return CheckInAnswer::Go(GoReason::NeverAsk);
    }
    if let Some(row_ref) = standing_row {
        return CheckInAnswer::Go(GoReason::StandingRow(row_ref.to_owned()));
    }
    if mode == CheckInMode::AlwaysAsk {
        return CheckInAnswer::Wait(WaitReason::AlwaysAsk);
    }
    match act.row().model_check {
        ModelCheck::UnsureTest | ModelCheck::SampledAudit => match unsure.is_sure() {
            Ok(true) => CheckInAnswer::Go(GoReason::Sure),
            Ok(false) => CheckInAnswer::Wait(WaitReason::Unsure),
            Err(_) => CheckInAnswer::Wait(WaitReason::UnsureTestFailed),
        },
        ModelCheck::AfterOwnerRow | ModelCheck::Never => {
            CheckInAnswer::Wait(WaitReason::ModelNotAllowed)
        }
    }
}
