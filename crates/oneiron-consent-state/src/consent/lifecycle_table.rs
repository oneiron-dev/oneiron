//! The consent lifecycle owner (core split slice 2, ruled 9 Nov): one transition table per consent axis.
//!
//! Four axes stay independent, with no product state: the approve-once marker, the standing grant, the widen
//! proposal and the code wait. Each table is a pure function from the stored state and a typed command to the
//! step the writer takes. Core keeps the storage adapters (the writers that read and put the rows) and the
//! evaluator; every writer asks its table and writes exactly the step the table returns, so a transition is
//! decided here and nowhere else.
//!
//! The tables encode the transitions the writers made before the owner existed, including those outside the
//! plain chains: a standing grant returns to Active when the owner re-affirms it, a decision slot is taken
//! already spent, refiling an identical widen proposal writes nothing, and a code wait can settle with no seal
//! or no answer. The one deliberate change is the repeat revoke (lead 10:31, 9 Nov; Engine 12:32): it succeeds,
//! writes nothing and reports the grant as already revoked, whatever revoked it, where the owner door used to
//! write a second receipt.

use crate::consent::code_wait_state::CodeConsentWaitState;
use crate::consent::grant::ConsentGrantStatus;

/// The consent lifecycle owner: the four tables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsentLifecycle;

// --- Approve-once marker ---------------------------------------------------------------------------------

/// The stored state of an approve-once marker row (absent: no row).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarkerState {
    /// The owner approved; the effect has not run.
    Available,
    /// The effect ran once, or the row is a decision slot (taken already spent).
    Spent,
    /// A state byte this version does not read. Presence still counts: neither an approval nor a slot may
    /// take its key, and a spend refuses it as corrupt.
    Unreadable,
}

/// A marker transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarkerCommand {
    /// The owner approves one exact effect.
    Approve,
    /// The admitted effect spends its approval.
    Spend,
    /// An owner decision takes its slot, already spent: no effect digest names it.
    TakeDecisionSlot,
}

/// Why a marker transition is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarkerRefusal {
    /// An approval for an effect that already carries a marker, in any state.
    AlreadyCarries,
    /// A spend with no marker.
    NoLiveMarker,
    /// A spend of a spent marker: a replay.
    AlreadySpent,
    /// A spend of a marker whose state byte cannot be read.
    Unreadable,
    /// A decision slot that already carries a row.
    SlotTaken,
}

impl ConsentLifecycle {
    /// The marker table.
    ///
    /// | from | Approve | Spend | TakeDecisionSlot |
    /// |---|---|---|---|
    /// | absent | Available | NoLiveMarker | Spent |
    /// | Available | AlreadyCarries | Spent | SlotTaken |
    /// | Spent | AlreadyCarries | AlreadySpent | SlotTaken |
    /// | Unreadable | AlreadyCarries | Unreadable | SlotTaken |
    ///
    /// # Errors
    ///
    /// The refusal of a transition the table does not allow.
    pub const fn marker(
        from: Option<MarkerState>,
        command: MarkerCommand,
    ) -> Result<MarkerState, MarkerRefusal> {
        match (command, from) {
            (MarkerCommand::Approve, None) => Ok(MarkerState::Available),
            (MarkerCommand::Approve, Some(_)) => Err(MarkerRefusal::AlreadyCarries),
            (MarkerCommand::Spend, None) => Err(MarkerRefusal::NoLiveMarker),
            (MarkerCommand::Spend, Some(MarkerState::Available)) => Ok(MarkerState::Spent),
            (MarkerCommand::Spend, Some(MarkerState::Spent)) => Err(MarkerRefusal::AlreadySpent),
            (MarkerCommand::Spend, Some(MarkerState::Unreadable)) => Err(MarkerRefusal::Unreadable),
            (MarkerCommand::TakeDecisionSlot, None) => Ok(MarkerState::Spent),
            (MarkerCommand::TakeDecisionSlot, Some(_)) => Err(MarkerRefusal::SlotTaken),
        }
    }
}

// --- Standing grant --------------------------------------------------------------------------------------

/// A standing-grant transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantCommand {
    /// An owner, derived, outbound or re-affirming mint of an ordinary standing grant.
    Mint,
    /// A bypass grant's mint (its own key space in the same table).
    MintBypass,
    /// The one revoke: the owner door, the in-transaction owner and engine revokes, and the bare revokes of
    /// graduation demotion, erase and pack update.
    Revoke,
}

/// The step a standing-grant writer takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantStep {
    /// Write the row with this status, and the companion writes named here in the same transaction.
    Write {
        /// The row's status after the write.
        status: ConsentGrantStatus,
        /// Retire the grant's owner-reason rules (a new issuance or a revoke ends them).
        retire_reason_rules: bool,
        /// Drop the grant from every open widen proposal's predecessors (a new issuance must not be revoked
        /// by a widening filed over its predecessor, FIX 9740).
        forget_widen_predecessor: bool,
    },
    /// No row: nothing is written. The owner door refuses (not found); the in-transaction revokes report
    /// that nothing was revoked.
    Missing,
    /// The grant is already revoked: nothing is written, and the owner door succeeds with `already_revoked`
    /// whatever revoked the current issuance. Its answer carries that issuance's consent revoke receipt; with
    /// no consent receipt (a graduation demotion, an office-edit erase or an owner-less pack update revoked
    /// it), the record that revoked it as `revoked_by` where that path writes one, else neither. The
    /// in-transaction revokes report that nothing was revoked.
    AlreadyRevoked,
}

impl ConsentLifecycle {
    /// The standing-grant table.
    ///
    /// | from | Mint | MintBypass | Revoke |
    /// |---|---|---|---|
    /// | absent | Active, retire rules, forget predecessor | Active | Missing |
    /// | Active | Active (new issuance), retire rules, forget predecessor | Active | Revoked, retire rules |
    /// | Revoked | Active (owner re-affirmation), retire rules, forget predecessor | Active | AlreadyRevoked |
    ///
    /// Revoked -> Revoke is AlreadyRevoked for every revoker, the ones that write no consent receipt included:
    /// the door succeeds, writes nothing and answers with what the ledgers hold (see [`GrantStep::AlreadyRevoked`]).
    #[must_use]
    pub const fn grant(from: Option<ConsentGrantStatus>, command: GrantCommand) -> GrantStep {
        match (command, from) {
            (GrantCommand::Mint, _) => GrantStep::Write {
                status: ConsentGrantStatus::Active,
                retire_reason_rules: true,
                forget_widen_predecessor: true,
            },
            (GrantCommand::MintBypass, _) => GrantStep::Write {
                status: ConsentGrantStatus::Active,
                retire_reason_rules: false,
                forget_widen_predecessor: false,
            },
            (GrantCommand::Revoke, None) => GrantStep::Missing,
            (GrantCommand::Revoke, Some(ConsentGrantStatus::Active)) => GrantStep::Write {
                status: ConsentGrantStatus::Revoked,
                retire_reason_rules: true,
                forget_widen_predecessor: false,
            },
            (GrantCommand::Revoke, Some(ConsentGrantStatus::Revoked)) => GrantStep::AlreadyRevoked,
        }
    }
}

// --- Widen proposal --------------------------------------------------------------------------------------

/// The stored state of a widen proposal row (absent: no row). Expiry is a guard at answer time, not a state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WidenState {
    /// Filed and open.
    Filed,
    /// Settled: accepted, rejected, or a contact-disclosure offer confirmed once, standing or denied.
    Settled,
}

/// A widen transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WidenCommand {
    /// File a proposal.
    File,
    /// The owner accepts a bound widening.
    Accept,
    /// The owner rejects a bound widening.
    Reject,
    /// The owner confirms a contact-disclosure offer (once, standing or deny).
    SettleOffer,
    /// A standing-grant mint drops its grant from the proposal's predecessors.
    ForgetPredecessor,
}

/// The step a widen writer takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WidenStep {
    /// Write the row in this state.
    Write(WidenState),
    /// Write nothing; the row stays as it is (an identical refiling, or bookkeeping on a row it does not
    /// concern).
    Unchanged,
    /// Refuse: the row is missing.
    Missing,
    /// Refuse: the proposal is already settled.
    Resolved,
}

impl ConsentLifecycle {
    /// The widen table.
    ///
    /// | from | File | Accept, Reject, SettleOffer | ForgetPredecessor |
    /// |---|---|---|---|
    /// | absent | Filed | Missing | Unchanged |
    /// | Filed | Unchanged (identical refiling) | Settled | Filed |
    /// | Settled | Unchanged | Resolved | Unchanged |
    #[must_use]
    pub const fn widen(from: Option<WidenState>, command: WidenCommand) -> WidenStep {
        match (command, from) {
            (WidenCommand::File, None) => WidenStep::Write(WidenState::Filed),
            (WidenCommand::File, Some(_)) => WidenStep::Unchanged,
            (WidenCommand::Accept | WidenCommand::Reject | WidenCommand::SettleOffer, None) => {
                WidenStep::Missing
            }
            (
                WidenCommand::Accept | WidenCommand::Reject | WidenCommand::SettleOffer,
                Some(WidenState::Filed),
            ) => WidenStep::Write(WidenState::Settled),
            (
                WidenCommand::Accept | WidenCommand::Reject | WidenCommand::SettleOffer,
                Some(WidenState::Settled),
            ) => WidenStep::Resolved,
            (WidenCommand::ForgetPredecessor, Some(WidenState::Filed)) => {
                WidenStep::Write(WidenState::Filed)
            }
            (WidenCommand::ForgetPredecessor, None | Some(WidenState::Settled)) => {
                WidenStep::Unchanged
            }
        }
    }
}

// --- Code wait -------------------------------------------------------------------------------------------

/// A code-wait transition: one per writer of the wait's control row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeWaitCommand {
    /// Mint the provisional binding with its held effect.
    Mint,
    /// Attach the owner ask (an orthogonal fact).
    AttachAsk,
    /// Seal with the parked step.
    Seal,
    /// Land the first answer.
    Answer,
    /// Settle: delivered, refused or of unknown delivery. A refusal may settle a wait with no seal or no
    /// answer (an unopened ask, a changed target, lost authority, a generic release or an expiry).
    Settle,
    /// Record the effect's admission (a sub-marker of Settling).
    RecordAdmission,
    /// The parked run takes the settled reply into its replay, once.
    Consume,
    /// Record that a parked run's resume was refused (an orthogonal fact).
    RefuseResume,
    /// Prepare an authority rebind (an orthogonal fact).
    PrepareRebind,
    /// Confirm an authority rebind (an orthogonal fact).
    ConfirmRebind,
}

/// A code-wait write whose state edge the table does not hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodeWaitEdgeRefused {
    /// The command the writer named.
    pub command: CodeWaitCommand,
    /// The state before the write (none: no row).
    pub from: Option<CodeConsentWaitState>,
    /// The state the new row reads as.
    pub to: CodeConsentWaitState,
}

impl ConsentLifecycle {
    /// Whether the code-wait table holds the edge `from -> to` for `command`.
    ///
    /// | command | edges |
    /// |---|---|
    /// | Mint | absent -> Provisional |
    /// | AttachAsk | any state -> itself (an orthogonal fact) |
    /// | Seal | Provisional -> Waiting; any state -> itself (the same seal again) |
    /// | Answer | Waiting -> Settling (a deny or lost authority then settles in a second write, under Settle) |
    /// | Settle | Provisional, Waiting or Settling -> Settled |
    /// | RecordAdmission | Settling -> Settling |
    /// | Consume | Settled -> Consumed |
    /// | RefuseResume | any unconsumed state -> itself |
    /// | PrepareRebind, ConfirmRebind | Settling -> Settling |
    ///
    /// The writers' first-wins checks (an answered, settled or consumed wait writes nothing) stay before the
    /// write; this table judges the write itself.
    ///
    /// # Errors
    ///
    /// [`CodeWaitEdgeRefused`] when the edge is not in the table.
    pub const fn code_wait(
        from: Option<CodeConsentWaitState>,
        command: CodeWaitCommand,
        to: CodeConsentWaitState,
    ) -> Result<(), CodeWaitEdgeRefused> {
        use CodeConsentWaitState::{Consumed, Provisional, Settled, Settling, Waiting};
        let held = match (command, from, to) {
            (CodeWaitCommand::Mint, None, Provisional) => true,
            (CodeWaitCommand::AttachAsk, Some(Provisional), Provisional)
            | (CodeWaitCommand::AttachAsk, Some(Waiting), Waiting)
            | (CodeWaitCommand::AttachAsk, Some(Settling), Settling)
            | (CodeWaitCommand::AttachAsk, Some(Settled), Settled)
            | (CodeWaitCommand::AttachAsk, Some(Consumed), Consumed) => true,
            (CodeWaitCommand::Seal, Some(Provisional), Waiting) => true,
            (CodeWaitCommand::Seal, Some(Provisional), Provisional)
            | (CodeWaitCommand::Seal, Some(Waiting), Waiting)
            | (CodeWaitCommand::Seal, Some(Settling), Settling)
            | (CodeWaitCommand::Seal, Some(Settled), Settled)
            | (CodeWaitCommand::Seal, Some(Consumed), Consumed) => true,
            (CodeWaitCommand::Answer, Some(Waiting), Settling) => true,
            (CodeWaitCommand::Settle, Some(Provisional | Waiting | Settling), Settled) => true,
            (CodeWaitCommand::RecordAdmission, Some(Settling), Settling) => true,
            (CodeWaitCommand::Consume, Some(Settled), Consumed) => true,
            (CodeWaitCommand::RefuseResume, Some(Provisional), Provisional)
            | (CodeWaitCommand::RefuseResume, Some(Waiting), Waiting)
            | (CodeWaitCommand::RefuseResume, Some(Settling), Settling)
            | (CodeWaitCommand::RefuseResume, Some(Settled), Settled) => true,
            (
                CodeWaitCommand::PrepareRebind | CodeWaitCommand::ConfirmRebind,
                Some(Settling),
                Settling,
            ) => true,
            _ => false,
        };
        if held {
            Ok(())
        } else {
            Err(CodeWaitEdgeRefused { command, from, to })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consent::code_wait_state::CodeConsentWaitState as S;
    use crate::consent::grant::ConsentGrantStatus::{Active, Revoked};

    #[test]
    fn a_repeat_revoke_writes_nothing_and_a_mint_always_writes_active() {
        assert_eq!(
            ConsentLifecycle::grant(None, GrantCommand::Revoke),
            GrantStep::Missing
        );
        assert_eq!(
            ConsentLifecycle::grant(Some(Revoked), GrantCommand::Revoke),
            GrantStep::AlreadyRevoked
        );
        assert_eq!(
            ConsentLifecycle::grant(Some(Active), GrantCommand::Revoke),
            GrantStep::Write {
                status: Revoked,
                retire_reason_rules: true,
                forget_widen_predecessor: false
            }
        );
        for from in [None, Some(Active), Some(Revoked)] {
            assert_eq!(
                ConsentLifecycle::grant(from, GrantCommand::Mint),
                GrantStep::Write {
                    status: Active,
                    retire_reason_rules: true,
                    forget_widen_predecessor: true
                }
            );
            assert_eq!(
                ConsentLifecycle::grant(from, GrantCommand::MintBypass),
                GrantStep::Write {
                    status: Active,
                    retire_reason_rules: false,
                    forget_widen_predecessor: false
                }
            );
        }
    }

    #[test]
    fn a_settled_widen_proposal_is_never_settled_again() {
        use WidenCommand::*;
        assert_eq!(
            ConsentLifecycle::widen(None, File),
            WidenStep::Write(WidenState::Filed)
        );
        assert_eq!(
            ConsentLifecycle::widen(Some(WidenState::Filed), File),
            WidenStep::Unchanged
        );
        for command in [Accept, Reject, SettleOffer] {
            assert_eq!(ConsentLifecycle::widen(None, command), WidenStep::Missing);
            assert_eq!(
                ConsentLifecycle::widen(Some(WidenState::Filed), command),
                WidenStep::Write(WidenState::Settled)
            );
            assert_eq!(
                ConsentLifecycle::widen(Some(WidenState::Settled), command),
                WidenStep::Resolved
            );
        }
        assert_eq!(
            ConsentLifecycle::widen(Some(WidenState::Filed), ForgetPredecessor),
            WidenStep::Write(WidenState::Filed)
        );
        assert_eq!(
            ConsentLifecycle::widen(Some(WidenState::Settled), ForgetPredecessor),
            WidenStep::Unchanged
        );
    }
}
