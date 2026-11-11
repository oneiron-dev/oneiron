//! The Dreamer park resume table (untangle slice 3, the wake lifecycle owner; Engine 09:32 and 14:26, 9 Nov).
//!
//! A parked Dreamer attempt keeps its queue lease until a resumer releases it. Eleven resumers exist, each in its
//! own module: the later wake pass, the trap consume, the outage sweep, the provider recovery, the boot recovery,
//! three turn-program paths, the payer funding, the drafter and the feedback triage. Which park each may resume,
//! by its cause and its park owner, is decided here and nowhere else. Each resumer keeps its other gates (the
//! lease state, the observation cut, the due time, the retry hint, the binding), and the generic resume still
//! checks the owner token.
//!
//! The table encodes the resumers as they were before it existed, including those that check no cause, with the
//! WAKE-D1 rows (lead, 9 Nov): a Cancelled park resumes on a later pass, and an ExecutorError or private Other park
//! waits for the owner's release, never a blind retry (constraint C5), boot included. It is the future park table
//! of the generic run tree (slice 6.5, census B01): that slice extends it, it does not replace it.

use crate::dreamer_runner::types::DreamerParkCause;

/// The park and lease owner of the server's Dreamer pass.
pub const DREAMER_SERVER_PARK_OWNER: &str = "oneiron-server-dreamer";
/// The park and lease owner of the server's agent runs.
pub const AGENT_RUNS_PARK_OWNER: &str = "oneiron-server-agent-runs";
/// The park and lease owner of the server's workflows.
pub const WORKFLOWS_PARK_OWNER: &str = "oneiron-server-workflows";
/// The park owner of the turn-program runtime.
pub const TURN_PROGRAM_PARK_OWNER: &str = "dreamer.turn_program";
/// The prefix of a trap's attempt-scoped park owner; the trap claim id in hex follows it.
pub const TRAP_PARK_OWNER_PREFIX: &str = "dreamer.trap:";
/// The park owner of the drafter's retrain wait.
pub const DRAFTER_RETRAIN_PARK_OWNER: &str = "coach.drafter_retrain";
/// The park owner of the feedback triage's graph wait.
pub const FEEDBACK_TRIAGE_PARK_OWNER: &str = "coach.feedback_triage";

/// Every park cause, in declaration order.
const CAUSES: [DreamerParkCause; 8] = [
    DreamerParkCause::ProviderUnavailable,
    DreamerParkCause::ExecutorError,
    DreamerParkCause::Checkpoint,
    DreamerParkCause::Retry,
    DreamerParkCause::Paused,
    DreamerParkCause::Cancelled,
    DreamerParkCause::Signal,
    DreamerParkCause::Other,
];

/// The class of a park's owner string, as the resume table reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ParkOwnerClass {
    /// [`DREAMER_SERVER_PARK_OWNER`].
    DreamerServer,
    /// [`AGENT_RUNS_PARK_OWNER`].
    AgentRuns,
    /// [`WORKFLOWS_PARK_OWNER`].
    Workflows,
    /// [`TURN_PROGRAM_PARK_OWNER`].
    TurnProgram,
    /// An owner under [`TRAP_PARK_OWNER_PREFIX`]. The trap consume still checks that it is the exact token of the
    /// matching attempt-scoped binding.
    Trap,
    /// [`DRAFTER_RETRAIN_PARK_OWNER`].
    DrafterRetrain,
    /// [`FEEDBACK_TRIAGE_PARK_OWNER`].
    FeedbackTriage,
    /// Every other owner: a caller-chosen pass or worker owner, `coach.host`, a step-wait token.
    Other,
}

impl ParkOwnerClass {
    /// Every class, in table order.
    pub const ALL: [Self; 8] = [
        Self::DreamerServer,
        Self::AgentRuns,
        Self::Workflows,
        Self::TurnProgram,
        Self::Trap,
        Self::DrafterRetrain,
        Self::FeedbackTriage,
        Self::Other,
    ];

    /// The class of `park_owner`.
    #[must_use]
    pub fn of(park_owner: &str) -> Self {
        match park_owner {
            DREAMER_SERVER_PARK_OWNER => Self::DreamerServer,
            AGENT_RUNS_PARK_OWNER => Self::AgentRuns,
            WORKFLOWS_PARK_OWNER => Self::Workflows,
            TURN_PROGRAM_PARK_OWNER => Self::TurnProgram,
            DRAFTER_RETRAIN_PARK_OWNER => Self::DrafterRetrain,
            FEEDBACK_TRIAGE_PARK_OWNER => Self::FeedbackTriage,
            owner if owner.starts_with(TRAP_PARK_OWNER_PREFIX) => Self::Trap,
            _ => Self::Other,
        }
    }
}

/// A resumer of parked Dreamer attempts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ParkResumer {
    /// A later wake pass resumes the park as the same try (DOOR-144).
    LaterPass,
    /// A consumed trap signal resumes its own attempt (ONE-1343).
    TrapConsume,
    /// The timed sweep of the agent runs' outage parks, by their retry hint.
    OutageSweep,
    /// A provider's recovery resumes its outage parks (OF-305).
    ProviderRecovery,
    /// The server's boot heals the parks of dead leases.
    BootRecovery,
    /// The turn-program admission restarts a park under the exact PR1 reason.
    ProgramRestart,
    /// The turn-program admission resumes a program hold whose condition is met.
    ProgramReadyHold,
    /// A program hold whose authority or host has returned.
    ProgramReturnedHold,
    /// The owner's release door resumes a diverged or unfinished program hold (FIX 5880).
    ProgramOwnerRelease,
    /// Funding returned for an agent run or workflow parked on its payer (FIX 805).
    PayerFunding,
    /// The drafter's training finished (FIX 14974).
    DrafterTrained,
    /// The feedback triage's graph completed or was invalidated (FIX 7549).
    FeedbackTriage,
    /// The vault's owner releases a park that waits on an owner act and that no other resumer frees (WAKE-D1).
    OwnerRelease,
}

impl ParkResumer {
    /// Every resumer, in table order.
    pub const ALL: [Self; 13] = [
        Self::LaterPass,
        Self::TrapConsume,
        Self::OutageSweep,
        Self::ProviderRecovery,
        Self::BootRecovery,
        Self::ProgramRestart,
        Self::ProgramReadyHold,
        Self::ProgramReturnedHold,
        Self::ProgramOwnerRelease,
        Self::PayerFunding,
        Self::DrafterTrained,
        Self::FeedbackTriage,
        Self::OwnerRelease,
    ];
}

/// The park resume table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParkResume;

impl ParkResume {
    /// Whether `resumer` may resume a park of `cause` under an owner of class `owner`. The resumer's other gates
    /// still apply.
    ///
    /// | resumer | causes | owners |
    /// |---|---|---|
    /// | LaterPass | Checkpoint, Paused, Retry, Cancelled | any |
    /// | TrapConsume | any | Trap |
    /// | OutageSweep | ProviderUnavailable | AgentRuns |
    /// | ProviderRecovery | ProviderUnavailable | DreamerServer, AgentRuns |
    /// | BootRecovery | any but ExecutorError and Other; Checkpoint; ProviderUnavailable | DreamerServer; any; AgentRuns |
    /// | ProgramRestart | any | TurnProgram |
    /// | ProgramReadyHold, ProgramReturnedHold, ProgramOwnerRelease | Other | TurnProgram |
    /// | PayerFunding | Signal | AgentRuns, Workflows |
    /// | DrafterTrained | any | DrafterRetrain |
    /// | FeedbackTriage | any | FeedbackTriage |
    /// | OwnerRelease | ExecutorError, Other | DreamerServer, AgentRuns, Workflows, Other |
    #[must_use]
    pub const fn admits(
        cause: DreamerParkCause,
        owner: ParkOwnerClass,
        resumer: ParkResumer,
    ) -> bool {
        use DreamerParkCause as Cause;
        use ParkOwnerClass as Owner;
        match resumer {
            ParkResumer::LaterPass => {
                matches!(
                    cause,
                    Cause::Checkpoint | Cause::Paused | Cause::Retry | Cause::Cancelled
                )
            }
            ParkResumer::TrapConsume => matches!(owner, Owner::Trap),
            ParkResumer::OutageSweep => {
                matches!(owner, Owner::AgentRuns) && matches!(cause, Cause::ProviderUnavailable)
            }
            ParkResumer::ProviderRecovery => {
                matches!(owner, Owner::DreamerServer | Owner::AgentRuns)
                    && matches!(cause, Cause::ProviderUnavailable)
            }
            // An ExecutorError or Other park waits for the owner's release: a boot resume would retry into the
            // same refusal, and ask the owner again for a consent (C5).
            ParkResumer::BootRecovery => {
                (matches!(owner, Owner::DreamerServer) && !Self::waits_on_owner(cause))
                    || matches!(cause, Cause::Checkpoint)
                    || (matches!(owner, Owner::AgentRuns)
                        && matches!(cause, Cause::ProviderUnavailable))
            }
            ParkResumer::ProgramRestart => matches!(owner, Owner::TurnProgram),
            ParkResumer::ProgramReadyHold
            | ParkResumer::ProgramReturnedHold
            | ParkResumer::ProgramOwnerRelease => Self::is_program_hold(cause, owner),
            ParkResumer::PayerFunding => {
                matches!(owner, Owner::AgentRuns | Owner::Workflows)
                    && matches!(cause, Cause::Signal)
            }
            ParkResumer::DrafterTrained => matches!(owner, Owner::DrafterRetrain),
            ParkResumer::FeedbackTriage => matches!(owner, Owner::FeedbackTriage),
            ParkResumer::OwnerRelease => {
                Self::waits_on_owner(cause)
                    && matches!(
                        owner,
                        Owner::DreamerServer | Owner::AgentRuns | Owner::Workflows | Owner::Other
                    )
            }
        }
    }

    /// Whether a park of `cause` waits on an owner act: an ExecutorError, or an Other park outside the turn-program
    /// runtime's own holds. Only the owner's release resumes it until slice 6.5's typed waits.
    #[must_use]
    pub const fn waits_on_owner(cause: DreamerParkCause) -> bool {
        matches!(
            cause,
            DreamerParkCause::ExecutorError | DreamerParkCause::Other
        )
    }

    /// Whether a park is a turn-program hold: the program runtime's own park, of cause Other. The three program
    /// hold resumers and the hold index read this one row.
    #[must_use]
    pub const fn is_program_hold(cause: DreamerParkCause, owner: ParkOwnerClass) -> bool {
        matches!(owner, ParkOwnerClass::TurnProgram) && matches!(cause, DreamerParkCause::Other)
    }

    /// Whether `resumer` may resume some park under an owner of class `owner`, for a resumer that skips a foreign
    /// owner before it reads the cause.
    #[must_use]
    pub const fn owner_may_resume(owner: ParkOwnerClass, resumer: ParkResumer) -> bool {
        let mut index = 0;
        while index < CAUSES.len() {
            if Self::admits(CAUSES[index], owner, resumer) {
                return true;
            }
            index += 1;
        }
        false
    }

    /// Whether `resumer` may resume some park of `cause`, for a reader that has the cause and no owner (the later
    /// pass's delay, the outage due index).
    #[must_use]
    pub const fn cause_may_resume(cause: DreamerParkCause, resumer: ParkResumer) -> bool {
        let mut index = 0;
        while index < ParkOwnerClass::ALL.len() {
            if Self::admits(cause, ParkOwnerClass::ALL[index], resumer) {
                return true;
            }
            index += 1;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Generated from WAKE-PARK-CENSUS.md section 4 by census_matrix_rows.py: cause, owner class, then
    // LaterPass, TrapConsume, OutageSweep, ProviderRecovery, BootRecovery, ProgramRestart, ProgramReadyHold,
    // ProgramReturnedHold, ProgramOwnerRelease, PayerFunding, DrafterTrained, FeedbackTriage.
    const CENSUS: [(DreamerParkCause, ParkOwnerClass, [bool; 12]); 64] = [
        (
            DreamerParkCause::ProviderUnavailable,
            ParkOwnerClass::DreamerServer,
            [
                false, false, false, true, true, false, false, false, false, false, false, false,
            ],
        ),
        (
            DreamerParkCause::ProviderUnavailable,
            ParkOwnerClass::AgentRuns,
            [
                false, false, true, true, true, false, false, false, false, false, false, false,
            ],
        ),
        (
            DreamerParkCause::ProviderUnavailable,
            ParkOwnerClass::Workflows,
            [
                false, false, false, false, false, false, false, false, false, false, false, false,
            ],
        ),
        (
            DreamerParkCause::ProviderUnavailable,
            ParkOwnerClass::TurnProgram,
            [
                false, false, false, false, false, true, false, false, false, false, false, false,
            ],
        ),
        (
            DreamerParkCause::ProviderUnavailable,
            ParkOwnerClass::Trap,
            [
                false, true, false, false, false, false, false, false, false, false, false, false,
            ],
        ),
        (
            DreamerParkCause::ProviderUnavailable,
            ParkOwnerClass::DrafterRetrain,
            [
                false, false, false, false, false, false, false, false, false, false, true, false,
            ],
        ),
        (
            DreamerParkCause::ProviderUnavailable,
            ParkOwnerClass::FeedbackTriage,
            [
                false, false, false, false, false, false, false, false, false, false, false, true,
            ],
        ),
        (
            DreamerParkCause::ProviderUnavailable,
            ParkOwnerClass::Other,
            [
                false, false, false, false, false, false, false, false, false, false, false, false,
            ],
        ),
        (
            DreamerParkCause::ExecutorError,
            ParkOwnerClass::DreamerServer,
            [
                false, false, false, false, true, false, false, false, false, false, false, false,
            ],
        ),
        (
            DreamerParkCause::ExecutorError,
            ParkOwnerClass::AgentRuns,
            [
                false, false, false, false, false, false, false, false, false, false, false, false,
            ],
        ),
        (
            DreamerParkCause::ExecutorError,
            ParkOwnerClass::Workflows,
            [
                false, false, false, false, false, false, false, false, false, false, false, false,
            ],
        ),
        (
            DreamerParkCause::ExecutorError,
            ParkOwnerClass::TurnProgram,
            [
                false, false, false, false, false, true, false, false, false, false, false, false,
            ],
        ),
        (
            DreamerParkCause::ExecutorError,
            ParkOwnerClass::Trap,
            [
                false, true, false, false, false, false, false, false, false, false, false, false,
            ],
        ),
        (
            DreamerParkCause::ExecutorError,
            ParkOwnerClass::DrafterRetrain,
            [
                false, false, false, false, false, false, false, false, false, false, true, false,
            ],
        ),
        (
            DreamerParkCause::ExecutorError,
            ParkOwnerClass::FeedbackTriage,
            [
                false, false, false, false, false, false, false, false, false, false, false, true,
            ],
        ),
        (
            DreamerParkCause::ExecutorError,
            ParkOwnerClass::Other,
            [
                false, false, false, false, false, false, false, false, false, false, false, false,
            ],
        ),
        (
            DreamerParkCause::Checkpoint,
            ParkOwnerClass::DreamerServer,
            [
                true, false, false, false, true, false, false, false, false, false, false, false,
            ],
        ),
        (
            DreamerParkCause::Checkpoint,
            ParkOwnerClass::AgentRuns,
            [
                true, false, false, false, true, false, false, false, false, false, false, false,
            ],
        ),
        (
            DreamerParkCause::Checkpoint,
            ParkOwnerClass::Workflows,
            [
                true, false, false, false, true, false, false, false, false, false, false, false,
            ],
        ),
        (
            DreamerParkCause::Checkpoint,
            ParkOwnerClass::TurnProgram,
            [
                true, false, false, false, true, true, false, false, false, false, false, false,
            ],
        ),
        (
            DreamerParkCause::Checkpoint,
            ParkOwnerClass::Trap,
            [
                true, true, false, false, true, false, false, false, false, false, false, false,
            ],
        ),
        (
            DreamerParkCause::Checkpoint,
            ParkOwnerClass::DrafterRetrain,
            [
                true, false, false, false, true, false, false, false, false, false, true, false,
            ],
        ),
        (
            DreamerParkCause::Checkpoint,
            ParkOwnerClass::FeedbackTriage,
            [
                true, false, false, false, true, false, false, false, false, false, false, true,
            ],
        ),
        (
            DreamerParkCause::Checkpoint,
            ParkOwnerClass::Other,
            [
                true, false, false, false, true, false, false, false, false, false, false, false,
            ],
        ),
        (
            DreamerParkCause::Retry,
            ParkOwnerClass::DreamerServer,
            [
                true, false, false, false, true, false, false, false, false, false, false, false,
            ],
        ),
        (
            DreamerParkCause::Retry,
            ParkOwnerClass::AgentRuns,
            [
                true, false, false, false, false, false, false, false, false, false, false, false,
            ],
        ),
        (
            DreamerParkCause::Retry,
            ParkOwnerClass::Workflows,
            [
                true, false, false, false, false, false, false, false, false, false, false, false,
            ],
        ),
        (
            DreamerParkCause::Retry,
            ParkOwnerClass::TurnProgram,
            [
                true, false, false, false, false, true, false, false, false, false, false, false,
            ],
        ),
        (
            DreamerParkCause::Retry,
            ParkOwnerClass::Trap,
            [
                true, true, false, false, false, false, false, false, false, false, false, false,
            ],
        ),
        (
            DreamerParkCause::Retry,
            ParkOwnerClass::DrafterRetrain,
            [
                true, false, false, false, false, false, false, false, false, false, true, false,
            ],
        ),
        (
            DreamerParkCause::Retry,
            ParkOwnerClass::FeedbackTriage,
            [
                true, false, false, false, false, false, false, false, false, false, false, true,
            ],
        ),
        (
            DreamerParkCause::Retry,
            ParkOwnerClass::Other,
            [
                true, false, false, false, false, false, false, false, false, false, false, false,
            ],
        ),
        (
            DreamerParkCause::Paused,
            ParkOwnerClass::DreamerServer,
            [
                true, false, false, false, true, false, false, false, false, false, false, false,
            ],
        ),
        (
            DreamerParkCause::Paused,
            ParkOwnerClass::AgentRuns,
            [
                true, false, false, false, false, false, false, false, false, false, false, false,
            ],
        ),
        (
            DreamerParkCause::Paused,
            ParkOwnerClass::Workflows,
            [
                true, false, false, false, false, false, false, false, false, false, false, false,
            ],
        ),
        (
            DreamerParkCause::Paused,
            ParkOwnerClass::TurnProgram,
            [
                true, false, false, false, false, true, false, false, false, false, false, false,
            ],
        ),
        (
            DreamerParkCause::Paused,
            ParkOwnerClass::Trap,
            [
                true, true, false, false, false, false, false, false, false, false, false, false,
            ],
        ),
        (
            DreamerParkCause::Paused,
            ParkOwnerClass::DrafterRetrain,
            [
                true, false, false, false, false, false, false, false, false, false, true, false,
            ],
        ),
        (
            DreamerParkCause::Paused,
            ParkOwnerClass::FeedbackTriage,
            [
                true, false, false, false, false, false, false, false, false, false, false, true,
            ],
        ),
        (
            DreamerParkCause::Paused,
            ParkOwnerClass::Other,
            [
                true, false, false, false, false, false, false, false, false, false, false, false,
            ],
        ),
        (
            DreamerParkCause::Cancelled,
            ParkOwnerClass::DreamerServer,
            [
                false, false, false, false, true, false, false, false, false, false, false, false,
            ],
        ),
        (
            DreamerParkCause::Cancelled,
            ParkOwnerClass::AgentRuns,
            [
                false, false, false, false, false, false, false, false, false, false, false, false,
            ],
        ),
        (
            DreamerParkCause::Cancelled,
            ParkOwnerClass::Workflows,
            [
                false, false, false, false, false, false, false, false, false, false, false, false,
            ],
        ),
        (
            DreamerParkCause::Cancelled,
            ParkOwnerClass::TurnProgram,
            [
                false, false, false, false, false, true, false, false, false, false, false, false,
            ],
        ),
        (
            DreamerParkCause::Cancelled,
            ParkOwnerClass::Trap,
            [
                false, true, false, false, false, false, false, false, false, false, false, false,
            ],
        ),
        (
            DreamerParkCause::Cancelled,
            ParkOwnerClass::DrafterRetrain,
            [
                false, false, false, false, false, false, false, false, false, false, true, false,
            ],
        ),
        (
            DreamerParkCause::Cancelled,
            ParkOwnerClass::FeedbackTriage,
            [
                false, false, false, false, false, false, false, false, false, false, false, true,
            ],
        ),
        (
            DreamerParkCause::Cancelled,
            ParkOwnerClass::Other,
            [
                false, false, false, false, false, false, false, false, false, false, false, false,
            ],
        ),
        (
            DreamerParkCause::Signal,
            ParkOwnerClass::DreamerServer,
            [
                false, false, false, false, true, false, false, false, false, false, false, false,
            ],
        ),
        (
            DreamerParkCause::Signal,
            ParkOwnerClass::AgentRuns,
            [
                false, false, false, false, false, false, false, false, false, true, false, false,
            ],
        ),
        (
            DreamerParkCause::Signal,
            ParkOwnerClass::Workflows,
            [
                false, false, false, false, false, false, false, false, false, true, false, false,
            ],
        ),
        (
            DreamerParkCause::Signal,
            ParkOwnerClass::TurnProgram,
            [
                false, false, false, false, false, true, false, false, false, false, false, false,
            ],
        ),
        (
            DreamerParkCause::Signal,
            ParkOwnerClass::Trap,
            [
                false, true, false, false, false, false, false, false, false, false, false, false,
            ],
        ),
        (
            DreamerParkCause::Signal,
            ParkOwnerClass::DrafterRetrain,
            [
                false, false, false, false, false, false, false, false, false, false, true, false,
            ],
        ),
        (
            DreamerParkCause::Signal,
            ParkOwnerClass::FeedbackTriage,
            [
                false, false, false, false, false, false, false, false, false, false, false, true,
            ],
        ),
        (
            DreamerParkCause::Signal,
            ParkOwnerClass::Other,
            [
                false, false, false, false, false, false, false, false, false, false, false, false,
            ],
        ),
        (
            DreamerParkCause::Other,
            ParkOwnerClass::DreamerServer,
            [
                false, false, false, false, true, false, false, false, false, false, false, false,
            ],
        ),
        (
            DreamerParkCause::Other,
            ParkOwnerClass::AgentRuns,
            [
                false, false, false, false, false, false, false, false, false, false, false, false,
            ],
        ),
        (
            DreamerParkCause::Other,
            ParkOwnerClass::Workflows,
            [
                false, false, false, false, false, false, false, false, false, false, false, false,
            ],
        ),
        (
            DreamerParkCause::Other,
            ParkOwnerClass::TurnProgram,
            [
                false, false, false, false, false, true, true, true, true, false, false, false,
            ],
        ),
        (
            DreamerParkCause::Other,
            ParkOwnerClass::Trap,
            [
                false, true, false, false, false, false, false, false, false, false, false, false,
            ],
        ),
        (
            DreamerParkCause::Other,
            ParkOwnerClass::DrafterRetrain,
            [
                false, false, false, false, false, false, false, false, false, false, true, false,
            ],
        ),
        (
            DreamerParkCause::Other,
            ParkOwnerClass::FeedbackTriage,
            [
                false, false, false, false, false, false, false, false, false, false, false, true,
            ],
        ),
        (
            DreamerParkCause::Other,
            ParkOwnerClass::Other,
            [
                false, false, false, false, false, false, false, false, false, false, false, false,
            ],
        ),
    ];

    /// The WAKE-D1 rows over the census: a Cancelled park resumes on a later pass, and boot no longer resumes an
    /// ExecutorError or Other park of the Dreamer's own pass.
    fn with_wake_d1(
        cause: DreamerParkCause,
        owner: ParkOwnerClass,
        resumer: ParkResumer,
        census: bool,
    ) -> bool {
        match resumer {
            ParkResumer::LaterPass if cause == DreamerParkCause::Cancelled => true,
            ParkResumer::BootRecovery
                if owner == ParkOwnerClass::DreamerServer
                    && matches!(
                        cause,
                        DreamerParkCause::ExecutorError | DreamerParkCause::Other
                    ) =>
            {
                false
            }
            _ => census,
        }
    }

    #[test]
    fn the_table_is_the_census_matrix_with_the_wake_d1_rows() {
        for (cause, owner, census) in CENSUS {
            for (resumer, admitted) in ParkResumer::ALL[..12].iter().copied().zip(census) {
                assert_eq!(
                    ParkResume::admits(cause, owner, resumer),
                    with_wake_d1(cause, owner, resumer, admitted),
                    "{cause:?} {owner:?} {resumer:?}"
                );
            }
            let release = matches!(
                cause,
                DreamerParkCause::ExecutorError | DreamerParkCause::Other
            ) && matches!(
                owner,
                ParkOwnerClass::DreamerServer
                    | ParkOwnerClass::AgentRuns
                    | ParkOwnerClass::Workflows
                    | ParkOwnerClass::Other
            );
            assert_eq!(
                ParkResume::admits(cause, owner, ParkResumer::OwnerRelease),
                release,
                "{cause:?} {owner:?}"
            );
        }
    }

    #[test]
    fn a_park_waiting_on_the_owner_has_a_resumer() {
        // Every ExecutorError and Other park now has some resumer: its own owner's, or the owner's release.
        for cause in [DreamerParkCause::ExecutorError, DreamerParkCause::Other] {
            for owner in ParkOwnerClass::ALL {
                assert!(
                    ParkResume::owner_may_resume(owner, ParkResumer::OwnerRelease)
                        || ParkResumer::ALL
                            .iter()
                            .any(|resumer| ParkResume::admits(cause, owner, *resumer)),
                    "{cause:?} {owner:?}"
                );
            }
        }
    }

    #[test]
    fn the_cause_list_names_every_cause() {
        // A new cause fails this match: add it to CAUSES and to the table.
        let named = CAUSES.map(|cause| match cause {
            DreamerParkCause::ProviderUnavailable
            | DreamerParkCause::ExecutorError
            | DreamerParkCause::Checkpoint
            | DreamerParkCause::Retry
            | DreamerParkCause::Paused
            | DreamerParkCause::Cancelled
            | DreamerParkCause::Signal
            | DreamerParkCause::Other => cause.as_str(),
        });
        let mut distinct = named.to_vec();
        distinct.sort_unstable();
        distinct.dedup();
        assert_eq!(distinct.len(), CAUSES.len());
    }

    #[test]
    fn owner_classes_read_the_owner_strings() {
        assert_eq!(
            ParkOwnerClass::of(DREAMER_SERVER_PARK_OWNER),
            ParkOwnerClass::DreamerServer
        );
        assert_eq!(
            ParkOwnerClass::of(AGENT_RUNS_PARK_OWNER),
            ParkOwnerClass::AgentRuns
        );
        assert_eq!(
            ParkOwnerClass::of(WORKFLOWS_PARK_OWNER),
            ParkOwnerClass::Workflows
        );
        assert_eq!(
            ParkOwnerClass::of(TURN_PROGRAM_PARK_OWNER),
            ParkOwnerClass::TurnProgram
        );
        assert_eq!(
            ParkOwnerClass::of("dreamer.trap:00ff"),
            ParkOwnerClass::Trap
        );
        assert_eq!(
            ParkOwnerClass::of(DRAFTER_RETRAIN_PARK_OWNER),
            ParkOwnerClass::DrafterRetrain
        );
        assert_eq!(
            ParkOwnerClass::of(FEEDBACK_TRIAGE_PARK_OWNER),
            ParkOwnerClass::FeedbackTriage
        );
        for other in ["coach.host", "dreamer.step_wait:00ff", "worker-7", ""] {
            assert_eq!(ParkOwnerClass::of(other), ParkOwnerClass::Other, "{other}");
        }
    }
}
