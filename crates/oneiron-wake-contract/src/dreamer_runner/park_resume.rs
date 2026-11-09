//! The Dreamer park resume table (untangle slice 3, the wake lifecycle owner; Engine 09:32 and 14:26, 9 Nov).
//!
//! A parked Dreamer attempt keeps its queue lease until a resumer releases it. Eleven resumers exist, each in its
//! own module: the later wake pass, the trap consume, the outage sweep, the provider recovery, the boot recovery,
//! three turn-program paths, the payer funding, the drafter and the feedback triage. Which park each may resume,
//! by its cause and its park owner, is decided here and nowhere else. Each resumer keeps its other gates (the
//! lease state, the observation cut, the due time, the retry hint, the binding), and the generic resume still
//! checks the owner token.
//!
//! The table encodes the resumers as they were before it existed, including those that check no cause. It is
//! the future park table of the generic run tree (slice 6.5, census B01): that slice extends it, it does not
//! replace it.

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
}

impl ParkResumer {
    /// Every resumer, in table order.
    pub const ALL: [Self; 12] = [
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
    /// | LaterPass | Checkpoint, Paused, Retry | any |
    /// | TrapConsume | any | Trap |
    /// | OutageSweep | ProviderUnavailable | AgentRuns |
    /// | ProviderRecovery | ProviderUnavailable | DreamerServer, AgentRuns |
    /// | BootRecovery | any; Checkpoint; ProviderUnavailable | DreamerServer; any; AgentRuns |
    /// | ProgramRestart | any | TurnProgram |
    /// | ProgramReadyHold, ProgramReturnedHold, ProgramOwnerRelease | Other | TurnProgram |
    /// | PayerFunding | Signal | AgentRuns, Workflows |
    /// | DrafterTrained | any | DrafterRetrain |
    /// | FeedbackTriage | any | FeedbackTriage |
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
                matches!(cause, Cause::Checkpoint | Cause::Paused | Cause::Retry)
            }
            ParkResumer::TrapConsume => matches!(owner, Owner::Trap),
            ParkResumer::OutageSweep => {
                matches!(owner, Owner::AgentRuns) && matches!(cause, Cause::ProviderUnavailable)
            }
            ParkResumer::ProviderRecovery => {
                matches!(owner, Owner::DreamerServer | Owner::AgentRuns)
                    && matches!(cause, Cause::ProviderUnavailable)
            }
            ParkResumer::BootRecovery => {
                matches!(owner, Owner::DreamerServer)
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
        }
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

