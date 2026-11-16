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
        // Like a top-up, a seat-available write and a pass start admit nothing untyped: only
        // admits_wait admits them, for the typed wait that names their seat or units.
        assert!(
            !ParkResume::admits(cause, owner, ParkResumer::SeatAvailable),
            "{cause:?} {owner:?}"
        );
        assert!(
            !ParkResume::admits(cause, owner, ParkResumer::PassStart),
            "{cause:?} {owner:?}"
        );
        assert!(
            !ParkResume::admits(cause, owner, ParkResumer::ResidentShareRaise),
            "{cause:?} {owner:?}"
        );
        // An owner policy write requeues an ExecutorError park the owner's release serves, and no other.
        assert_eq!(
            ParkResume::admits(cause, owner, ParkResumer::PolicyChange),
            release && cause == DreamerParkCause::ExecutorError,
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

#[test]
fn a_typed_budget_wait_narrows_a_trap_park_to_its_top_up_and_trap_consume() {
    assert_eq!(ParkResumer::ALL.len(), 18);
    for cause in CAUSES {
        for owner in ParkOwnerClass::ALL {
            for resumer in ParkResumer::ALL {
                let untyped = ParkResume::admits_wait(cause, owner, None, resumer);
                if matches!(
                    resumer,
                    ParkResumer::BudgetTopUp
                        | ParkResumer::SeatAvailable
                        | ParkResumer::PassStart
                        | ParkResumer::ResidentShareRaise
                ) {
                    assert!(!untyped, "{cause:?} {owner:?} {resumer:?}");
                } else {
                    assert_eq!(
                        untyped,
                        ParkResume::admits(cause, owner, resumer),
                        "{cause:?} {owner:?} {resumer:?}"
                    );
                }
                let typed = ParkResume::admits_wait(
                    cause,
                    owner,
                    Some(DreamerParkWaitClass::Budget),
                    resumer,
                );
                let admitted = if owner == ParkOwnerClass::Trap {
                    matches!(
                        resumer,
                        ParkResumer::BudgetTopUp
                            | ParkResumer::TrapConsume
                            | ParkResumer::OwnerRelease
                    )
                } else {
                    ParkResume::admits(cause, owner, resumer)
                };
                assert_eq!(typed, admitted, "{cause:?} {owner:?} {resumer:?}");
                let pass_typed = ParkResume::admits_wait(
                    cause,
                    owner,
                    Some(DreamerParkWaitClass::PassBudget),
                    resumer,
                );
                let pass_admitted = if owner == ParkOwnerClass::Trap {
                    matches!(
                        resumer,
                        ParkResumer::PassStart
                            | ParkResumer::BudgetTopUp
                            | ParkResumer::TrapConsume
                            | ParkResumer::OwnerRelease
                    )
                } else {
                    ParkResume::admits(cause, owner, resumer)
                };
                assert_eq!(pass_typed, pass_admitted, "{cause:?} {owner:?} {resumer:?}");
                let share_typed = ParkResume::admits_wait(
                    cause,
                    owner,
                    Some(DreamerParkWaitClass::ResidentShare),
                    resumer,
                );
                let share_admitted = if owner == ParkOwnerClass::Trap {
                    matches!(
                        resumer,
                        ParkResumer::ResidentShareRaise
                            | ParkResumer::TrapConsume
                            | ParkResumer::OwnerRelease
                    )
                } else {
                    ParkResume::admits(cause, owner, resumer)
                };
                assert_eq!(
                    share_typed, share_admitted,
                    "{cause:?} {owner:?} {resumer:?}"
                );
                for class in [
                    DreamerParkWaitClass::Consent,
                    DreamerParkWaitClass::Peer,
                    DreamerParkWaitClass::Human,
                ] {
                    assert_eq!(
                        ParkResume::admits_wait(cause, owner, Some(class), resumer),
                        owner == ParkOwnerClass::Trap && resumer == ParkResumer::TrapConsume,
                        "{cause:?} {owner:?} {class:?} {resumer:?}"
                    );
                }
                assert_eq!(
                    ParkResume::admits_wait(
                        cause,
                        owner,
                        Some(DreamerParkWaitClass::Seat),
                        resumer
                    ),
                    matches!(
                        resumer,
                        ParkResumer::SeatAvailable | ParkResumer::OwnerRelease
                    ),
                    "{cause:?} {owner:?} {resumer:?}"
                );
            }
        }
    }
    // The C5 spot check: no blind resumer frees a Budget or PassBudget wait on a trap park,
    // whatever its cause, so its own sender (a top-up, a pass with room) is the wait's only
    // timed route besides its own trap consume and the owner's release.
    for cause in CAUSES {
        for resumer in [
            ParkResumer::LaterPass,
            ParkResumer::BootRecovery,
            ParkResumer::OutageSweep,
            ParkResumer::ProviderRecovery,
        ] {
            for class in [
                DreamerParkWaitClass::Budget,
                DreamerParkWaitClass::PassBudget,
                DreamerParkWaitClass::ResidentShare,
            ] {
                assert!(
                    !ParkResume::admits_wait(cause, ParkOwnerClass::Trap, Some(class), resumer),
                    "{cause:?} {class:?} {resumer:?}"
                );
            }
        }
        // A pass start wakes no scope's wait; a top-up may wake a pass budget wait, whose
        // scope its scan matches (a free-time item's step, B3).
        assert!(!ParkResume::admits_wait(
            cause,
            ParkOwnerClass::Trap,
            Some(DreamerParkWaitClass::Budget),
            ParkResumer::PassStart
        ));
        assert!(ParkResume::admits_wait(
            cause,
            ParkOwnerClass::Trap,
            Some(DreamerParkWaitClass::PassBudget),
            ParkResumer::BudgetTopUp
        ));
        // No top-up or pass gives a resident a share, and a share write wakes no scope's or
        // pass's wait (D3).
        for resumer in [ParkResumer::BudgetTopUp, ParkResumer::PassStart] {
            assert!(!ParkResume::admits_wait(
                cause,
                ParkOwnerClass::Trap,
                Some(DreamerParkWaitClass::ResidentShare),
                resumer
            ));
        }
        for class in [
            DreamerParkWaitClass::Budget,
            DreamerParkWaitClass::PassBudget,
        ] {
            assert!(!ParkResume::admits_wait(
                cause,
                ParkOwnerClass::Trap,
                Some(class),
                ParkResumer::ResidentShareRaise
            ));
        }
    }
    // A Seat wait admits only its seat's available write and the owner's release, under any
    // owner and for any cause; every blind resumer and the trap consume refuse it (C5).
    for cause in CAUSES {
        for owner in ParkOwnerClass::ALL {
            for resumer in [
                ParkResumer::LaterPass,
                ParkResumer::BootRecovery,
                ParkResumer::OutageSweep,
                ParkResumer::ProviderRecovery,
                ParkResumer::TrapConsume,
                ParkResumer::BudgetTopUp,
                ParkResumer::PassStart,
                ParkResumer::ResidentShareRaise,
            ] {
                assert!(
                    !ParkResume::admits_wait(
                        cause,
                        owner,
                        Some(DreamerParkWaitClass::Seat),
                        resumer
                    ),
                    "{cause:?} {owner:?} {resumer:?}"
                );
            }
            for resumer in [ParkResumer::SeatAvailable, ParkResumer::OwnerRelease] {
                assert!(
                    ParkResume::admits_wait(
                        cause,
                        owner,
                        Some(DreamerParkWaitClass::Seat),
                        resumer
                    ),
                    "{cause:?} {owner:?} {resumer:?}"
                );
            }
        }
    }
}
