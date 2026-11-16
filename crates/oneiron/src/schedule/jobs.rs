//! The job registry: every kind of job the engine runs on a schedule.

use super::JobSpec;

/// Every job kind, one line each: the engine's 19 sweeps (stage 5a), the deadlines doors note for
/// five of them, the pending check-ins' due transitions, the outage parks' timed resumes, the
/// model seats' resets, the agent waits' `until`, the watcher TASKs' ticks and the actors' timer
/// turn programs (stage 5b), the held sends' releases (stage 5c) and the tests' jobs; the other
/// host loops join in stage 5c.
static JOBS: &[&JobSpec] = &[
    &crate::housekeeping::jobs::SECRET_LEASE_EXPIRY_JOB,
    &crate::housekeeping::jobs::CRITICAL_CONFIRM_EXPIRY_JOB,
    &crate::housekeeping::jobs::SYMBOL_LEASE_EXPIRY_JOB,
    &crate::housekeeping::jobs::VOICE_PRINT_RETENTION_JOB,
    &crate::housekeeping::jobs::ESIGN_EXPIRY_JOB,
    &crate::housekeeping::jobs::ESIGN_SEAL_BACKSTOP_JOB,
    &crate::housekeeping::jobs::COMMITMENT_LAPSE_JOB,
    &crate::housekeeping::jobs::GATE_DECISION_RETENTION_JOB,
    &crate::housekeeping::jobs::HARD_ERASE_SWEEP_JOB,
    &crate::housekeeping::jobs::PPR_CACHE_EVICTION_JOB,
    &crate::housekeeping::jobs::SHARED_ACT_MATURITY_JOB,
    &crate::housekeeping::jobs::SECRET_LIFT_HISTORY_JOB,
    &crate::housekeeping::jobs::CLAIM_VAD_DEBT_JOB,
    &crate::housekeeping::jobs::FOUND_KEY_NOTICES_JOB,
    &crate::housekeeping::jobs::BODY_LINE_INDEX_REBUILD_JOB,
    &crate::housekeeping::jobs::ANNOTATION_BODY_ANCHORS_JOB,
    &crate::housekeeping::jobs::DRAFTER_CORPUS_SWEEP_JOB,
    &crate::housekeeping::jobs::MODEL_PACK_RETIREMENT_JOB,
    &crate::housekeeping::jobs::OAUTH_EXPIRY_JOB,
    &crate::housekeeping::jobs::SECRET_LEASE_EXPIRY_DEADLINE_JOB,
    &crate::housekeeping::jobs::CRITICAL_CONFIRM_EXPIRY_DEADLINE_JOB,
    &crate::housekeeping::jobs::VOICE_PRINT_RETENTION_DEADLINE_JOB,
    &crate::housekeeping::jobs::SHARED_ACT_MATURITY_DEADLINE_JOB,
    &crate::housekeeping::jobs::ANNOTATION_BODY_ANCHORS_DEADLINE_JOB,
    &crate::check_in::CHECK_IN_DUE_JOB,
    &crate::dreamer_runner::OUTAGE_RESUME_JOB,
    &crate::dreamer_runner::SEAT_RESET_JOB,
    &crate::agent_dispatch::CHILD_WAIT_UNTIL_JOB,
    &crate::runtime_hooks::TASK_TICK_JOB,
    &crate::dreamer_runner::PROGRAM_TIMER_JOB,
    &crate::outbound::UNDO_SEND_RELEASE_JOB,
    #[cfg(oneiron_test_support)]
    &crate::test_doors::schedule::TEST_COUNT,
    #[cfg(oneiron_test_support)]
    &crate::test_doors::schedule::TEST_FAIL,
    #[cfg(oneiron_test_support)]
    &crate::test_doors::schedule::TEST_PAGED,
    #[cfg(oneiron_test_support)]
    &crate::test_doors::schedule::TEST_ENGINE,
    #[cfg(oneiron_test_support)]
    &crate::test_doors::schedule::TEST_LAPSE,
    #[cfg(oneiron_test_support)]
    &crate::test_doors::schedule::TEST_CADENCE,
    #[cfg(oneiron_test_support)]
    &crate::test_doors::schedule::TEST_ITEMS,
    #[cfg(oneiron_test_support)]
    &crate::test_doors::schedule::TEST_OPEN,
    #[cfg(oneiron_test_support)]
    &crate::test_doors::schedule::TEST_ANSWER,
    #[cfg(oneiron_test_support)]
    &crate::test_doors::schedule::TEST_ONCE,
    #[cfg(oneiron_test_support)]
    &crate::test_doors::schedule::TEST_REARM,
    #[cfg(oneiron_test_support)]
    &crate::test_doors::schedule::TEST_DUE_BY,
    #[cfg(oneiron_test_support)]
    &crate::test_doors::schedule::TEST_FAIL_ONCE,
];

/// The job kind whose code is `code`.
pub(crate) fn job_named(code: &str) -> Option<&'static JobSpec> {
    JOBS.iter().copied().find(|job| job.code == code)
}

/// Every job kind.
pub(crate) fn jobs() -> impl Iterator<Item = &'static JobSpec> {
    JOBS.iter().copied()
}
