//! The job registry: every kind of job the engine runs on a schedule.

use super::JobSpec;

/// Every job kind, one line each. Stage 0.2 registers none outside the tests; the sweeps, the due
/// indexes and the host loops join in stage 5.
static JOBS: &[&JobSpec] = &[
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
];

/// The job kind whose code is `code`.
pub(crate) fn job_named(code: &str) -> Option<&'static JobSpec> {
    JOBS.iter().copied().find(|job| job.code == code)
}
