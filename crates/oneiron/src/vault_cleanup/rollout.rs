//! The integrity-teeth badge an automatic cleanup run records on its digest.
//!
//! The automatic posture does not wait on these teeth: the owner ruled that
//! the Dreamer applies its cleanup and reverts if needed, in every vault from
//! birth, with no grant step and no holdout (2026-10-18, ARCH-0073
//! #arm-ruled; DEC-0006). Each automatic run takes a snapshot first and the
//! owner can revert it. ARCH-0066 teeth #5 and #9 ride each automatic run's
//! digest and receipt as a proof badge instead. Each flag flips in the PR
//! that closes its tooth.

use super::CleanupIntegrityTeeth;

/// ARCH-0066 tooth #5: read/fold verification coverage at consumption.
const READ_FOLD_COVERAGE_CLOSED: bool = false;
/// ARCH-0066 tooth #9: OS-level separation of the vault's files.
const OS_SEPARATION_CLOSED: bool = false;

/// The badge an automatic run records: both teeth as they stand now.
pub(super) const fn integrity_teeth() -> CleanupIntegrityTeeth {
    CleanupIntegrityTeeth {
        read_fold_coverage_closed: READ_FOLD_COVERAGE_CLOSED,
        os_separation_closed: OS_SEPARATION_CLOSED,
    }
}
