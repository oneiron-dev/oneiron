//! The residence directive door (row SEQ-FLOOR-S-WITHHELD-COSIGN-REVIEW-TESTS):
//! read the directives pending on this install, then run one of them on a
//! connection as its upkeep round does, its act and result together, so a
//! test lands a revocation between the read and the run. Compiled only under
//! `--cfg oneiron_test_support`; never API.

use crate::Vault;
use crate::sync::connection::SyncConnection;
use crate::sync::residence::ResidenceDirectiveState;
use crate::sync::transport::TransportError;

/// The accepted directives naming this install's machine that it has no
/// result for yet, oldest first, as an upkeep round reads them.
///
/// # Errors
///
/// Storage.
pub fn pending_residence_directives(
    vault: &Vault,
) -> crate::error::Result<Vec<ResidenceDirectiveState>> {
    crate::sync::residence::pending_residence_directives(vault)
}

/// Runs `pending` on `connection` and records its result, as an upkeep
/// round runs each directive it read as pending.
///
/// # Errors
///
/// The directive's: an act that cannot run, or a result the fold refuses,
/// in which case nothing the act did commits.
pub async fn apply_residence_directive(
    connection: &SyncConnection,
    pending: &ResidenceDirectiveState,
) -> Result<(), TransportError> {
    connection.apply_residence_directive(pending).await
}
