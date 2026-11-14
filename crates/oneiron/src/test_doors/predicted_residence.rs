//! Doors for the integration tests of the predicted residence level (census
//! L7-46 + L10-14, ARCH-0023b #predicted-residence).

use crate::sync::connection::SyncConnection;
use crate::sync::transport::TransportError;

/// Runs the owner's pending residence directives naming this machine on
/// `connection`, as its residence upkeep does once the authority history is
/// in, without a socket. Answers how many it finished.
///
/// # Errors
///
/// The connection's: a directive that cannot run yet, or storage.
pub async fn apply_residence_directives(
    connection: &SyncConnection,
) -> Result<usize, TransportError> {
    connection.apply_residence_directives().await
}
