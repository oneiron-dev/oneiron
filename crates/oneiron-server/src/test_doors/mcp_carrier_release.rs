//! Doors for `tests/board_child_release.rs` (census L2-38, review round 1):
//! the release check a gateway carrier frame passes before it rides and
//! again once its call has nothing left to wait on, toward a destination
//! the test names.

use oneiron::context_board::BoardStreamFrame;
use oneiron::settings::ReadDestination;

/// Whether `frame` may leave toward `destination`, with no rider rows, as
/// the MCP result carrier judges a queued frame.
#[must_use]
pub fn carrier_releases(
    vault: &oneiron::Vault,
    destination: &ReadDestination,
    frame: &BoardStreamFrame,
) -> bool {
    crate::api::carrier_releases_for_test(vault, destination, frame)
}
