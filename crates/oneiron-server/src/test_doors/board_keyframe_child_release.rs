//! Door for `tests/board_keyframe_child_release.rs`
//! (BOARD-KEYFRAME-CHILD-RELEASE): the judgment a connector board
//! keyframe's bare child row passes, toward a destination the test names.

use oneiron::settings::ReadDestination;

/// The rows the bare row of the child whose attempt id is `child` is served
/// by on a connector's board toward `destination`, beside its attempt:
/// `None` when the row stays off that board.
pub fn bare_child_served_rows(
    vault: &oneiron::Vault,
    destination: &ReadDestination,
    child: &str,
) -> Option<Vec<oneiron::EntityId>> {
    crate::api::bare_child_served_rows_for_test(vault, destination, child)
}
