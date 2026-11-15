//! Door for `tests/git_lfs_install_wait_out.rs` (L3-30): the whole of the
//! line an LFS upload takes its install room on, held as installs in flight
//! would hold it, so the next upload's install waits its deadline out.

use crate::byte_line::HeldBytes;
use crate::server::SyncServer;

/// The installs line, held whole until this is dropped.
#[must_use = "the line is held only while this lives"]
pub struct HeldInstallLine {
    _held: HeldBytes,
}

/// Holds the whole of `server`'s LFS installs line. `None` when the line is
/// not free within the server's queue wait.
pub async fn hold_whole_install_line(server: &SyncServer) -> Option<HeldInstallLine> {
    let installs = server.transfers.lfs_installs();
    installs
        .reserve(
            installs.total(),
            server.transfers.wait,
            &server.transfers.questions,
        )
        .await
        .map(|held| HeldInstallLine { _held: held })
}
