//! Door for `tests/hook_user_service.rs` ([L1-14]): the launchd agent
//! `oneiron user-service install` writes on macOS, rendered on any Unix
//! host, so the Linux fleet checks it too.

use std::path::Path;

/// The launchd agent `install` writes to run `oneiron` with `config` and
/// `settings_file`, logging under `home`.
///
/// # Errors
///
/// A path a unit file cannot hold, in the renderer's words.
pub fn launchd_agent(
    oneiron: &Path,
    config: &Path,
    settings_file: Option<&Path>,
    home: &Path,
) -> Result<String, String> {
    crate::commands::user_service::launchd_agent(oneiron, config, settings_file, home)
        .map_err(|error| format!("{error:#}"))
}
