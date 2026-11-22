//! A test's config file, or a file its config names, written with the mode
//! the server admits whatever the process umask. Test-only: shared by the
//! crate's unit tests and its process-level integration tests.
//!
//! The server refuses a config file, and a prompt, wording, recipe, template
//! or settings file a config names, that any user can write
//! (`config::merge::file_admission`). A bare `std::fs::write` takes its mode
//! from the umask, and the fleet's test runner runs at umask 000, so such a
//! file is mode 0666 there and the test meets the refusal in place of the
//! behaviour it checks (FIX SIDE-FILE-TESTS-UMASK-DEPENDENT).

use std::path::Path;

/// Writes `contents` to `path`, then sets the file to mode 0600 (its owner's
/// alone, as `oneiron init` writes a config), whatever the umask made it.
/// An existing file is replaced and set to that mode too.
pub(crate) fn write_owner_only_file(
    path: impl AsRef<Path>,
    contents: impl AsRef<[u8]>,
) -> std::io::Result<()> {
    let path = path.as_ref();
    std::fs::write(path, contents)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}
