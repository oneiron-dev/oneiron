//! The container CLI's environment beyond `PATH`: the `HOME` and
//! `XDG_RUNTIME_DIR` its host binds once for the process (FIX 6876). A
//! rootless CLI started under a vault's UID finds its per-UID storage and
//! runtime state through them. Unbound, every CLI call keeps `PATH` alone.

use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;

/// The bound directories: the CLI's `HOME`, then its `XDG_RUNTIME_DIR`.
static CLI_ENV: OnceLock<(Option<PathBuf>, Option<PathBuf>)> = OnceLock::new();

/// Binds the container CLI's `HOME` and `XDG_RUNTIME_DIR` for this process:
/// every CLI call after it (run, inspect and removal) carries the ones
/// given, and only those. The first call wins; a later one changes nothing.
/// The host checks them first; nothing here reads or makes a directory.
pub fn set_cli_env(home: Option<PathBuf>, runtime_dir: Option<PathBuf>) {
    let _ = CLI_ENV.set((home, runtime_dir));
}

/// A CLI call's environment, after its `PATH`.
pub(crate) trait ApplyCliEnv {
    /// Adds the bound `HOME` and `XDG_RUNTIME_DIR` to the call's cleared
    /// environment; nothing when none is bound.
    fn apply_cli_env(&mut self) -> &mut Self;
}

impl ApplyCliEnv for Command {
    fn apply_cli_env(&mut self) -> &mut Self {
        if let Some((home, runtime_dir)) = CLI_ENV.get() {
            if let Some(home) = home {
                self.env("HOME", home);
            }
            if let Some(runtime_dir) = runtime_dir {
                self.env("XDG_RUNTIME_DIR", runtime_dir);
            }
        }
        self
    }
}

/// Adds the bound `HOME` and `XDG_RUNTIME_DIR` to a cleared spawn from
/// another crate (FIX 6886): the public twin of [`ApplyCliEnv`], which stays
/// crate-private. Nothing when none is bound.
pub fn apply_cli_env_to_command(command: &mut Command) -> &mut Command {
    command.apply_cli_env()
}
