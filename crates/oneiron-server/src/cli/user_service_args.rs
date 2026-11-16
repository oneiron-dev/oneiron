//! `oneiron user-service`: the optional user service of ARCH-0028
//! `#plugin-first-run` step 4, which keeps this user's local vault running
//! between sessions and after login.

use std::path::PathBuf;

use clap::{Args, Subcommand};

#[derive(Subcommand, Clone, Debug)]
pub enum UserServiceCommand {
    /// Write this user's service for the local vault `oneiron hook` starts
    /// (a systemd user unit on Linux, a launchd agent on macOS) and start it
    /// through the person's own supervisor. Run again, it writes the unit
    /// anew and restarts the service. It never overwrites a unit it did not
    /// write.
    Install(UserServiceInstallArgs),
    /// Stop this user's service, and delete the unit `install` wrote.
    Remove,
    /// Print whether the service is installed, as one JSON line.
    Status,
}

#[derive(Args, Clone, Debug)]
pub struct UserServiceInstallArgs {
    /// The config the service's `serve` reads; without it, the one every
    /// command reads when none is named (`ONEIRON_CONFIG`, else the default
    /// `oneiron.toml`), as the hook's step 4 starts.
    #[arg(long, value_name = "FILE")]
    pub config: Option<PathBuf>,

    /// The owner's settings file, layered over the config as `serve
    /// --settings-file` layers it; give the hook's own `--settings-file`.
    #[arg(long, value_name = "FILE")]
    pub settings_file: Option<PathBuf>,

    /// The oneiron binary the service runs. Defaults to this one.
    #[arg(long, value_name = "FILE")]
    pub oneiron: Option<PathBuf>,
}
