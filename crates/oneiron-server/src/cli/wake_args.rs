//! Host-side wake inbox commands. Delivery runs with `mcp --wake-config`.

use std::path::PathBuf;

use clap::{Args, Subcommand};

#[derive(Args, Clone, Debug)]
pub struct WakeArgs {
    /// TOML adapter configuration in this harness instance's config directory.
    /// That directory, not a harness name or a terminal title, identifies it.
    #[arg(long)]
    pub config: PathBuf,

    #[command(subcommand)]
    pub command: WakeCommand,
}

#[derive(Subcommand, Clone, Debug)]
pub enum WakeCommand {
    /// Read the instance inbox and acknowledge exactly the envelopes printed.
    Inbox {
        /// Emit Claude Code's Stop-hook decision instead of the JSON batch.
        /// With no mail, the hook is allowed to stop.
        #[arg(long)]
        claude_code_stop: bool,
    },
    /// Acknowledge one or more occurrence ids, never a whole TASK.
    Ack {
        #[arg(required = true)]
        event_ref: Vec<String>,
    },
}
