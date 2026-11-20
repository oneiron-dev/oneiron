//! `oneiron continue --cloud`: the Claude Code session working in this repo
//! goes on in the selected hosted vault, on its node's own runner seat.

use std::path::PathBuf;

use clap::Args;

#[derive(Args, Clone, Debug)]
pub struct ContinueArgs {
    /// Continue in the hosted vault `oneiron hosted` selected (the one place
    /// a session continues today).
    #[arg(long, required = true)]
    pub cloud: bool,
    /// The custody repo the working tree goes to, by the name the vault
    /// serves it under (its push URL's `/git/<repo>`).
    #[arg(long)]
    pub repo: String,
    /// The runner the session goes on in.
    #[arg(long, default_value = "claude-code")]
    pub runner: String,
    /// A note for the run.
    #[arg(long)]
    pub note: Option<String>,
    /// The session's log, as the hook reads `transcript_path`; without it,
    /// the newest log Claude Code kept for this directory.
    #[arg(long)]
    pub transcript: Option<PathBuf>,
}
