//! `oneiron hook`: the flags of the Python example it replaces
//! (`oneiron_hook.py`), with the same defaults and limits.

use std::path::PathBuf;

use clap::{Args, Subcommand, ValueEnum};

#[derive(Args, Clone, Debug)]
pub struct HookArgs {
    /// The agent harness whose hook event arrives on stdin.
    #[arg(long, value_enum)]
    pub host: HookHost,

    #[command(subcommand)]
    pub event: HookEvent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum HookHost {
    ClaudeCode,
    /// Hermes Agent's memory-provider plugin (`packages/oneiron-hermes`). It
    /// asks only `bind`, and reads and writes through the Python SDK.
    Hermes,
}

#[derive(Subcommand, Clone, Debug)]
pub enum HookEvent {
    /// Bind a vault for the session, print one line naming it, and recall a
    /// short block for the project (`SessionStart`).
    SessionStart(HookRecallArgs),
    /// Recall a short block for the prompt (`UserPromptSubmit`; off unless
    /// the hook is set up). Never starts a server.
    Prompt(HookRecallArgs),
    /// Queue the session's log for the running `serve` to import
    /// (`PreCompact`, `Stop`, `SessionEnd`).
    HandOver(HookHandOverArgs),
    /// Bind a vault for a session, in the same order as `session-start`, and
    /// print `{"url", "lines"}` as one JSON line: a plugin that runs in its
    /// host's process (Hermes) asks here, so the order has one home. Reads
    /// no event.
    Bind(HookBindArgs),
}

#[derive(Args, Clone, Debug)]
pub struct HookBindArgs {
    #[command(flatten)]
    pub common: HookCommonArgs,

    /// The vault's origin. This pins it, as for `session-start`.
    #[arg(long)]
    pub url: Option<String>,
}

#[derive(Args, Clone, Debug)]
pub struct HookCommonArgs {
    /// The oneiron binary to run for the bridge and the import. Defaults to
    /// this one.
    #[arg(long)]
    pub oneiron: Option<PathBuf>,

    /// Seconds before giving up.
    #[arg(long, default_value_t = 8.0)]
    pub timeout: f64,
}

#[derive(Args, Clone, Debug)]
pub struct HookRecallArgs {
    #[command(flatten)]
    pub common: HookCommonArgs,

    /// The vault's origin. This pins it: without it the hook binds the pin in
    /// `hook.toml`, else a running local vault, else starts one.
    #[arg(long)]
    pub url: Option<String>,

    /// The agent credential `token agent --out` wrote. Without it the hook
    /// binds a vault but recalls nothing.
    #[arg(long, value_name = "FILE")]
    pub credential_file: Option<PathBuf>,

    /// Most hits printed.
    #[arg(long, default_value_t = 8)]
    pub limit: usize,

    /// Recall this instead of the project's name (or the prompt).
    #[arg(long)]
    pub query: Option<String>,

    /// Recall effort: light reads lexically; medium and up embed the query
    /// (allow a --timeout the server's embedder can meet).
    #[arg(long, value_enum, default_value_t = HookEffort::Light)]
    pub effort: HookEffort,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum HookEffort {
    Light,
    Medium,
    High,
    Xhigh,
    Max,
}

impl HookEffort {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Light => "light",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Xhigh => "xhigh",
            Self::Max => "max",
        }
    }
}

#[derive(Args, Clone, Debug)]
pub struct HookHandOverArgs {
    #[command(flatten)]
    pub common: HookCommonArgs,

    /// The serve config, for where the import queue is. Without it, the
    /// config of the running local vault, else the default config.
    #[arg(long)]
    pub config: Option<PathBuf>,
}
