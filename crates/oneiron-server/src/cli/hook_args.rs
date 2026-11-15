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

/// The harness whose hook runs (`docs/ops/client-session-hooks.md`). Every
/// host's event is read for the same fields; the host decides how a reply
/// is printed and which `oneiron import` reads its session log.
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum HookHost {
    /// Claude Code (`plugins/claude-code/hooks/hooks.json`): plain text on
    /// stdout joins the session's context; its logs are Claude Code sessions.
    ClaudeCode,
    /// OpenAI Codex (`plugins/agent-plugins/com.openai/hooks/hooks.json`):
    /// plain text on stdout joins the session's context, as for Claude Code;
    /// its logs are Codex rollouts.
    Codex,
    /// Cursor (`plugins/cursor/hooks/hooks.json`): it reads one JSON object
    /// with `additional_context`; its logs are hook transcripts.
    Cursor,
    /// GitHub Copilot in VS Code and the Copilot CLI
    /// (`plugins/agent-plugins/com.github.copilot/hooks/hooks.json`): it
    /// reads one JSON object with `additionalContext`; its logs are hook
    /// transcripts.
    Copilot,
    /// Hermes Agent's memory-provider plugin (`packages/oneiron-hermes`). It
    /// asks only `bind`, and reads and writes through the Python SDK.
    Hermes,
}

impl HookHost {
    /// The name `--host` takes.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ClaudeCode => "claude-code",
            Self::Codex => "codex",
            Self::Cursor => "cursor",
            Self::Copilot => "copilot",
            Self::Hermes => "hermes",
        }
    }

    /// The harness's own name, as a person reads it.
    #[must_use]
    pub const fn product_name(self) -> &'static str {
        match self {
            Self::ClaudeCode => "Claude Code",
            Self::Codex => "Codex",
            Self::Cursor => "Cursor",
            Self::Copilot => "GitHub Copilot",
            Self::Hermes => "Hermes Agent",
        }
    }
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
    /// (`PreCompact`, `Stop`, `SessionEnd`), by the import that reads the
    /// host's logs.
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

    /// The owner's settings file, layered over the config as `serve
    /// --settings-file` layers it, for a server the hook starts and an
    /// import it queues. Without it a hand-over takes the running local
    /// vault's own, unless its `--config` names another config.
    #[arg(long, value_name = "FILE")]
    pub settings_file: Option<PathBuf>,
}

#[derive(Args, Clone, Debug)]
pub struct HookRecallArgs {
    #[command(flatten)]
    pub common: HookCommonArgs,

    /// The vault's origin. This pins it: without it the hook binds the pin in
    /// `hook.toml`, else a running local vault, else the hosted vault
    /// `oneiron hosted` selected, else starts one.
    #[arg(long)]
    pub url: Option<String>,

    /// The agent credential `token agent --out` wrote, for a pinned or local
    /// vault. Without it the hook binds such a vault but recalls nothing. A
    /// selected hosted vault's recall runs as the credential its selection
    /// names, never this one.
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
    /// config of the running local vault, else the default config. A config
    /// named here takes that vault's settings file only if it is its own.
    #[arg(long)]
    pub config: Option<PathBuf>,
}
