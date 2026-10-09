//! Flags for the owner's own commands: doctor, backup, restore, export, the
//! secret scan switch, importing history, import consent and agent-run
//! consent.
//!
//! Every command that opens the vault reads the same config as `serve`
//! (`--config`, `--vault-path`, `ONEIRON_*`) and needs the vault stopped: the
//! writer lease admits one process. A running server answers the same actions
//! at `/v1/owner/*`.

use std::path::PathBuf;

use clap::{Args, Subcommand, ValueEnum};

use super::VaultArgs;
use crate::config::ServeArgs;

#[derive(Args, Clone, Debug)]
pub struct DoctorArgs {
    #[command(flatten)]
    pub vault: VaultArgs,

    /// Config file whose `[backup]` section to report. Defaults to the XDG path.
    #[arg(long)]
    pub config: Option<PathBuf>,
}

#[derive(Args, Clone, Debug)]
pub struct WhoamiArgs {
    /// Path to the LMDB vault directory.
    pub path: PathBuf,

    /// Config file the vault runs with. Defaults to the XDG path.
    #[arg(long)]
    pub config: Option<PathBuf>,
}

#[derive(Args, Clone, Debug)]
pub struct BackupArgs {
    /// List this vault's backups instead of taking one.
    #[arg(long)]
    pub list: bool,

    /// Backup directory; overrides `[backup] dir`.
    #[arg(long)]
    pub dir: Option<PathBuf>,

    /// How many backups to keep, this one included; overrides `[backup] keep`.
    #[arg(long)]
    pub keep: Option<usize>,

    #[command(flatten)]
    pub serve: ServeArgs,
}

#[derive(Args, Clone, Debug)]
pub struct RestoreArgs {
    /// The backup file.
    pub backup: PathBuf,

    /// Restore into a scratch copy, open and check it, and report. The vault
    /// itself is never opened, so this also works while `serve` runs.
    #[arg(long)]
    pub rehearse: bool,

    /// With `--rehearse`: create this new directory and keep the restored
    /// copy in it, at `<DIR>/vault`.
    #[arg(long, requires = "rehearse")]
    pub scratch: Option<PathBuf>,

    #[command(flatten)]
    pub serve: ServeArgs,
}

#[derive(Args, Clone, Debug)]
pub struct ExportArgs {
    /// `toon`, `md`, `json`, `yaml` or `txt`.
    #[arg(long, default_value = "toon")]
    pub format: String,

    /// Write the export to this new file (owner-only); stdout when omitted.
    #[arg(long)]
    pub out: Option<PathBuf>,

    #[command(flatten)]
    pub serve: ServeArgs,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum SecretScanSwitch {
    On,
    Off,
}

#[derive(Args, Clone, Debug)]
pub struct SecretScanArgs {
    /// `on` or `off`. Omit it to print the setting and every change to it.
    pub mode: Option<SecretScanSwitch>,

    #[command(flatten)]
    pub serve: ServeArgs,
}

#[derive(Subcommand, Clone, Debug)]
pub enum ImportCommand {
    /// A ChatGPT export: the zip, its `conversations.json`, or the unzipped folder.
    Chatgpt(Box<ImportSourceArgs>),
    /// A Claude.ai export: the zip, its `conversations.json`, or the unzipped folder.
    Claude(Box<ImportSourceArgs>),
    /// Claude Code history: `~/.claude/projects`, one project's folder, or one session log.
    ClaudeCode(Box<ImportSourceArgs>),
    /// Codex history: `~/.codex/sessions`, any folder under it, or one rollout.
    Codex(Box<ImportSourceArgs>),
    /// Print the exact batch, ids filled in, and the digest that approves it.
    Preview(Box<ImportBatchArgs>),
    /// Admit the whole previewed batch as approved, in one act.
    Approve(Box<ImportDecisionArgs>),
    /// Decline the whole previewed batch; nothing is admitted.
    Decline(Box<ImportDecisionArgs>),
}

#[derive(Args, Clone, Debug)]
pub struct ImportSourceArgs {
    /// What to import. Only this path is read: symbolic links under it are
    /// not followed.
    pub path: PathBuf,

    /// Print, per conversation, how many messages are new, already imported
    /// or changed, and write nothing. The vault is not opened, so this also
    /// works while `serve` runs.
    #[arg(long)]
    pub dry_run: bool,

    #[command(flatten)]
    pub serve: ServeArgs,
}

#[derive(Args, Clone, Debug)]
pub struct ImportBatchArgs {
    /// Batch JSON file, or `-` for stdin.
    pub batch: String,

    #[command(flatten)]
    pub serve: ServeArgs,
}

#[derive(Args, Clone, Debug)]
pub struct ImportDecisionArgs {
    /// The exact batch `import preview` printed (its `batch` field), or `-`.
    pub batch: String,

    /// The digest `import preview` printed for that batch.
    #[arg(long)]
    pub digest: String,

    #[command(flatten)]
    pub serve: ServeArgs,
}

#[derive(Subcommand, Clone, Debug)]
pub enum RunsCommand {
    /// Agent runs with proposals waiting for you.
    Pending(Box<ServeOnlyArgs>),
    /// What one run is waiting on, and the bundle id that decides it.
    Show(Box<RunArgs>),
    /// Approve every proposal of the reviewed run in one act.
    Approve(Box<RunDecisionArgs>),
    /// Decline every proposal of the reviewed run in one act.
    Decline(Box<RunDecisionArgs>),
}

#[derive(Args, Clone, Debug)]
pub struct ServeOnlyArgs {
    #[command(flatten)]
    pub serve: ServeArgs,
}

#[derive(Args, Clone, Debug)]
pub struct RunArgs {
    /// The run id.
    #[arg(required_unless_present = "run_ref")]
    pub run_id: Option<String>,

    /// The `run_ref` `runs pending` printed for the run, in place of its id.
    #[arg(long = "ref", value_name = "RUN_REF", conflicts_with = "run_id")]
    pub run_ref: Option<String>,

    #[command(flatten)]
    pub serve: ServeArgs,
}

#[derive(Args, Clone, Debug)]
pub struct RunDecisionArgs {
    /// The run id.
    #[arg(required_unless_present = "run_ref")]
    pub run_id: Option<String>,

    /// The `run_ref` `runs pending` printed for the run, in place of its id.
    #[arg(long = "ref", value_name = "RUN_REF", conflicts_with = "run_id")]
    pub run_ref: Option<String>,

    /// The bundle id `runs show` printed for exactly these proposals.
    #[arg(long)]
    pub bundle: String,

    #[command(flatten)]
    pub serve: ServeArgs,
}
