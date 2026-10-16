//! Flags for the owner's own commands: doctor, backup, maintain, restore,
//! window recovery, export, the secret scan switch, registering and rotating a
//! secret, importing history, import consent, agent-run consent and legal
//! holds.
//!
//! Every command that opens the vault reads the same config as `serve`
//! (`--config`, `--vault-path`, `ONEIRON_*`) and needs the vault stopped: the
//! writer lease admits one process. A running server answers the same actions
//! at `/v1/owner/*`.

use std::path::PathBuf;

use clap::{Args, Subcommand, ValueEnum};

use crate::config::ServeArgs;

#[derive(Args, Clone, Debug)]
pub struct DoctorArgs {
    /// Path to the LMDB vault directory.
    pub path: PathBuf,

    /// Embedding vector dimension for the vault; overrides the config's.
    #[arg(long)]
    pub dimensions: Option<usize>,

    /// LMDB map size in bytes; overrides the config's.
    #[arg(long)]
    pub map_size: Option<usize>,

    /// Comma-separated trusted roots containing ja/ko/zh dictionary assets;
    /// overrides the config's.
    #[arg(long = "dict-search-paths", value_delimiter = ',', num_args = 1..)]
    pub dict_search_paths: Option<Vec<PathBuf>>,

    /// Config file the vault runs with, as `serve --config` reads it; its
    /// `[backup]` section is reported. Defaults to the XDG path.
    #[arg(long)]
    pub config: Option<PathBuf>,

    /// Also list the ids of the stored vectors this device family computed:
    /// `cpu`, `cuda`, `metal`, `remote` (an endpoint's) or `unknown` (not
    /// recorded). These are the vectors a patch for one device would embed
    /// again.
    #[arg(long)]
    pub vectors_from: Option<oneiron::embed::EmbeddingDevice>,

    /// With `--vectors-from`, only those this runtime computed, named as
    /// `vector_provenance` names it.
    #[arg(long, requires = "vectors_from")]
    pub vectors_runtime: Option<String>,
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
pub struct MaintainArgs {
    /// Rebuild the vector graph from the stored vectors.
    #[arg(long)]
    pub rebuild_vector_graph: bool,

    /// With `--rebuild-vector-graph`: leave out stored vectors that do not
    /// validate (they stay stored) instead of failing the rebuild.
    #[arg(long, requires = "rebuild_vector_graph")]
    pub heal_invalid_vectors: bool,

    /// Recompute every short id's hash and drop short ids nothing holds.
    #[arg(long)]
    pub recompute_short_ids: bool,

    /// Index gate decisions recorded before the claim-keyed index existed.
    #[arg(long)]
    pub backfill_gate_claim_index: bool,

    /// Move every legacy conversation onto its DAG chain.
    #[arg(long)]
    pub migrate_conversation_dags: bool,

    /// Drop the text index and index every record again from the text it was
    /// indexed with: the repair for a vault refused after an analyzer or
    /// dictionary change.
    #[arg(long)]
    pub reindex_text: bool,

    #[command(flatten)]
    pub serve: ServeArgs,
}

#[derive(Args, Clone, Debug)]
pub struct RestoreArgs {
    /// The backup file.
    #[arg(required_unless_present = "activate")]
    pub backup: Option<PathBuf>,

    /// Activate the previous vault a restore set aside at this path, which
    /// is archived and refuses writes, as a side vault of the configured
    /// vault: it gets key custody of its own and opens for writing again.
    #[arg(long, value_name = "PREVIOUS_VAULT", conflicts_with_all = ["backup", "rehearse"])]
    pub activate: Option<PathBuf>,

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
pub struct RecoverWindowArgs {
    /// The sync window: `YYYY-MM`, or `YYYY-MM@<world id>`.
    pub window: String,

    #[command(flatten)]
    pub serve: ServeArgs,
}

#[derive(Args, Clone, Debug)]
pub struct RecoverClockArgs {
    #[command(flatten)]
    pub serve: ServeArgs,
}

#[derive(Args, Clone, Debug)]
pub struct ExportArgs {
    /// `archive`: the whole vault as one re-importable ZIP (JSONL per record
    /// kind, files by BLAKE3, manifest). `okf`: a lossy ZIP of markdown
    /// concepts (Open Knowledge Format) for other tools, not a full copy.
    /// Export is not a backup.
    #[arg(long, default_value = "archive")]
    pub format: String,

    /// Carry your custody secrets' values (the default). `--include-secrets
    /// false` exports each as its handle only, to re-enter after import.
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    pub include_secrets: bool,

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

/// The value is read from stdin, exactly as given (`printf %s "$TOKEN" |`
/// keeps a trailing newline out), and never from the command line.
#[derive(Subcommand, Clone, Debug)]
pub enum SecretsCommand {
    /// Put a secret into the stopped vault's custody.
    Register(Box<SecretRegisterArgs>),
    /// Replace a secret's value. Each lease picks the new value up when it
    /// next materializes.
    Rotate(Box<SecretRotateArgs>),
}

/// A secret's custody class (ARCH-0069 S1).
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum SecretClass {
    /// Encrypted and synced, unless `--device-only`.
    CustodyPortable,
    /// Never leaves this device.
    CustodyDeviceBound,
    /// Never replicated; other vaults get doored use through grants.
    CrossVault,
}

#[derive(Args, Clone, Debug)]
pub struct SecretRegisterArgs {
    /// The secret's custody name.
    #[arg(long)]
    pub name: String,

    #[arg(long, value_enum)]
    pub class: SecretClass,

    /// The custody ladder's rung: 0 doored, 1 leased, 2 local-registered.
    #[arg(long, value_parser = clap::value_parser!(u8).range(0..=2))]
    pub rung: u8,

    /// Keep a portable value on this device.
    #[arg(long)]
    pub device_only: bool,

    /// An effector that may use the secret, at its rung: `EFFECTOR` or
    /// `EFFECTOR=SCOPE,SCOPE` (`deploy=read`). Repeat for more. With
    /// `--repo` and none given, the manifest's bindings are used.
    #[arg(long = "binding", value_name = "EFFECTOR[=SCOPES]")]
    pub bindings: Vec<String>,

    /// A repository this vault serves whose secret manifest declares the
    /// name. Its entry is copied onto the record, and nothing wider than it
    /// is registered.
    #[arg(long)]
    pub repo: Option<String>,

    /// The published ref the manifest is read at.
    #[arg(long = "ref", default_value = "refs/heads/main")]
    pub git_ref: String,

    #[command(flatten)]
    pub serve: ServeArgs,
}

#[derive(Args, Clone, Debug)]
pub struct SecretRotateArgs {
    /// The secret's custody name.
    #[arg(long)]
    pub name: String,

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
    /// A coding agent's session log a hook handed over (its
    /// `transcript_path`): GitHub Copilot's (VS Code's transcript or the CLI's
    /// `events.jsonl`) or a Cursor agent transcript. One file, under a folder
    /// listed in `[import] hook_transcript_roots`.
    HookTranscript(Box<ImportSourceArgs>),
    /// A folder of linked markdown notes (an Obsidian vault, an agent's
    /// memory folder): writes the batch of new notes and links to `--out` and
    /// prints the digest that approves or declines it.
    Notes(Box<ImportNotesArgs>),
    /// Print the exact batch, ids filled in, and the digest that approves it.
    Preview(Box<ImportBatchArgs>),
    /// Admit the whole previewed batch as approved, in one act.
    Approve(Box<ImportDecisionArgs>),
    /// Decline the whole previewed batch; nothing is admitted.
    Decline(Box<ImportDecisionArgs>),
    /// A whole-vault archive `oneiron export` wrote (OF-222): checks every
    /// member against its manifest, then re-imports it in one transaction.
    Archive(Box<ImportArchiveArgs>),
}

#[derive(Args, Clone, Debug)]
pub struct ImportArchiveArgs {
    /// The archive (a ZIP).
    pub path: PathBuf,

    #[command(flatten)]
    pub serve: ServeArgs,
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

    /// Hand one session log to the running `serve` instead, which imports it
    /// within seconds. Needs `[import] queue = true` in the serve config and
    /// a log under that source's root; writes one small queue file, nothing
    /// else.
    #[arg(long, conflicts_with = "dry_run")]
    pub queue: bool,

    #[command(flatten)]
    pub serve: ServeArgs,
}

#[derive(Args, Clone, Debug)]
pub struct ImportNotesArgs {
    /// The folder. Only this path is read: symbolic links and hidden entries
    /// under it are skipped.
    pub path: PathBuf,

    /// Write the batch to this new file (owner-only). `import approve` and
    /// `import decline` take it with the printed digest.
    #[arg(long)]
    pub out: PathBuf,

    /// The note kind of a note whose frontmatter `type` names no kind the
    /// vault knows.
    #[arg(long, default_value = "observation")]
    pub kind: String,

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
pub enum HandoffAlarmsCommand {
    /// Every saved fork alarm a held root handoff left, open or acknowledged.
    List(Box<ServeOnlyArgs>),
    /// Acknowledge one alarm: it stays saved, its refused row marked seen.
    Acknowledge(Box<HandoffAlarmAckArgs>),
}

#[derive(Args, Clone, Debug)]
pub struct HandoffAlarmAckArgs {
    /// The alarm's retired key, `suite:hex`, as `list` names it.
    pub signer: String,

    #[command(flatten)]
    pub serve: ServeArgs,
}

#[derive(Subcommand, Clone, Debug)]
pub enum LegalHoldsCommand {
    /// Every hold you may see: your own, and each legal order you may be
    /// told of.
    List(Box<ServeOnlyArgs>),
    /// The hold log, oldest first: ids, times and reason codes.
    Log(Box<ServeOnlyArgs>),
    /// Place a hold. Deletes of what it names then fail for agents, timers,
    /// members and you alike; every other verb keeps working.
    Place(Box<LegalHoldPlaceArgs>),
    /// Add records or partitions to one of your standing holds.
    Widen(Box<LegalHoldWidenArgs>),
    /// "Lift the hold and erase?": lift your holds on these records and
    /// erase them. Prints the confirm's prompt, and acts only with `--yes`.
    LiftAndErase(Box<LegalHoldLiftArgs>),
}

/// What a hold names.
#[derive(Args, Clone, Debug)]
pub struct LegalHoldTargetArgs {
    /// A record to hold, 32 hex. Repeat for more.
    #[arg(long = "record", value_name = "HEX")]
    pub records: Vec<String>,

    /// A claim's gate-decision key partition to hold, 32 hex, or `none` for
    /// the claim-free partition. Repeat for more.
    #[arg(long = "gate-partition", value_name = "HEX|none")]
    pub gate_partitions: Vec<String>,
}

#[derive(Args, Clone, Debug)]
pub struct LegalHoldPlaceArgs {
    #[command(flatten)]
    pub targets: LegalHoldTargetArgs,

    /// An opaque matter reference, never free text: 1 to 128 of
    /// A-Z a-z 0-9 . _ : - /.
    #[arg(long)]
    pub matter_ref: Option<String>,

    #[command(flatten)]
    pub serve: ServeArgs,
}

#[derive(Args, Clone, Debug)]
pub struct LegalHoldWidenArgs {
    /// The hold, 32 hex, as `list` names it.
    pub hold_id: String,

    #[command(flatten)]
    pub targets: LegalHoldTargetArgs,

    #[command(flatten)]
    pub serve: ServeArgs,
}

#[derive(Args, Clone, Debug)]
pub struct LegalHoldLiftArgs {
    /// The records to lift and erase, 32 hex each.
    #[arg(required = true, value_name = "RECORD")]
    pub records: Vec<String>,

    /// You have read the prompt and confirm it.
    #[arg(long)]
    pub yes: bool,

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
