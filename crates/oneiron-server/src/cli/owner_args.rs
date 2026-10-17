//! Flags for the owner's own commands: doctor, backup, maintain, restore,
//! window recovery, export, the secret scan switch, registering and rotating a
//! secret, the vault key's wraps, importing history, import consent,
//! agent-run consent and legal holds.
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

    /// How the backup's vault key unlocks: `device` (this install's
    /// keystore, from the device wrap the backup carries), `password`,
    /// `passkey`, `escrow` or `kit`. Every way but `device` needs `--trust`.
    /// Where no vault is yet, the restore makes it and wraps its key to this
    /// install.
    #[arg(long, value_enum, default_value_t = UnlockMethod::Device, conflicts_with = "activate")]
    pub unlock: UnlockMethod,

    /// With `--unlock passkey`: the passkey's credential name.
    #[arg(long, value_name = "NAME")]
    pub credential: Option<String>,

    /// With `--unlock escrow`: the escrow wrap's label.
    #[arg(long, value_name = "NAME")]
    pub label: Option<String>,

    /// With `--unlock kit`: a world kit piece file, a recovery code as text
    /// or a piece export. Give two, or one and the kit passphrase, read from
    /// stdin or `--secret-file`.
    #[arg(long = "piece", value_name = "FILE")]
    pub pieces: Vec<PathBuf>,

    /// With `--unlock kit`: the vault id the kit is bound to, 64 hex digits,
    /// as `oneiron recovery-kit status` prints it.
    #[arg(long, value_name = "HEX")]
    pub vault_id: Option<String>,

    /// Trust exactly the checkpoint signers in this file, in place of this
    /// install's: `oneiron vault-key signer` prints one on a host that holds
    /// the vault. A backup's own head is never trusted.
    #[arg(long, value_name = "FILE", conflicts_with = "activate")]
    pub trust: Option<PathBuf>,

    /// Print what the backup's head says unlocks it, with each passkey's PRF
    /// input, and restore nothing.
    #[arg(long, conflicts_with_all = ["activate", "rehearse"])]
    pub inspect: bool,

    #[command(flatten)]
    pub secret: SecretSourceArgs,

    #[command(flatten)]
    pub serve: ServeArgs,
}

/// How a backup's vault key unlocks.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
pub enum UnlockMethod {
    /// This install's keystore, from the device wrap the backup carries.
    #[default]
    Device,
    /// The vault password.
    Password,
    /// A passkey's PRF output at the input `--inspect` prints.
    Passkey,
    /// An escrow recipient's seed, from a recovery box or as a secret.
    Escrow,
    /// The world recovery kit: its root opens the `world-kit` escrow wrap.
    Kit,
}

/// Where a secret is read, and the recovery box that keeps escrow seeds. A
/// secret is read from stdin unless a file is named, exactly as given but
/// for one trailing line break; a PRF output or a seed is 32 bytes, raw, hex
/// or base64url.
#[derive(Args, Clone, Debug, Default)]
pub struct SecretSourceArgs {
    /// Read the secret from this file, which only its owner may read.
    #[arg(long, value_name = "FILE", conflicts_with_all = ["box_dir", "box_command"])]
    pub secret_file: Option<PathBuf>,

    /// A recovery box that is a directory the owner holds: removable media,
    /// or a self-hoster's own box. Seeds rest there owner-only.
    #[arg(long, value_name = "DIR", conflicts_with = "box_command")]
    pub box_dir: Option<PathBuf>,

    /// A recovery box that is a program: `PROGRAM store <vault> <label>`
    /// keeps the seed it reads on stdin, `PROGRAM release <vault> <label>`
    /// prints it after its own sign-in.
    #[arg(long, value_name = "PROGRAM")]
    pub box_command: Option<PathBuf>,
}

/// A stopped vault's data key and the wraps that unlock it.
#[derive(Subcommand, Clone, Debug)]
pub enum VaultKeyCommand {
    /// Whether the vault has a data key, and its wraps.
    Status(Box<VaultKeyArgs>),
    /// This install's checkpoint signer: the pin another host trusts this
    /// vault's backups by (`oneiron restore --trust`).
    Signer(Box<VaultKeyArgs>),
    /// The PRF input a passkey is asked for its output at.
    PrfInput(Box<VaultKeyNamedArgs>),
    /// Set the vault password, read as a secret; it replaces an earlier one.
    SetPassword(Box<VaultKeyArgs>),
    /// Wrap the key to a passkey by its PRF output, read as a secret.
    AddPasskey(Box<VaultKeyNamedArgs>),
    /// Seal the key to a new escrow recipient whose seed a recovery box keeps.
    AddEscrow(Box<VaultKeyNamedArgs>),
    /// Wrap the key to this install's keystore.
    AddDevice(Box<VaultKeyArgs>),
    /// Remove one wrap by its id (`password`, `passkey:<name>`, ...); the
    /// last one stays.
    Remove(Box<VaultKeyNamedArgs>),
}

#[derive(Args, Clone, Debug)]
pub struct VaultKeyArgs {
    #[command(flatten)]
    pub secret: SecretSourceArgs,

    #[command(flatten)]
    pub serve: ServeArgs,
}

#[derive(Args, Clone, Debug)]
pub struct VaultKeyNamedArgs {
    /// The passkey's credential name, the escrow wrap's label (1 to 64
    /// letters, digits, dots, dashes or underscores), or the wrap's id.
    pub name: String,

    #[command(flatten)]
    pub secret: SecretSourceArgs,

    #[command(flatten)]
    pub serve: ServeArgs,
}

#[derive(Args, Clone, Debug)]
pub struct RecoverWindowArgs {
    /// The sync window: `YYYY-MM`, or `YYYY-MM@<world id>`.
    pub window: String,

    /// Also re-bootstrap the window (a pathological history): its CRDT state
    /// becomes the rebuilt state with no history behind it, and every device
    /// behind it resyncs from a replacement. Refused while a legal hold names
    /// any row the window carries.
    #[arg(long)]
    pub rebootstrap: bool,

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
    /// Revoke a secret: the record goes terminal and every lease over it is
    /// revoked. Reads nothing from stdin.
    Revoke(Box<SecretRevokeArgs>),
    /// Sign a portable secret's current custody transition with your owner
    /// anchor, for an install that cannot sign as one of your machines. Reads
    /// your recovery kit from stdin, one recovery code per line; the kit
    /// never leaves this process, so the vault must be stopped.
    AnchorSign(Box<SecretAnchorSignArgs>),
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

#[derive(Args, Clone, Debug)]
pub struct SecretRevokeArgs {
    /// The secret's custody name.
    #[arg(long)]
    pub name: String,

    #[command(flatten)]
    pub serve: ServeArgs,
}

#[derive(Args, Clone, Debug)]
pub struct SecretAnchorSignArgs {
    /// The secret's custody name.
    #[arg(long)]
    pub name: String,

    /// The kit has a passphrase piece: the first line of stdin is the kit
    /// passphrase, and one recovery code then opens it.
    #[arg(long)]
    pub with_passphrase: bool,

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
    /// A folder of markdown notes that stays attached (OF-554): its new
    /// files land, changed files supersede what they landed and removed
    /// files retract theirs (archived, never erased). Nothing is written to
    /// the folder.
    #[command(subcommand)]
    Folder(ImportFolderCommand),
}

#[derive(Subcommand, Clone, Debug)]
pub enum ImportFolderCommand {
    /// Attach a folder and land its notes; `oneiron serve` rescans it every
    /// few minutes from then on.
    Attach(Box<ImportFolderAttachArgs>),
    /// Rescan one attached folder now, or every attached folder.
    Rescan(Box<ImportFolderRescanArgs>),
    /// Detach a folder: no rescan reads it again. Its notes stay.
    Detach(Box<ImportFolderPathArgs>),
    /// Every attached folder, with its ledger's counts.
    List(Box<ImportFolderListArgs>),
}

#[derive(Args, Clone, Debug)]
pub struct ImportFolderAttachArgs {
    /// The folder. Only this path is read: symbolic links and hidden entries
    /// under it are skipped.
    pub path: PathBuf,

    /// Only notes whose path under the folder matches (`*` within a name,
    /// `**` across folders, `?` one character). Repeatable; none is every
    /// markdown file.
    #[arg(long)]
    pub include: Vec<String>,

    /// The note kind of a note whose frontmatter `type` names no kind the
    /// vault knows.
    #[arg(long, default_value = "observation")]
    pub kind: String,

    #[command(flatten)]
    pub serve: ServeArgs,
}

#[derive(Args, Clone, Debug)]
pub struct ImportFolderRescanArgs {
    /// The attached folder; none rescans every attached folder.
    pub path: Option<PathBuf>,

    #[command(flatten)]
    pub serve: ServeArgs,
}

#[derive(Args, Clone, Debug)]
pub struct ImportFolderPathArgs {
    /// The attached folder.
    pub path: PathBuf,

    #[command(flatten)]
    pub serve: ServeArgs,
}

#[derive(Args, Clone, Debug)]
pub struct ImportFolderListArgs {
    #[command(flatten)]
    pub serve: ServeArgs,
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
pub enum GuestsCommand {
    /// Withdraw one ask guest's access at this host: its grant is deleted
    /// and each live pact it governs is disconnected, signed with the
    /// config's host key. What the guest already synced stays the guest's.
    Revoke(Box<GuestRevokeArgs>),
}

#[derive(Args, Clone, Debug)]
pub struct GuestRevokeArgs {
    /// The guest's grant, 32 hex.
    pub grant_ref: String,

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

/// Your embedding spaces (OF-370) on a stopped vault. A running server
/// answers the same at `/v1/owner/embedding-spaces`, and only it checks a
/// move, since the check runs its own probe towers:
/// `oneiron api raw POST /v1/owner/embedding-spaces/move/check --data
/// '{"candidate": "..."}'`.
#[derive(Subcommand, Clone, Debug)]
pub enum EmbeddingSpacesCommand {
    /// Every declared space, the text index, the space each kind slot
    /// reads, every move with its last check, and the probes per kind.
    List(Box<ServeOnlyArgs>),
    /// Declare or widen one space. A new width is a new space.
    Declare(Box<EmbeddingSpaceDeclareArgs>),
    /// Bind one kind slot to a declared space, or with no space return it to
    /// its default.
    Bind(Box<EmbeddingSpaceBindArgs>),
    /// Bind every kind slot the space accepts, text included, to it.
    OneSpace(Box<EmbeddingSpaceArgs>),
    /// Drop a space no slot binds and no open move names, with its rows.
    Retire(Box<EmbeddingSpaceArgs>),
    /// Start moving every slot the incumbent serves to the candidate. The
    /// next `serve` fills the candidate and checks it on its own.
    Move(Box<EmbeddingSpaceMoveArgs>),
    /// Swap a full candidate in on your yes, over a check that did not read
    /// not worse.
    MoveApprove(Box<EmbeddingSpaceCandidateArgs>),
    /// Bind a swapped-in move's incumbent again.
    MoveUndo(Box<EmbeddingSpaceCandidateArgs>),
    /// End an open move with no swap.
    MoveAbandon(Box<EmbeddingSpaceCandidateArgs>),
    /// The probes a move's check runs: list, store or remove one.
    #[command(subcommand)]
    Probes(EmbeddingSpaceProbesCommand),
}

/// An input kind a slot, a space or a probe names.
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum EmbeddingKind {
    Text,
    Image,
    Audio,
}

#[derive(Args, Clone, Debug)]
pub struct EmbeddingSpaceDeclareArgs {
    /// The space id: an `ai.embed` rung id, then `@where`.
    pub id: String,

    /// The space's dimensions.
    #[arg(long)]
    pub width: usize,

    /// The inputs its model embeds as documents, comma separated.
    #[arg(long, value_delimiter = ',', required = true)]
    pub accepts: Vec<EmbeddingKind>,

    /// The query kinds its model can encode into it, comma separated.
    #[arg(long, value_delimiter = ',')]
    pub query_towers: Vec<EmbeddingKind>,

    /// The similarity floor of this space's raw cosines; give it with
    /// `--strong`. Without both, the vault's own floors judge the space.
    #[arg(long, requires = "strong")]
    pub floor: Option<f32>,

    /// The score of a strong match in this space; give it with `--floor`.
    #[arg(long, requires = "floor")]
    pub strong: Option<f32>,

    #[command(flatten)]
    pub serve: ServeArgs,
}

#[derive(Args, Clone, Debug)]
pub struct EmbeddingSpaceBindArgs {
    /// The kind slot.
    #[arg(value_enum)]
    pub kind: EmbeddingKind,

    /// The declared space; leave it out to return the slot to its default.
    pub space: Option<String>,

    #[command(flatten)]
    pub serve: ServeArgs,
}

#[derive(Args, Clone, Debug)]
pub struct EmbeddingSpaceArgs {
    /// The declared space's id.
    pub space: String,

    #[command(flatten)]
    pub serve: ServeArgs,
}

#[derive(Args, Clone, Debug)]
pub struct EmbeddingSpaceMoveArgs {
    /// The space to move to.
    pub candidate: String,

    /// The declared space it replaces; leave it out for the text index.
    #[arg(long)]
    pub incumbent: Option<String>,

    /// A tolerance stricter than the measured retest noise.
    #[arg(long)]
    pub margin: Option<f32>,

    #[command(flatten)]
    pub serve: ServeArgs,
}

#[derive(Args, Clone, Debug)]
pub struct EmbeddingSpaceCandidateArgs {
    /// The move's candidate space.
    pub candidate: String,

    #[command(flatten)]
    pub serve: ServeArgs,
}

#[derive(Subcommand, Clone, Debug)]
pub enum EmbeddingSpaceProbesCommand {
    /// Every stored probe with its id.
    List(Box<ServeOnlyArgs>),
    /// Store one probe you wrote.
    Put(Box<EmbeddingSpaceProbePutArgs>),
    /// Remove one probe by its id.
    Delete(Box<EmbeddingSpaceProbeDeleteArgs>),
}

#[derive(Args, Clone, Debug)]
pub struct EmbeddingSpaceProbePutArgs {
    /// The kind of the documents it finds.
    #[arg(long, value_enum)]
    pub kind: EmbeddingKind,

    /// The query.
    #[arg(long)]
    pub query: String,

    /// The document the query was written from, 32 hex.
    #[arg(long, value_name = "HEX")]
    pub family: String,

    /// Another document that answers it, 32 hex. Repeat for more.
    #[arg(long = "target", value_name = "HEX")]
    pub targets: Vec<String>,

    /// Who wrote the query.
    #[arg(long)]
    pub author: String,

    #[command(flatten)]
    pub serve: ServeArgs,
}

#[derive(Args, Clone, Debug)]
pub struct EmbeddingSpaceProbeDeleteArgs {
    /// The probe's id, 32 hex, as `probes list` names it.
    pub id: String,

    #[command(flatten)]
    pub serve: ServeArgs,
}
