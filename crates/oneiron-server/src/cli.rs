use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

use crate::commands;
use crate::config::ServeArgs;

mod deployment_args;
pub use deployment_args::HostRelayArgs;
mod hook_args;
mod owner_args;
mod wake_args;
pub use hook_args::{
    HookArgs, HookBindArgs, HookCommonArgs, HookEffort, HookEvent, HookHandOverArgs, HookHost,
    HookRecallArgs,
};
pub use owner_args::{
    BackupArgs, DoctorArgs, ExportArgs, HandoffAlarmAckArgs, HandoffAlarmsCommand,
    ImportArchiveArgs, ImportBatchArgs, ImportCommand, ImportDecisionArgs, ImportFolderAttachArgs,
    ImportFolderCommand, ImportFolderListArgs, ImportFolderPathArgs, ImportFolderRescanArgs,
    ImportNotesArgs, ImportSourceArgs, MaintainArgs, RecoverClockArgs, RecoverWindowArgs,
    RestoreArgs, RunArgs, RunDecisionArgs, RunsCommand, SecretClass, SecretRegisterArgs,
    SecretRotateArgs, SecretScanArgs, SecretScanSwitch, SecretsCommand, ServeOnlyArgs, WhoamiArgs,
};
pub use owner_args::{GuestRevokeArgs, GuestsCommand, SecretRevokeArgs};
pub use owner_args::{
    LegalHoldLiftArgs, LegalHoldPlaceArgs, LegalHoldTargetArgs, LegalHoldWidenArgs,
    LegalHoldsCommand, SecretSourceArgs, UnlockMethod, VaultKeyArgs, VaultKeyCommand,
    VaultKeyNamedArgs,
};
pub use wake_args::{WakeArgs, WakeCommand};

const DEFAULT_SERVER_DIMENSIONS: usize = 4096;
const DEFAULT_SERVER_MAP_SIZE: usize = 1 << 33;

#[derive(Parser)]
#[command(
    about = "Oneiron local sync daemon",
    version,
    propagate_version = true,
    args_conflicts_with_subcommands = true
)]
pub struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    #[command(flatten)]
    serve: ServeArgs,
}

#[derive(Subcommand)]
pub enum Command {
    /// Run the Oneiron sync daemon.
    ///
    /// `--managed-by-hypnos` (plus its argv group) switches the daemon into
    /// managed serve mode, where it runs as a supervised child process. The
    /// flags ride [`ServeArgs`] so both the bare and the explicit `serve`
    /// forms accept them; the mode is selected in `commands::serve`.
    Serve(Box<ServeArgs>),
    /// Revoke an existing device lease binding.
    Revoke(Box<RevokeArgs>),
    /// Print or locate the agentskills-compatible skill pack.
    SkillsPack(SkillsPackArgs),
    /// Create a vault and print its doctor report.
    Init(InitArgs),
    /// Open a vault and print its doctor report, with where its data lives:
    /// path, size on disk, last backup and last export.
    Doctor(DoctorArgs),
    /// Print a stopped vault's owner principal and its vault id.
    Whoami(Box<WhoamiArgs>),
    /// Back up a stopped vault now (`--list` shows its backups).
    Backup(Box<BackupArgs>),
    /// Run a stopped vault's housekeeping now, every sweep, and any repair
    /// named; print the report. A running `serve` sweeps on its own.
    Maintain(Box<MaintainArgs>),
    /// Restore a backup over a stopped vault, or `--rehearse` it in a
    /// scratch copy without touching the vault.
    Restore(Box<RestoreArgs>),
    /// Rebuild one sync window of a stopped vault from a canonical snapshot
    /// of its CRDT state, repairing its rows. The snapshot stays in memory
    /// and never touches disk; only the window's manifest is kept.
    RecoverWindow(Box<RecoverWindowArgs>),
    /// Let agents back in after the host clock ran ahead and was set back:
    /// on a stopped vault, move the clock holder proofs are judged on back
    /// to the host's clock, and refuse every proof signed before now.
    RecoverClock(Box<RecoverClockArgs>),
    /// Export the whole vault in one of five formats.
    Export(Box<ExportArgs>),
    /// Turn the write-door secret scan on or off, or show it.
    SecretScan(Box<SecretScanArgs>),
    /// Register a secret in a stopped vault's custody, or rotate one. The
    /// value is read from stdin.
    #[command(subcommand)]
    Secrets(SecretsCommand),
    /// A stopped vault's data key: its wraps (password, passkey, escrow,
    /// device), this install's checkpoint signer and a passkey's PRF input.
    #[command(subcommand)]
    VaultKey(VaultKeyCommand),
    /// Import your own history into a stopped vault (ChatGPT and Claude.ai
    /// exports, Claude Code and Codex sessions, a Copilot or Cursor hook
    /// transcript, a folder of markdown notes), or preview, approve or decline
    /// one whole import batch.
    #[command(subcommand)]
    Import(ImportCommand),
    /// Agent runs waiting for consent: list, review, approve or decline whole.
    #[command(subcommand)]
    Runs(RunsCommand),
    /// Fork alarms a held root handoff left: list them, or acknowledge one.
    #[command(subcommand)]
    HandoffAlarms(HandoffAlarmsCommand),
    /// Your legal holds: place, widen, list, read the log, or lift one
    /// through the "Lift the hold and erase?" confirm.
    #[command(subcommand)]
    LegalHolds(LegalHoldsCommand),
    /// Your ask guests at this host: revoke one's access.
    #[command(subcommand)]
    Guests(GuestsCommand),
    /// Move a stopped vault to the configured embedding model: repin it and
    /// queue every record to be embedded again, which the next `serve` does.
    Reembed(Box<ReembedArgs>),
    /// Resolve repo commit provenance trailers against a vault claim.
    Provenance(Box<ProvenanceArgs>),
    /// Create pairing links and revoke slips.
    #[command(subcommand)]
    Token(TokenCommand),
    /// Make short curl-shaped calls against the existing HTTP API.
    Api(ApiArgs),
    /// Serve MCP on stdio for an agent that spawns a command (Claude Code,
    /// Codex), forwarding each message to a running server with a paired
    /// credential and a fresh holder proof.
    Mcp(McpArgs),
    /// Run one agent-harness hook: read the host's event on stdin, bind a
    /// vault (a pin, a running local vault, else start one), recall for the
    /// session or the prompt, or queue the session's log. Always exits 0
    /// once parsed; a mistyped command exits 1, never 2.
    Hook(HookArgs),
    /// Read or acknowledge a host instance wake inbox.
    Wake(WakeArgs),
    /// Scaffold a self-host node from the shipped deployment templates.
    #[command(subcommand)]
    Host(HostCommand),
    /// Owner acts for the vault's Dreamer.
    #[command(subcommand)]
    Dreamer(DreamerCommand),
    /// Run this host's local embedder for other vaults.
    #[command(subcommand)]
    Embedder(EmbedderCommand),
    /// The tagger's offline handoff with the model project: distillation
    /// jobs from the approved teacher, student receipts, and publishing.
    #[command(subcommand)]
    Oneironer(commands::OneironerCommand),
    /// Official subscription seats: where a vendor login may run and what
    /// you run to sign one in. Never takes or shows a vendor token.
    #[command(subcommand)]
    Seat(SeatCommand),
}

#[derive(Subcommand)]
pub enum SeatCommand {
    /// List every seat route with its placement on your own runtime and on
    /// an Oneiron-hosted one (no vendor approvals assumed).
    Routes,
    /// Print the sign-in plan for one seat: placement verdict, the login you
    /// run yourself, and what the seat does when its plan window is dry.
    LoginPlan(Box<SeatLoginPlanArgs>),
}

#[derive(Args, Clone, Debug)]
pub struct SeatLoginPlanArgs {
    /// Seat route label (see `seat routes`).
    #[arg(long)]
    pub route: String,
    /// Your own label for the account. A label only, never a credential.
    #[arg(long)]
    pub account: String,
    /// Runtime mode the seat would run under.
    #[arg(long, default_value = "local_free")]
    pub mode: crate::runtime::RuntimeMode,
    /// Which of your machines holds the login.
    #[arg(long)]
    pub machine: Option<String>,
    /// Where the vendor's own login store lives on that machine.
    #[arg(long = "login-store")]
    pub login_store: Option<String>,
    /// Custody handle name for endpoint-shaped seats.
    #[arg(long = "credential-handle")]
    pub credential_handle: Option<String>,
    /// Say the vendor binary is modified. A Claude login seat then refuses:
    /// the hosting permission covers the unmodified binary only.
    #[arg(long = "modified-binary")]
    pub modified_binary: bool,
    /// Anthropic has approved offering a Claude.ai login via the Agent SDK.
    #[arg(long = "anthropic-sdk-approved")]
    pub anthropic_sdk_approved: bool,
    /// OpenAI has approved hosted ChatGPT-plan use.
    #[arg(long = "openai-hosted-approved")]
    pub openai_hosted_approved: bool,
    /// What a dry seat does: park (default), continue_on_local, overdraft.
    #[arg(long, default_value = "park")]
    pub dry: String,
    /// Spend cap units when --dry is overdraft. Zero parks instead.
    #[arg(long = "overdraft-cap", default_value_t = 0)]
    pub overdraft_cap: u64,
    /// Plan-window percent already used, when known.
    #[arg(long = "plan-percent-used")]
    pub plan_percent_used: Option<u8>,
    /// Plan-window reset (epoch seconds), when known.
    #[arg(long = "plan-resets-at")]
    pub plan_resets_at: Option<u64>,
    /// Judge dryness at this epoch second instead of the host clock.
    #[arg(long, default_value_t = 0)]
    pub now: u64,
    /// Sign in with ChatGPT: our app registration's client id.
    #[arg(long = "siwc-client-id")]
    pub siwc_client_id: Option<String>,
    /// Sign in with ChatGPT: the registered redirect URI.
    #[arg(long = "siwc-redirect-uri")]
    pub siwc_redirect_uri: Option<String>,
    /// Sign in with ChatGPT: your PKCE verifier. Only its S256 challenge is
    /// printed, inside the authorize URL; the verifier is never stored.
    #[arg(long = "siwc-verifier")]
    pub siwc_verifier: Option<String>,
    /// Sign in with ChatGPT: OAuth state value.
    #[arg(long = "siwc-state")]
    pub siwc_state: Option<String>,
    /// Sign in with ChatGPT: OAuth scope, when the registration asks for one.
    #[arg(long = "siwc-scope")]
    pub siwc_scope: Option<String>,
}

#[derive(Subcommand)]
pub enum EmbedderCommand {
    /// Serve the local embedding model over an OpenAI-compatible
    /// `/v1/embeddings` for vaults on the `endpoint` provider to share: one
    /// model in memory for all of them, on a GPU where the build has one.
    /// Point a vault at it with `init --embedder endpoint --embedder-endpoint
    /// http://127.0.0.1:7399/v1` and the model id this prints; its vectors are
    /// the ones a local vault makes.
    Serve(Box<EmbedderServeArgs>),
}

#[derive(Args, Clone)]
pub struct EmbedderServeArgs {
    /// Config file whose `[embedder]` section names the model, as `serve
    /// --config` reads it. With neither this, `ONEIRON_CONFIG`, the XDG
    /// config nor `--embedder-*` flags, the default local model.
    #[arg(long)]
    pub config: Option<PathBuf>,
    /// `--embedder-*` flags, as `serve` takes them: repository, revision,
    /// device, quantisation, input cap.
    #[command(flatten)]
    pub embedder: crate::config::EmbedderArgs,
    /// Vault width the `[embedder]` section is checked against, as `serve`
    /// checks it.
    #[arg(long)]
    pub dimensions: Option<usize>,
    /// Address to listen on. Anything but loopback needs `--api-key-env`.
    #[arg(long, default_value = "127.0.0.1")]
    pub host: std::net::IpAddr,
    #[arg(long, default_value_t = 7399)]
    pub port: u16,
    /// Environment variable NAME holding the key every request must send as
    /// a bearer token. Never the key itself.
    #[arg(long)]
    pub api_key_env: Option<String>,
    /// Another name a request's `model` may give, beside the model id.
    #[arg(long = "model-alias")]
    pub model_aliases: Vec<String>,
    #[arg(long, default_value = "info")]
    pub log_level: String,
}

#[derive(Subcommand)]
pub enum DreamerCommand {
    /// Give a vault created before the Dreamer's policy rows shipped the
    /// rows a fresh vault seeds, so its Dreamer can read the vault and land
    /// routine consolidation (run once, with the server stopped; a vault that
    /// has them is left as it is). `--extraction-route` also routes the
    /// vault's extraction defaults.
    Grant(Box<DreamerGrantArgs>),
}

#[derive(Args, Clone)]
pub struct DreamerGrantArgs {
    /// Also route the vault's extraction and consolidation defaults to this
    /// locality (`own_server` for a model server you run, `third_party` for a
    /// hosted API), raising the extraction bound to it if lower. Omit to leave
    /// the vault's inference defaults as they are.
    #[arg(long, value_parser = parse_route)]
    pub extraction_route: Option<oneiron::ModelLocality>,

    #[command(flatten)]
    pub serve: ServeArgs,
}

fn parse_route(value: &str) -> Result<oneiron::ModelLocality, String> {
    match value {
        "own_server" => Ok(oneiron::ModelLocality::OwnServer),
        "third_party" => Ok(oneiron::ModelLocality::ThirdParty),
        other => Err(format!("{other:?} is not own_server or third_party")),
    }
}

#[derive(Subcommand)]
pub enum HostCommand {
    Init(HostInitArgs),
    /// Move a stopped self-host vault's root to a new host secret, in-chain:
    /// the vault id stays, and every credential the old secret minted stops
    /// working. Run it after a host secret leaks, or to change it.
    ReRoot(Box<HostReRootArgs>),
    /// Run one vault as a Firecracker VM behind a unix socket: start it on
    /// the first connection or a due wake, and sleep it when idle.
    Vm(Box<HostVmArgs>),
    /// Run a blind iroh relay room and a ciphertext-only locker, never an engine.
    Relay(HostRelayArgs),
    /// Recover a shared vault's Owner on proof of control, on a stopped
    /// self-host vault: you judged the claimant's proof that they control
    /// the organization owning it, and this host's key signs the handover.
    /// A running `serve` answers the same at
    /// `/v1/operator/shared/recover-owner`, under the host's root credential.
    RecoverSharedOwner(Box<HostRecoverSharedOwnerArgs>),
}

#[derive(Args, Clone, Debug)]
pub struct HostVmArgs {
    /// JSON VM profile: firecracker, kernel, rootfs, vault_disk, state_dir,
    /// vcpus, mem_mib and optional boot_args and allowed_origins.
    #[arg(long)]
    pub config: PathBuf,
    #[arg(long)]
    pub vault_name: String,
    /// The unix socket clients connect to; each connection is proxied into
    /// the vault's HTTP surface.
    #[arg(long)]
    pub listen: PathBuf,
    /// Inherited descriptor carrying the 64-byte DEK and spawn-token frame.
    #[arg(long)]
    pub credentials_fd: i32,
    /// Seconds without traffic before the vault sleeps.
    #[arg(long, default_value_t = 300)]
    pub idle_secs: u64,
}

/// The current secret comes from `--secret-file`, the config or
/// `ONEIRON_AUTH_SECRET`; the new one from `--new-secret-file` or
/// `ONEIRON_NEW_AUTH_SECRET`. Neither is read from argv or printed.
#[derive(Args, Clone, Debug)]
pub struct HostReRootArgs {
    /// Read the current host secret from this file, readable by its owner
    /// only, instead of the config or `ONEIRON_AUTH_SECRET`.
    #[arg(long, value_name = "FILE")]
    pub secret_file: Option<PathBuf>,

    /// Read the new host secret from this file, readable by its owner only,
    /// instead of `ONEIRON_NEW_AUTH_SECRET`.
    #[arg(long, value_name = "FILE")]
    pub new_secret_file: Option<PathBuf>,

    #[command(flatten)]
    pub serve: ServeArgs,
}

/// The host secret comes from the config or `ONEIRON_AUTH_SECRET`, never argv.
#[derive(Args, Clone, Debug)]
pub struct HostRecoverSharedOwnerArgs {
    /// The shared vault, by the id its creation named.
    #[arg(long)]
    pub vault_id: u64,

    /// The Owner who is gone, PERSON id hex: still holding the Owner role.
    #[arg(long)]
    pub from: String,

    /// The person taking the Owner role, PERSON id hex: a live person.
    #[arg(long)]
    pub claimant: String,

    /// The proof of control you judged. The engine keeps no note; its BLAKE3
    /// is printed beside the receipt id for your own record.
    #[arg(long)]
    pub proof_note: String,

    #[command(flatten)]
    pub serve: ServeArgs,
}

#[derive(Args, Clone, Debug)]
pub struct HostInitArgs {
    /// New output directory; existing nodes are never overwritten.
    pub path: PathBuf,
    /// Executable encryption provisioning hook. Receives the output directory
    /// as its only argument, with no shell interpolation. A failure aborts init.
    #[arg(long)]
    pub encryption_hook: Option<PathBuf>,
}

#[derive(Subcommand)]
pub enum TokenCommand {
    /// Provision the first owner link while the self-host vault is stopped.
    Bootstrap(Box<TokenBootstrapArgs>),
    /// Create a one-hour pairing link on the running server and print it.
    Pair(Box<TokenPairArgs>),
    /// Mint a read-only credential for a local agent on the stopped vault.
    Read(Box<TokenReadArgs>),
    /// Mint a scoped credential for one named agent (Claude Code, Codex) on
    /// the stopped vault, for `oneiron mcp`.
    Agent(Box<TokenAgentArgs>),
    /// Revoke one previously minted token by its id.
    Revoke(Box<TokenRevokeArgs>),
}

/// Local-only bootstrap: the vault is opened exclusively from the host's
/// configured path. No issuer secret is sent over HTTP or printed.
#[derive(Args, Clone, Debug)]
pub struct TokenBootstrapArgs {
    /// Origin clients will contact after `serve` starts. The default is
    /// where `oneiron serve` listens unless told otherwise.
    #[arg(long, env = "ONEIRON_URL", default_value = "http://127.0.0.1:9090")]
    pub url: String,

    /// Optional shrink-only lifetime for the first owner slip (seconds).
    #[arg(long)]
    pub lifetime_secs: Option<u64>,

    #[command(flatten)]
    pub serve: ServeArgs,
}

/// Pairing is the only enrollment. The owner fixes the holder, the class and
/// the verbs here; whoever redeems the link chooses only the connection key.
#[derive(Args, Clone, Debug)]
pub struct TokenPairArgs {
    /// The running server's origin. The link carries it. The default is
    /// where `oneiron serve` listens unless told otherwise.
    #[arg(long, env = "ONEIRON_URL", default_value = "http://127.0.0.1:9090")]
    pub url: String,

    /// Environment variable holding a logged owner-grade capability slip.
    #[arg(long, default_value = "ONEIRON_TOKEN")]
    pub token_env: String,

    /// Environment variable holding its Ed25519 binding seed (64 hex chars).
    /// Neither credential reaches curl's argv.
    #[arg(long, default_value = "ONEIRON_BINDING_KEY")]
    pub binding_key_env: String,

    /// Verbs the paired slip carries, comma-separated (e.g.
    /// `core:read,core:write`). Omit for every verb.
    #[arg(long, value_delimiter = ',', num_args = 1..)]
    pub scope: Option<Vec<String>>,

    /// The principal the paired slip is for, as 32 lowercase hex characters.
    #[arg(long = "principal-ref")]
    pub principal_ref: String,

    /// D13 actor class the slip binds write identity to: `human`, `agent`,
    /// or `system`. Required by `/v1/core/facade` routes; absent by default.
    #[arg(long = "actor-class")]
    pub actor_class: Option<String>,

    /// The paired slip's lifetime in seconds.
    #[arg(long = "lifetime-secs", default_value_t = 365 * 24 * 60 * 60)]
    pub lifetime_secs: u64,
}

/// A local agent's read credential, minted through the same host-rooted
/// pairing doors as `bootstrap` while the vault is stopped. The issuer key
/// comes from the config or `ONEIRON_AUTH_SECRET`, never argv.
#[derive(Args, Clone, Debug)]
pub struct TokenReadArgs {
    /// The principal the credential reads as: a 32-hex id or a short ref.
    /// Defaults to the vault's owner (`oneiron whoami`).
    #[arg(long = "principal-ref")]
    pub principal_ref: Option<String>,

    /// D13 actor class the credential binds: `human`, `agent` or `system`.
    /// The owner reads its whole vault as `human`.
    #[arg(long = "actor-class", default_value = "human")]
    pub actor_class: String,

    /// The credential's lifetime in seconds, capped by the vault's policy.
    #[arg(long = "lifetime-secs", default_value_t = 30 * 24 * 60 * 60)]
    pub lifetime_secs: u64,

    #[command(flatten)]
    pub serve: ServeArgs,
}

/// A named agent's credential: a paired slip for the agent's own principal,
/// class `agent`, carrying at most read, propose and write. Never owner-grade;
/// `token revoke` takes the slip id it prints.
#[derive(Args, Clone, Debug)]
pub struct TokenAgentArgs {
    /// The agent's name, e.g. `claude-code`. One name is one agent principal,
    /// however many times it is minted.
    #[arg(long)]
    pub name: String,

    /// What the agent may do. The latest mint for a name holds: it sets that
    /// agent's tier and revokes the agent's earlier slips.
    #[arg(long, value_enum, default_value_t = AgentTier::FullAccess)]
    pub tier: AgentTier,

    /// The credential's lifetime in seconds, capped by the vault's policy.
    #[arg(long = "lifetime-secs", default_value_t = 30 * 24 * 60 * 60)]
    pub lifetime_secs: u64,

    /// Write the credential to this new file, readable by its owner only, and
    /// print only its slip id and principal. Without it the credential is
    /// printed.
    #[arg(long, value_name = "FILE")]
    pub out: Option<PathBuf>,

    #[command(flatten)]
    pub serve: ServeArgs,
}

/// ARCH-0028's registration-time authority tiers for an agent.
#[derive(Clone, Copy, Debug, Eq, PartialEq, clap::ValueEnum)]
pub enum AgentTier {
    /// Retrieve and inspect; no write capability.
    ReadOnly,
    /// Write capability at ceiling `proposed`: what it writes waits for the
    /// owner's review. It proposes (`core:propose`) and holds no `core:write`,
    /// so no write door that cannot hold a write for review admits it.
    ProposeOnly,
    /// Write capability at ceiling `auto`: its writes land through the same
    /// write gate as the owner's.
    FullAccess,
}

/// Revoking one token is an explicit act on one named identity. It is
/// deliberately not a side effect of rotation: rotation rewraps the MAC key
/// and invalidates every token at once, which is the other lever.
#[derive(Args, Clone, Debug)]
pub struct TokenRevokeArgs {
    /// Token id (`jti`) to revoke, as 32 lowercase hex characters. It is
    /// carried in the token's visible claims.
    #[arg(long)]
    pub jti: String,

    #[command(flatten)]
    pub serve: ServeArgs,
}

/// `oneiron api …` is a curl-shaped façade over the routes this server already
/// serves. It registers no endpoint, carries no second authority model, and
/// interprets no response: the same bearer credential, the same request/error
/// envelope, and the same body bytes the server sent.
#[derive(Args, Clone, Debug)]
pub struct ApiArgs {
    /// Existing Oneiron server root. The default is where `oneiron serve`
    /// listens unless told otherwise.
    #[arg(long, env = "ONEIRON_URL", default_value = "http://127.0.0.1:9090")]
    pub base_url: String,

    /// Environment variable holding a bearer slip. The credential is never
    /// a positional argument, never printed, and never reaches curl's argv.
    /// When the variable is unset the request carries no `Authorization`
    /// header at all, which is what a public route and an
    /// `allow_unauthenticated` server answer.
    #[arg(long, default_value = "ONEIRON_SECRET")]
    pub secret_env: String,

    /// Environment variable with the Ed25519 binding seed for a slip bearer.
    #[arg(long, default_value = "ONEIRON_BINDING_KEY")]
    pub binding_key_env: String,

    #[command(subcommand)]
    pub command: ApiCommand,
}

/// Four short commands over existing routes plus one escape hatch. `raw` is
/// what keeps this family from growing into a second hand-maintained route
/// catalog: anything not shaped below is still one `raw METHOD PATH` away.
#[derive(Subcommand, Clone, Debug, PartialEq, Eq)]
pub enum ApiCommand {
    /// GET the vault capability discovery document.
    Discover,
    /// GET the BM25 text-search route.
    Search {
        /// Query text; percent-encoded into the query string.
        query: String,

        /// Maximum hits to return; the server's own default applies when
        /// omitted.
        #[arg(long)]
        limit: Option<u32>,
    },
    /// GET one entity by id.
    Get {
        /// Entity id; percent-encoded into the path.
        entity_id: String,
    },
    /// POST one core memory verb.
    Call {
        /// Verb name; percent-encoded into the path.
        verb: String,

        /// Request body: `@FILE` reads a file, `-` reads stdin, anything else
        /// is sent verbatim. No form is ever evaluated as shell text.
        #[arg(long, value_name = "@FILE|-|JSON")]
        data: String,
    },
    /// Send METHOD PATH against the same origin, unshaped.
    Raw {
        /// HTTP method, e.g. `GET` or `POST`.
        method: String,

        /// Absolute request path on the configured origin, e.g. `/api/health`.
        path: String,

        /// Request body: `@FILE`, `-` for stdin, or verbatim bytes.
        #[arg(long, value_name = "@FILE|-|JSON")]
        data: Option<String>,

        /// Media type for the body. A body defaults to `application/json`;
        /// naming a type replaces that default, which is how an unshaped wire
        /// protocol (`application/x-git-upload-pack-request`, say) is sent.
        #[arg(long, value_name = "MIME")]
        content_type: Option<String>,
    },
}

/// `oneiron mcp`: a stdio MCP server in front of a running server's MCP
/// endpoint. The endpoint is the operator's choice, made here in the agent's
/// MCP config, or else the server's; nothing the agent sends can change it.
#[derive(Args, Clone, Debug)]
pub struct McpArgs {
    /// The running server's origin. The default is where `oneiron serve`
    /// listens unless told otherwise.
    #[arg(long, env = "ONEIRON_URL", default_value = "http://127.0.0.1:9090")]
    pub url: String,

    /// Which MCP endpoint to forward to. Without it, the bridge asks the
    /// server at the first request: `primary` when this credential may run
    /// code there (a bound code host, and a credential `execute_code`
    /// admits), `tool-first` otherwise.
    #[arg(long, value_enum)]
    pub surface: Option<McpSurface>,

    /// File holding the paired credential, as `token agent --out` writes it.
    /// Only its owner may be able to read it. Without this flag the slip and
    /// its seed come from the two environment variables below.
    #[arg(long, value_name = "FILE")]
    pub credential_file: Option<PathBuf>,

    /// Run this instance's wake adapter while the MCP bridge is alive. The
    /// TOML file's parent is the harness config-dir instance. `inbox = true`
    /// uses `wake inbox`; otherwise helper, tmux and boot are tried in order.
    #[arg(long, value_name = "FILE")]
    pub wake_config: Option<PathBuf>,

    /// Environment variable holding the paired slip.
    #[arg(long, default_value = "ONEIRON_SECRET")]
    pub secret_env: String,

    /// Environment variable holding its binding seed (64 hex characters).
    #[arg(long, default_value = "ONEIRON_BINDING_KEY")]
    pub binding_key_env: String,

    /// Seconds one request may take, answer included, before it fails as
    /// `server_unreachable`.
    #[arg(long, default_value_t = 120, value_parser = clap::value_parser!(u64).range(1..))]
    pub request_timeout_secs: u64,

    /// Seconds an answer may stall once it has started arriving before the
    /// request fails as `server_unreachable`.
    #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u64).range(1..))]
    pub idle_timeout_secs: u64,
}

/// The two MCP endpoints a server registers.
#[derive(Clone, Copy, Debug, Eq, PartialEq, clap::ValueEnum)]
pub enum McpSurface {
    /// `/mcp/tool-first`: one tool per exported verb.
    ToolFirst,
    /// `/mcp`: the code-mode catalog (`setup_oneiron`, `execute_code`).
    Primary,
}

impl McpSurface {
    #[must_use]
    pub const fn path(self) -> &'static str {
        match self {
            Self::ToolFirst => "/mcp/tool-first",
            Self::Primary => "/mcp",
        }
    }
}

#[derive(Args, Clone, Debug)]
pub struct RevokeArgs {
    /// Client id to revoke, as 16 lowercase hexadecimal characters.
    #[arg(long)]
    pub client: String,

    #[command(flatten)]
    pub serve: ServeArgs,
}

#[derive(Args, Clone, Debug)]
pub struct SkillsPackArgs {
    /// Emit a JSON envelope with artifact path, media type, byte count, and Markdown content.
    #[arg(long, conflicts_with = "path")]
    pub json: bool,

    /// Print the repository-relative path to the committed skill pack artifact.
    #[arg(long)]
    pub path: bool,
}

#[derive(Args, Clone, Default)]
pub struct ReembedArgs {
    /// Drop every vector and queue every record again even when the vault
    /// already holds the configured model and embedding transform.
    #[arg(long)]
    pub force: bool,
    #[command(flatten)]
    pub serve: ServeArgs,
}

#[derive(Args, Clone, Debug, Default)]
pub struct InitArgs {
    /// Vault directory to create.
    pub path: PathBuf,
    /// Same config file that `serve --config` reads. Defaults to the XDG path.
    #[arg(long)]
    pub config: Option<PathBuf>,
    /// Choose local, endpoint, or none. Noninteractive omission selects none.
    #[arg(long)]
    pub embedder: Option<crate::config::EmbedderProvider>,
    #[arg(long)]
    pub embedder_endpoint: Option<String>,
    /// Endpoint locality. Non-loopback URLs default to third-party.
    #[arg(long)]
    pub embedder_locality: Option<crate::config::EmbedderLocality>,
    /// On-device endpoint serving the same model for remote fallback and queries.
    #[arg(long)]
    pub embedder_fallback_endpoint: Option<String>,
    /// Explicitly authorize all embeddable entities to use the remote endpoint.
    #[arg(long)]
    pub embedder_egress_allow_all: bool,
    /// Authorize only these entity IDs; all other rows stay on device.
    #[arg(long, value_delimiter = ',')]
    pub embedder_egress_allow: Vec<String>,
    /// Model key served by an OpenAI-compatible embedding endpoint.
    #[arg(long)]
    pub embedder_model_key: Option<String>,
    /// Pinned embedding space identity, model_id@revision.
    #[arg(long)]
    pub embedder_model_id: Option<String>,
    /// Environment variable NAME holding the key, not the key itself.
    #[arg(long)]
    pub embedder_api_key_env: Option<String>,
    #[arg(long)]
    pub dimensions: Option<usize>,
    #[arg(long, default_value_t = DEFAULT_SERVER_MAP_SIZE)]
    pub map_size: usize,
    #[arg(long = "dict-search-paths", value_delimiter = ',', num_args = 1..)]
    pub dict_search_paths: Option<Vec<PathBuf>>,
    /// Tagger: local, endpoint, or none. Noninteractive omission selects none.
    #[arg(long)]
    pub oneironer: Option<crate::config::OneironerProvider>,
    /// Base URL of a loopback tagger server.
    #[arg(long)]
    pub oneironer_url: Option<String>,
    /// The checkpoint the tagger must report (16 lowercase hex digits).
    #[arg(long)]
    pub oneironer_checkpoint_sha16: Option<String>,
    /// How many labels the tagger must report.
    #[arg(long)]
    pub oneironer_label_count: Option<u32>,
    /// `save` (the default) or `shadow`.
    #[arg(long)]
    pub oneironer_mode: Option<crate::config::OneironerMode>,
    /// The local tagger's model bundle: the directory holding `oneironer.json`.
    #[arg(long)]
    pub oneironer_model_dir: Option<PathBuf>,
    /// The local tagger's engine device: `auto` (the fastest that clears the
    /// bundle's parity bar), `cpu`, `metal` or `cuda`.
    #[arg(long)]
    pub oneironer_device: Option<crate::config::EmbedderDevice>,
    /// Name the local bundle as a tier (`tiny`, `medium`, ...): init writes
    /// it as `[oneironer.tiers.<label>]` and serves it with `oneironer.tier`,
    /// so more candidates can sit beside it.
    #[arg(long)]
    pub oneironer_tier: Option<String>,
}

#[derive(Args, Clone, Debug)]
pub struct VaultArgs {
    /// Path to the LMDB vault directory.
    pub path: PathBuf,

    /// Embedding vector dimension for the vault.
    #[arg(long, default_value_t = DEFAULT_SERVER_DIMENSIONS)]
    pub dimensions: usize,

    /// LMDB map size in bytes.
    #[arg(long, default_value_t = DEFAULT_SERVER_MAP_SIZE)]
    pub map_size: usize,

    /// Comma-separated trusted roots containing ja/ko/zh dictionary assets.
    #[arg(long = "dict-search-paths", value_delimiter = ',', num_args = 1..)]
    pub dict_search_paths: Option<Vec<PathBuf>>,
}

#[derive(Args, Clone, Debug)]
pub struct ProvenanceArgs {
    /// 40-hex commit SHA whose Oneiron provenance trailer should be resolved.
    #[arg(
        value_name = "SHA",
        conflicts_with = "claim_id",
        required_unless_present = "claim_id"
    )]
    pub sha: Option<String>,

    /// Resolve commits carrying this claim id instead of resolving a SHA.
    #[arg(
        long = "claim-id",
        conflicts_with = "sha",
        required_unless_present = "sha"
    )]
    pub claim_id: Option<String>,

    /// Path to the Git repository.
    #[arg(long = "repo-path", default_value = ".")]
    pub repo_path: PathBuf,

    /// Path to the LMDB vault directory.
    #[arg(long = "vault-path")]
    pub vault_path: PathBuf,

    /// Embedding vector dimension for the vault.
    #[arg(long, default_value_t = DEFAULT_SERVER_DIMENSIONS)]
    pub dimensions: usize,

    /// LMDB map size in bytes.
    #[arg(long, default_value_t = DEFAULT_SERVER_MAP_SIZE)]
    pub map_size: usize,

    /// Comma-separated trusted roots containing ja/ko/zh dictionary assets.
    #[arg(long = "dict-search-paths", value_delimiter = ',', num_args = 1..)]
    pub dict_search_paths: Option<Vec<PathBuf>>,

    /// Export the generated provenance mirror into refs/notes/oneiron-provenance.
    #[arg(long = "git-notes")]
    pub git_notes: bool,

    /// Include raw claim value, scope, and evidence payloads in the JSON output.
    #[arg(long = "include-payload")]
    pub include_payload: bool,
}

impl Cli {
    fn into_command(self) -> Command {
        self.command.unwrap_or(Command::Serve(Box::new(self.serve)))
    }
}

pub async fn run() -> anyhow::Result<()> {
    crate::logging::install_panic_hook();
    let cli = Cli::try_parse().unwrap_or_else(|error| {
        // Exit 2 from a hook blocks a compaction or keeps a turn from
        // ending, so a mistyped `oneiron hook` exits 1: the host shows it
        // as a hook error and goes on.
        if error.use_stderr() && std::env::args_os().nth(1).is_some_and(|arg| arg == "hook") {
            let _ = error.print();
            std::process::exit(1);
        }
        error.exit()
    });
    run_cli(cli).await
}

pub async fn run_cli(cli: Cli) -> anyhow::Result<()> {
    match cli.into_command() {
        Command::Serve(args) => commands::serve(*args).await,
        Command::Revoke(args) => commands::revoke(*args).await,
        Command::SkillsPack(args) => commands::skills_pack(args),
        Command::Init(args) => {
            crate::logging::off_runtime("init", move || commands::init(args)).await?
        }
        Command::Doctor(args) => commands::doctor(args),
        Command::Whoami(args) => commands::whoami(*args),
        Command::Backup(args) => commands::backup(*args),
        Command::Maintain(args) => commands::maintain(*args),
        Command::Restore(args) => commands::restore(*args),
        Command::RecoverWindow(args) => commands::recover_window(*args),
        Command::RecoverClock(args) => commands::recover_clock(*args),
        Command::Export(args) => commands::export(*args),
        Command::SecretScan(args) => commands::secret_scan(*args),
        // Revoke reads no value, so it never reaches the stdin read.
        Command::Secrets(SecretsCommand::Revoke(args)) => commands::revoke_secret(*args),
        Command::Secrets(command) => commands::secrets(command),
        Command::VaultKey(command) => commands::vault_key(command),
        Command::Import(command) => commands::import(command),
        Command::Runs(command) => commands::runs(command),
        Command::HandoffAlarms(command) => commands::handoff_alarms(command),
        Command::LegalHolds(command) => commands::legal_holds(command),
        Command::Guests(command) => commands::guests(command),
        // Blocking: an endpoint's transform is read over blocking HTTP.
        Command::Reembed(args) => {
            crate::logging::off_runtime("reembed", move || commands::reembed(*args)).await?
        }
        Command::Provenance(args) => commands::provenance(*args),
        Command::Token(TokenCommand::Bootstrap(args)) => commands::token_bootstrap(*args),
        Command::Token(TokenCommand::Pair(args)) => commands::token_pair(*args),
        Command::Token(TokenCommand::Read(args)) => commands::token_read(*args),
        Command::Token(TokenCommand::Agent(args)) => commands::token_agent(*args),
        Command::Token(TokenCommand::Revoke(args)) => commands::token_revoke(*args),
        Command::Api(args) => commands::api(args).await,
        Command::Mcp(args) => commands::mcp(args),
        Command::Wake(args) => crate::wake_adapters::command(args),
        Command::Hook(args) => {
            crate::logging::off_runtime("hook", move || commands::hook(args)).await
        }
        Command::Host(HostCommand::Init(args)) => commands::host_init(args),
        Command::Host(HostCommand::ReRoot(args)) => commands::host_re_root(*args),
        Command::Host(HostCommand::RecoverSharedOwner(args)) => {
            commands::host_recover_shared_owner(*args)
        }
        Command::Host(HostCommand::Relay(args)) => crate::managed::run_relay(&args.config).await,
        #[cfg(target_os = "linux")]
        Command::Host(HostCommand::Vm(args)) => {
            crate::managed::run_vault_vm(crate::managed::VaultVmRun {
                config: args.config,
                vault_name: args.vault_name,
                listen: args.listen,
                credentials_fd: args.credentials_fd,
                idle: std::time::Duration::from_secs(args.idle_secs),
            })
            .await
        }
        #[cfg(not(target_os = "linux"))]
        Command::Host(HostCommand::Vm(_)) => {
            anyhow::bail!("vault VMs need Linux with KVM")
        }
        Command::Dreamer(DreamerCommand::Grant(args)) => commands::dreamer_grant(*args),
        Command::Embedder(EmbedderCommand::Serve(args)) => commands::embedder_serve(*args).await,
        Command::Oneironer(command) => commands::oneironer(command),
        Command::Seat(SeatCommand::Routes) => commands::seat_routes(),
        Command::Seat(SeatCommand::LoginPlan(args)) => commands::seat_login_plan(*args),
    }
}
