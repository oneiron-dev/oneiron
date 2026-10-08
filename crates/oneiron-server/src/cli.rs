use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

use crate::commands;
use crate::config::ServeArgs;

mod owner_args;
pub use owner_args::{
    BackupArgs, DoctorArgs, ExportArgs, ImportBatchArgs, ImportCommand, ImportDecisionArgs,
    RestoreArgs, RunArgs, RunDecisionArgs, RunsCommand, SecretScanArgs, SecretScanSwitch,
    ServeOnlyArgs, WhoamiArgs,
};

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
    /// Restore a backup over a stopped vault, or `--rehearse` it in a
    /// scratch copy without touching the vault.
    Restore(Box<RestoreArgs>),
    /// Export the whole vault in one of five formats.
    Export(Box<ExportArgs>),
    /// Turn the write-door secret scan on or off, or show it.
    SecretScan(Box<SecretScanArgs>),
    /// Preview, approve or decline one whole import batch.
    #[command(subcommand)]
    Import(ImportCommand),
    /// Agent runs waiting for consent: list, review, approve or decline whole.
    #[command(subcommand)]
    Runs(RunsCommand),
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
    /// Scaffold a self-host node from the shipped deployment templates.
    #[command(subcommand)]
    Host(HostCommand),
}

#[derive(Subcommand)]
pub enum HostCommand {
    Init(HostInitArgs),
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
    /// Revoke one previously minted token by its id.
    Revoke(Box<TokenRevokeArgs>),
}

/// Local-only bootstrap: the vault is opened exclusively from the host's
/// configured path. No issuer secret is sent over HTTP or printed.
#[derive(Args, Clone, Debug)]
pub struct TokenBootstrapArgs {
    /// Origin clients will contact after `serve` starts.
    #[arg(long, env = "ONEIRON_URL", default_value = "http://127.0.0.1:3000")]
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
    /// The running server's origin. The link carries it.
    #[arg(long, env = "ONEIRON_URL", default_value = "http://127.0.0.1:3000")]
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
    /// The principal the credential reads as, 32 lowercase hex characters.
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
    /// Existing Oneiron server root.
    #[arg(long, env = "ONEIRON_URL", default_value = "http://127.0.0.1:3000")]
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
    run_cli(Cli::parse()).await
}

pub async fn run_cli(cli: Cli) -> anyhow::Result<()> {
    match cli.into_command() {
        Command::Serve(args) => commands::serve(*args).await,
        Command::Revoke(args) => commands::revoke(*args).await,
        Command::SkillsPack(args) => commands::skills_pack(args),
        Command::Init(args) => tokio::task::spawn_blocking(move || commands::init(args)).await?,
        Command::Doctor(args) => commands::doctor(args),
        Command::Whoami(args) => commands::whoami(*args),
        Command::Backup(args) => commands::backup(*args),
        Command::Restore(args) => commands::restore(*args),
        Command::Export(args) => commands::export(*args),
        Command::SecretScan(args) => commands::secret_scan(*args),
        Command::Import(command) => commands::import(command),
        Command::Runs(command) => commands::runs(command),
        Command::Reembed(args) => commands::reembed(*args),
        Command::Provenance(args) => commands::provenance(*args),
        Command::Token(TokenCommand::Bootstrap(args)) => commands::token_bootstrap(*args),
        Command::Token(TokenCommand::Pair(args)) => commands::token_pair(*args),
        Command::Token(TokenCommand::Read(args)) => commands::token_read(*args),
        Command::Token(TokenCommand::Revoke(args)) => commands::token_revoke(*args),
        Command::Api(args) => commands::api(args).await,
        Command::Host(HostCommand::Init(args)) => commands::host_init(args),
    }
}

#[cfg(test)]
mod tests;
