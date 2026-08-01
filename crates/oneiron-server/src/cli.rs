use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

use crate::commands;
use crate::config::ServeArgs;

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
    Serve(Box<ServeArgs>),
    /// Revoke an existing device lease binding.
    Revoke(Box<RevokeArgs>),
    /// Print or locate the agentskills-compatible skill pack.
    SkillsPack(SkillsPackArgs),
    /// Create a vault and print its doctor report.
    Init(VaultArgs),
    /// Open a vault and print its doctor report.
    Doctor(VaultArgs),
    /// Resolve repo commit provenance trailers against a vault claim.
    Provenance(Box<ProvenanceArgs>),
    /// Mint bearer tokens against the configured auth secret.
    #[command(subcommand)]
    Token(TokenCommand),
}

#[derive(Subcommand)]
pub enum TokenCommand {
    /// Mint a scoped core bearer token and print it to stdout.
    Mint(Box<TokenMintArgs>),
}

#[derive(Args, Clone, Debug)]
pub struct TokenMintArgs {
    /// Core scopes to grant, comma-separated (e.g. `core:read,core:write`).
    /// Omit to mint an owner-grade token carrying every scope.
    #[arg(long, value_delimiter = ',', num_args = 1..)]
    pub scope: Option<Vec<String>>,

    /// Bind the token to a third-party principal, as 32 lowercase hex
    /// characters. Requires `--scope`: an owner-grade token is never bound.
    #[arg(long = "principal-ref", requires = "scope")]
    pub principal_ref: Option<String>,

    #[command(flatten)]
    pub serve: ServeArgs,
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
        Command::Init(args) => commands::init(args),
        Command::Doctor(args) => commands::doctor(args),
        Command::Provenance(args) => commands::provenance(*args),
        Command::Token(TokenCommand::Mint(args)) => commands::token_mint(*args),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_subcommand_defaults_to_serve() {
        let cli = Cli::try_parse_from(["oneiron-server", "--port", "9191"]).unwrap();
        match cli.into_command() {
            Command::Serve(args) => assert_eq!(args.port, Some(9191)),
            _ => panic!("expected serve command"),
        }
    }

    #[test]
    fn explicit_serve_accepts_current_flags() {
        let cli = Cli::try_parse_from([
            "oneiron-server",
            "serve",
            "--vault-path",
            "/tmp/oneiron-vault",
            "--host",
            "127.0.0.1",
            "--port",
            "9191",
        ])
        .unwrap();

        match cli.into_command() {
            Command::Serve(args) => {
                assert_eq!(args.vault_path, Some(PathBuf::from("/tmp/oneiron-vault")));
                assert_eq!(args.host.as_deref(), Some("127.0.0.1"));
                assert_eq!(args.port, Some(9191));
            }
            _ => panic!("expected serve command"),
        }
    }

    #[test]
    fn explicit_serve_accepts_cors_origins_alias() {
        let cli = Cli::try_parse_from([
            "oneiron-server",
            "serve",
            "--cors-origins",
            "https://a.example,https://b.example",
        ])
        .unwrap();

        match cli.into_command() {
            Command::Serve(args) => assert_eq!(
                args.allowed_origins,
                Some(vec![
                    "https://a.example".to_owned(),
                    "https://b.example".to_owned()
                ])
            ),
            _ => panic!("expected serve command"),
        }
    }

    #[test]
    fn revoke_accepts_client_and_serve_config_flags() {
        let cli = Cli::try_parse_from([
            "oneiron-server",
            "revoke",
            "--client",
            "0123456789abcdef",
            "--vault-path",
            "/tmp/oneiron-vault",
        ])
        .unwrap();

        match cli.into_command() {
            Command::Revoke(args) => {
                assert_eq!(args.client, "0123456789abcdef");
                assert_eq!(
                    args.serve.vault_path,
                    Some(PathBuf::from("/tmp/oneiron-vault"))
                );
            }
            _ => panic!("expected revoke command"),
        }
    }

    #[test]
    fn skills_pack_defaults_to_markdown_output() {
        let cli = Cli::try_parse_from(["oneiron-server", "skills-pack"]).unwrap();

        match cli.into_command() {
            Command::SkillsPack(args) => {
                assert!(!args.json);
                assert!(!args.path);
            }
            _ => panic!("expected skills-pack command"),
        }
    }

    #[test]
    fn skills_pack_accepts_json_output() {
        let cli = Cli::try_parse_from(["oneiron-server", "skills-pack", "--json"]).unwrap();

        match cli.into_command() {
            Command::SkillsPack(args) => {
                assert!(args.json);
                assert!(!args.path);
            }
            _ => panic!("expected skills-pack command"),
        }
    }

    #[test]
    fn skills_pack_path_conflicts_with_json() {
        let err = match Cli::try_parse_from(["oneiron-server", "skills-pack", "--json", "--path"]) {
            Ok(_) => panic!("expected --json and --path to conflict"),
            Err(err) => err,
        };

        assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    #[test]
    fn provenance_accepts_sha_and_vault_path() {
        let cli = Cli::try_parse_from([
            "oneiron-server",
            "provenance",
            "0123456789abcdef0123456789abcdef01234567",
            "--vault-path",
            "/tmp/oneiron-vault",
            "--repo-path",
            "/tmp/repo",
            "--git-notes",
            "--include-payload",
        ])
        .unwrap();

        match cli.into_command() {
            Command::Provenance(args) => {
                assert_eq!(
                    args.sha.as_deref(),
                    Some("0123456789abcdef0123456789abcdef01234567")
                );
                assert_eq!(args.vault_path, PathBuf::from("/tmp/oneiron-vault"));
                assert_eq!(args.repo_path, PathBuf::from("/tmp/repo"));
                assert!(args.git_notes);
                assert!(args.include_payload);
            }
            _ => panic!("expected provenance command"),
        }
    }

    #[test]
    fn provenance_accepts_claim_id_lookup() {
        let cli = Cli::try_parse_from([
            "oneiron-server",
            "provenance",
            "--claim-id",
            "0123456789abcdef0123456789abcdef",
            "--vault-path",
            "/tmp/oneiron-vault",
        ])
        .unwrap();

        match cli.into_command() {
            Command::Provenance(args) => {
                assert_eq!(
                    args.claim_id.as_deref(),
                    Some("0123456789abcdef0123456789abcdef")
                );
                assert!(args.sha.is_none());
            }
            _ => panic!("expected provenance command"),
        }
    }

    #[test]
    fn provenance_requires_sha_or_claim_id() {
        let err = match Cli::try_parse_from([
            "oneiron-server",
            "provenance",
            "--vault-path",
            "/tmp/oneiron-vault",
        ]) {
            Ok(_) => panic!("expected provenance target requirement"),
            Err(err) => err,
        };

        assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn token_mint_parses_scope_list_and_principal_ref() {
        let cli = Cli::try_parse_from([
            "oneiron-server",
            "token",
            "mint",
            "--scope",
            "core:read,companion:profile:read",
            "--principal-ref",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ])
        .unwrap();

        match cli.into_command() {
            Command::Token(TokenCommand::Mint(args)) => {
                assert_eq!(
                    args.scope,
                    Some(vec![
                        "core:read".to_owned(),
                        "companion:profile:read".to_owned()
                    ])
                );
                assert_eq!(
                    args.principal_ref.as_deref(),
                    Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                );
            }
            _ => panic!("expected token mint command"),
        }
    }

    #[test]
    fn token_mint_defaults_to_owner_grade_claims() {
        let cli = Cli::try_parse_from(["oneiron-server", "token", "mint"]).unwrap();

        match cli.into_command() {
            Command::Token(TokenCommand::Mint(args)) => {
                assert!(args.scope.is_none());
                assert!(args.principal_ref.is_none());
            }
            _ => panic!("expected token mint command"),
        }
    }

    /// Mirrors the server-side grammar rule: an owner-grade token is never
    /// bound to a third-party principal, so the flag pair is rejected at parse.
    #[test]
    fn token_mint_principal_ref_requires_scope() {
        let err = match Cli::try_parse_from([
            "oneiron-server",
            "token",
            "mint",
            "--principal-ref",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ]) {
            Ok(_) => panic!("expected --principal-ref to require --scope"),
            Err(err) => err,
        };

        assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
    }
}
