use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

use crate::commands;
use crate::config::ServeArgs;

const DEFAULT_SERVER_DIMENSIONS: usize = 4096;
const DEFAULT_SERVER_MAP_SIZE: usize = 1 << 33;

#[derive(Parser)]
#[command(
    name = "oneiron-server",
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
}
