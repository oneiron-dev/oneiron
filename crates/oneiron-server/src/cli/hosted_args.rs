//! `oneiron hosted`: the hosted vaults this user signed in to here and the
//! one selected, which `oneiron hook` binds at its step 3. The surface the
//! owner signed in on runs these to export his selection.

use std::path::PathBuf;

use clap::{Args, Subcommand};

use super::McpAuthMode;

#[derive(Subcommand, Clone, Debug)]
pub enum HostedCommand {
    /// Record a hosted vault signed in to here, by its origin, its vault id
    /// and the credential that reaches it, once the origin admits that
    /// credential over `oneiron mcp`; then select it.
    Login(HostedLoginArgs),
    /// Select one recorded hosted vault for `oneiron hook`, or none.
    Select(HostedSelectArgs),
    /// Forget one recorded hosted vault, or every one. Never deletes a
    /// credential file.
    Logout(HostedLogoutArgs),
    /// Print where the hosted selection stands, as one JSON line.
    Status,
}

#[derive(Args, Clone, Debug)]
pub struct HostedLoginArgs {
    /// The hosted vault's origin, as `oneiron mcp --url` takes it.
    #[arg(long)]
    pub origin: String,

    /// Its authority vault id, in hex. A slip names its own vault, which
    /// this must match when given; an owner's sign-in names none, so owner
    /// mode needs it.
    #[arg(long)]
    pub vault_id: Option<String>,

    /// How a client authenticates there, as for `oneiron mcp`: `slip`, a
    /// paired credential from `--credential-file`; `owner`, the owner's
    /// sign-in from `--owner-upgrade-headers-file`.
    #[arg(long, value_enum, default_value_t = McpAuthMode::Slip)]
    pub auth_mode: McpAuthMode,

    /// Slip mode's paired credential, as `token agent --out` writes it.
    /// Only its owner may be able to read it.
    #[arg(long, value_name = "FILE")]
    pub credential_file: Option<PathBuf>,

    /// Owner mode's sign-in: the file of upgrade headers the surface the
    /// owner signed in on wrote for this vault. Only its owner may be able
    /// to read it.
    #[arg(long, value_name = "FILE")]
    pub owner_upgrade_headers_file: Option<PathBuf>,

    /// Seconds the origin may take to admit the credential.
    #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u64).range(1..))]
    pub timeout_secs: u64,
}

#[derive(Args, Clone, Debug)]
pub struct HostedSelectArgs {
    /// The recorded vault id to select; its first characters are enough
    /// when no other recorded id begins with them.
    #[arg(required_unless_present = "none", conflicts_with = "none")]
    pub vault_id: Option<String>,

    /// Select no hosted vault: `oneiron hook` then goes on to a local one.
    #[arg(long)]
    pub none: bool,
}

#[derive(Args, Clone, Debug)]
pub struct HostedLogoutArgs {
    /// Forget only this recorded vault (its first characters are enough);
    /// without it, every hosted vault recorded here.
    #[arg(long)]
    pub vault_id: Option<String>,
}
