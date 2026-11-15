//! `oneiron link`, `oneiron link status` and `oneiron unlink` (L10-16):
//! the owner's hosted peer, asked of a running `serve` at `/v1/owner/link`.

use clap::{Args, Subcommand};

use super::RunningServerArgs;

/// Link a hosted peer of this vault: the cloud's always-on machine, a
/// hosted node, never yours. The vault stays primary and keeps everything.
#[derive(Args, Clone, Debug)]
#[command(args_conflicts_with_subcommands = true)]
pub struct LinkArgs {
    #[command(subcommand)]
    pub command: Option<LinkCommand>,

    /// Where the hosted peer redeems its link: this server's origin as the
    /// peer reaches it, `https://` (or `http://` on this machine).
    #[arg(long, env = "ONEIRON_LINK_ORIGIN")]
    pub origin: Option<String>,

    /// How long to wait for the hosted peer to enrol, in seconds.
    #[arg(long, default_value_t = 600)]
    pub wait_secs: u64,

    #[command(flatten)]
    pub server: RunningServerArgs,
}

#[derive(Subcommand, Clone, Debug)]
pub enum LinkCommand {
    /// Show where the vault's hosted peer stands.
    Status(RunningServerArgs),
}

/// Unlink the vault's hosted peer: it is revoked at once, and the cloud
/// erases its copy and keys. The local vault is not touched.
#[derive(Args, Clone, Debug)]
pub struct UnlinkArgs {
    #[command(flatten)]
    pub server: RunningServerArgs,
}
