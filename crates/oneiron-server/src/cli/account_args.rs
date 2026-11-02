//! `oneiron account`: the owner links a stopped vault to the Oneiron cloud
//! account and manages that link (G7). A running `serve` answers the same
//! acts at `/v1/owner/cloud-registration/*`.

use clap::{Args, Subcommand};

use crate::config::ServeArgs;

#[derive(Subcommand)]
pub enum AccountCommand {
    /// Link this vault to your Oneiron cloud account: open the address
    /// shown, enter the code shown, and approve there. `--replace` lets a
    /// different cloud account replace the current link.
    Login(Box<AccountLoginArgs>),
    /// Show where the link stands; `--refresh` refreshes it first.
    Status(Box<AccountStatusArgs>),
    /// Refresh the link's tokens once, then check it online.
    Refresh(Box<AccountServeArgs>),
    /// Stop the link here and ask the cloud to revoke it; `--erase` erases
    /// every token this vault kept for it first.
    Logout(Box<AccountLogoutArgs>),
}

#[derive(Args, Clone, Debug)]
pub struct AccountLoginArgs {
    /// Replace a current link to another cloud account.
    #[arg(long)]
    pub replace: bool,

    #[command(flatten)]
    pub serve: ServeArgs,
}

#[derive(Args, Clone, Debug)]
pub struct AccountStatusArgs {
    /// Refresh the link's tokens before reading it.
    #[arg(long)]
    pub refresh: bool,

    #[command(flatten)]
    pub serve: ServeArgs,
}

#[derive(Args, Clone, Debug)]
pub struct AccountServeArgs {
    #[command(flatten)]
    pub serve: ServeArgs,
}

#[derive(Args, Clone, Debug)]
pub struct AccountLogoutArgs {
    /// Erase every token this vault kept for the link, in every generation,
    /// before the revoke.
    #[arg(long)]
    pub erase: bool,

    #[command(flatten)]
    pub serve: ServeArgs,
}
