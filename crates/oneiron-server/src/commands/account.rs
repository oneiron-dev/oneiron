//! `oneiron account`: the owner's cloud registration on a stopped vault
//! (G7). Holding the vault's writer lease is the owner proof, as for every
//! owner command; the acts are the ones `/v1/owner/cloud-registration`
//! answers on a running server, through the same client. A login shows the
//! verification address and the code on stderr, apart, and polls at the
//! issuer's pace until it is approved, denied or expired; each command's
//! result goes to stdout as JSON. No token or code goes to argv, a log or
//! stdout.

use std::io::Write as _;
use std::time::Duration;

use super::owner::{emit, open_stopped_vault_with, vault_config};
use crate::cli::{
    AccountCommand, AccountLoginArgs, AccountLogoutArgs, AccountServeArgs, AccountStatusArgs,
};
use crate::cloud_registration::{CloudRegistration, Polled, Started};
use crate::config::{ServeArgs, resolve_serve_config};
use crate::owner::local_owner;

pub fn account(command: AccountCommand) -> anyhow::Result<()> {
    match command {
        AccountCommand::Login(args) => login(*args),
        AccountCommand::Status(args) => status(*args),
        AccountCommand::Refresh(args) => refresh(*args),
        AccountCommand::Logout(args) => logout(*args),
    }
}

/// The stopped vault `serve` names, its local owner, and its client under
/// the configured pins.
fn open(
    serve: &ServeArgs,
) -> anyhow::Result<(
    oneiron::Vault,
    oneiron::consent::AuthenticatedOwner,
    CloudRegistration,
)> {
    let config = resolve_serve_config(serve)?;
    let vault = open_stopped_vault_with(
        &config,
        vault_config(&config),
        "or ask it: `oneiron api raw GET /v1/owner/cloud-registration/status`",
    )?;
    let owner = local_owner(&vault)?;
    let client = CloudRegistration::new(config.cloud_registration_pins.as_deref());
    Ok((vault, owner, client))
}

fn login(args: AccountLoginArgs) -> anyhow::Result<()> {
    let (vault, owner, client) = open(&args.serve)?;
    let (flow, interval) = match client.start(&vault, &owner, args.replace)? {
        Started::Pending {
            flow,
            verification_uri,
            user_code,
            expires_in,
            interval,
        } => {
            let mut stderr = std::io::stderr().lock();
            writeln!(stderr, "Open: {verification_uri}")?;
            writeln!(stderr, "Enter the code: {user_code}")?;
            writeln!(
                stderr,
                "Approve there within {} minutes; this command waits.",
                expires_in.div_ceil(60)
            )?;
            stderr.flush()?;
            (flow, interval)
        }
        other => return emit(&other),
    };
    let mut wait = Duration::from_secs(interval);
    loop {
        std::thread::sleep(wait);
        match client.poll(&vault, &owner, &flow)? {
            Polled::Pending { next_poll_in, .. } => {
                wait = Duration::from_secs(next_poll_in.max(1));
            }
            Polled::Unavailable { description, .. } => {
                let mut stderr = std::io::stderr().lock();
                writeln!(stderr, "Cloud registration unavailable; still waiting.")?;
                if let Some(description) = description {
                    writeln!(stderr, "{description}")?;
                }
                wait = Duration::from_secs(interval);
            }
            other => return emit(&other),
        }
    }
}

fn status(args: AccountStatusArgs) -> anyhow::Result<()> {
    let (vault, owner, client) = open(&args.serve)?;
    if args.refresh {
        return emit(&client.refresh(&vault, &owner)?);
    }
    emit(&client.status(&vault, &owner)?)
}

fn refresh(args: AccountServeArgs) -> anyhow::Result<()> {
    let (vault, owner, client) = open(&args.serve)?;
    emit(&client.refresh(&vault, &owner)?)
}

fn logout(args: AccountLogoutArgs) -> anyhow::Result<()> {
    let (vault, owner, client) = open(&args.serve)?;
    emit(&client.logout(&vault, &owner, args.erase)?)
}
