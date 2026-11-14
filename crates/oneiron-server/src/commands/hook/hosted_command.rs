//! `oneiron hosted`: the commands that publish this user's hosted sign-in
//! and selection, which `oneiron hook` binds at its step 3
//! ([`super::hosted_selection`]). The surface the owner signed in on (the
//! cloud console, the app) runs them to export the association it made;
//! each writes through the one publish helper.
//!
//! - `login` records one hosted vault, its origin, vault id, auth mode and
//!   credential file, once the origin admits that credential over
//!   `oneiron mcp` (the transport a recall uses), and selects it. A slip
//!   names its own vault, which must be the one named; an owner's sign-in
//!   names none, so the id the exporting surface gives is confirmed
//!   against the vault the origin answers for.
//! - `login` with no credential file signs in first, through the vault's
//!   own OAuth server as a native app ([`super::hosted_sign_in`]), and
//!   records that sign-in in OAuth mode, its vault id the one the origin
//!   answers for.
//! - `select` selects one recorded vault, or none.
//! - `logout` forgets one recorded vault, or every one. It never deletes a
//!   credential file another surface wrote: that surface keeps it. An OAuth
//!   sign-in `login` made is revoked at the vault and its file removed.
//! - `status` reads where the selection stands.
//!
//! Each prints the selection's state as one JSON line. It names credential
//! files, never a value in them.

use std::io::Write as _;
use std::path::Path;
use std::time::{Duration, Instant};

use serde_json::json;

use super::hosted_selection::{self, HostedAuthMode, HostedVault, Selection};
use super::{hosted_sign_in, recall};
use crate::cli::{HostedCommand, HostedLoginArgs, HostedLogoutArgs, HostedSelectArgs, McpAuthMode};
use crate::commands::credential_file::PairedCredentialFile;

/// An authority vault id: 32 bytes, in hex.
const VAULT_ID_HEX_CHARS: usize = 64;

pub fn hosted(command: HostedCommand) -> anyhow::Result<()> {
    match command {
        HostedCommand::Login(args) => login(&args)?,
        HostedCommand::Select(args) => select(&args)?,
        HostedCommand::Logout(args) => logout(&args)?,
        HostedCommand::Status => {}
    }
    let _ = writeln!(std::io::stdout().lock(), "{}", status());
    Ok(())
}

/// Records the vault `args` name once its origin admits the credential
/// and, in owner mode, answers for the vault named, and selects it.
/// Nothing is recorded when it does not. In OAuth mode this signs in first
/// and writes the sign-in beside the selection; a sign-in that is then not
/// recorded is revoked and removed again.
fn login(args: &HostedLoginArgs) -> anyhow::Result<()> {
    let mut selection = held()?;
    let origin = origin(&args.origin)?;
    // The file given names the mode when none is asked; no file signs in.
    let mode = args.auth_mode.unwrap_or(if args.credential_file.is_some() {
        McpAuthMode::Slip
    } else if args.owner_upgrade_headers_file.is_some() {
        McpAuthMode::Owner
    } else {
        McpAuthMode::OAuth
    });
    let (auth_mode, file, id) = match mode {
        McpAuthMode::Slip => {
            anyhow::ensure!(
                args.owner_upgrade_headers_file.is_none(),
                "--owner-upgrade-headers-file is the owner's sign-in, which slip mode does not \
                 read; pass --auth-mode owner with it"
            );
            let file = args.credential_file.as_deref().ok_or_else(|| {
                anyhow::anyhow!(
                    "slip mode needs --credential-file: the paired credential `oneiron token \
                     agent --out` wrote for this vault"
                )
            })?;
            let own = slip_vault_id(file)?;
            if let Some(named) = &args.vault_id {
                let named = vault_id(named)?;
                anyhow::ensure!(
                    named == own,
                    "the slip in {} is for vault {own}, not {named}; a credential goes to its \
                     own vault alone",
                    file.display()
                );
            }
            (HostedAuthMode::Slip, file.to_owned(), Some(own))
        }
        McpAuthMode::Owner => {
            anyhow::ensure!(
                args.credential_file.is_none(),
                "--credential-file names a paired slip, and owner mode runs as the vault's \
                 owner with no slip; drop it, or pass --auth-mode slip"
            );
            let file = args.owner_upgrade_headers_file.as_deref().ok_or_else(|| {
                anyhow::anyhow!(
                    "owner mode needs --owner-upgrade-headers-file: the file of upgrade headers \
                     the surface the owner signed in on wrote for this vault"
                )
            })?;
            let named = args.vault_id.as_deref().ok_or_else(|| {
                anyhow::anyhow!(
                    "owner mode needs --vault-id: the vault the surface the owner signed in on \
                     issued this sign-in for"
                )
            })?;
            (
                HostedAuthMode::Owner,
                file.to_owned(),
                Some(vault_id(named)?),
            )
        }
        McpAuthMode::OAuth => {
            anyhow::ensure!(
                args.credential_file.is_none() && args.owner_upgrade_headers_file.is_none(),
                "oauth mode signs in here and reads no credential file; drop --credential-file \
                 and --owner-upgrade-headers-file, or pass the --auth-mode they belong to"
            );
            let named = args.vault_id.as_deref().map(vault_id).transpose()?;
            let file = hosted_selection::oauth_sign_in_file(&origin).ok_or_else(|| {
                anyhow::anyhow!("there is no per-user oneiron folder (HOME is not set)")
            })?;
            hosted_selection::create_user_dir_for(&file)?;
            hosted_sign_in::sign_in(
                &origin,
                &file,
                Duration::from_secs(args.sign_in_timeout_secs),
            )?;
            (HostedAuthMode::OAuth, file, named)
        }
    };
    let recorded = record(args, &mut selection, origin, auth_mode, &file, id);
    if recorded.is_err() && auth_mode == HostedAuthMode::OAuth {
        // Nothing names this sign-in now: it goes, at the vault too.
        let _ = hosted_sign_in::sign_out(&file);
    }
    recorded
}

/// Records the vault at `origin` reached by `file` in `auth_mode`, once
/// the origin admits that credential and answers for the vault `id` names
/// (or, signed in by OAuth with no id named, for the vault it answers), and
/// selects it.
fn record(
    args: &HostedLoginArgs,
    selection: &mut Selection,
    origin: String,
    auth_mode: HostedAuthMode,
    file: &Path,
    id: Option<String>,
) -> anyhow::Result<()> {
    let mut vault = HostedVault {
        origin,
        vault_id: id.clone().unwrap_or_default(),
        auth_mode,
        credential_file: std::path::absolute(file)
            .map_err(|error| anyhow::anyhow!("{}: {error}", file.display()))?,
        verified_at_ms: 0,
    };
    let deadline = Instant::now() + Duration::from_secs(args.timeout_secs);
    let oneiron = super::oneiron(None);
    let answered = match recall::admits(&oneiron, &vault.origin, vault.recall_auth(), deadline) {
        Ok(answered) => answered,
        Err(error) => {
            anyhow::bail!(
                "{} did not admit this credential over `oneiron mcp` ({error}); nothing was \
                 recorded",
                vault.origin
            );
        }
    };
    // An owner's sign-in and an OAuth sign-in name no vault of their own, so
    // the id given is confirmed against the vault the origin answers for
    // (FIX 11695): a named mismatch is reported and nothing is recorded, as a
    // slip's own mismatch is. A slip's admission already proves its vault.
    if auth_mode != HostedAuthMode::Slip {
        match (answered.as_deref(), id.as_deref()) {
            (Some(answer), Some(named)) if answer == named => {}
            (Some(answer), None) => answer.clone_into(&mut vault.vault_id),
            (Some(answer), Some(named)) => {
                anyhow::bail!(
                    "{} answers for vault {answer}, not {named}; a credential goes to its own \
                     vault alone, so nothing was recorded",
                    vault.origin
                );
            }
            // An origin that names no vault (not yet rooted) is recorded as
            // before, with the reason on one line: only a named mismatch
            // stops the login.
            (None, Some(named)) => eprintln!(
                "{} answered no vault id, so the vault {named} it was told is recorded \
                 unconfirmed",
                vault.origin
            ),
            (None, None) => anyhow::bail!(
                "{} answered no vault id, so nothing was recorded; pass --vault-id with the \
                 vault this origin serves",
                vault.origin
            ),
        }
    }
    vault.verified_at_ms = now_ms();
    selection
        .vaults
        .retain(|kept| kept.vault_id != vault.vault_id);
    selection.selected = Some(vault.vault_id.clone());
    selection.vaults.push(vault);
    hosted_selection::publish(selection)
}

/// Selects the recorded vault `args` names, or none.
fn select(args: &HostedSelectArgs) -> anyhow::Result<()> {
    let mut selection = held()?;
    selection.selected = match &args.vault_id {
        Some(named) => Some(recorded(&selection, named)?),
        None => None,
    };
    hosted_selection::publish(&selection)
}

/// Forgets the recorded vault `args` names, or every one, and then signs
/// out of each OAuth sign-in among them.
fn logout(args: &HostedLogoutArgs) -> anyhow::Result<()> {
    let Some(named) = &args.vault_id else {
        // Every sign-in goes, whatever the file held.
        let gone = hosted_selection::read()
            .map(|held| held.vaults)
            .unwrap_or_default();
        hosted_selection::publish(&Selection::default())?;
        sign_out(&gone);
        return Ok(());
    };
    let mut selection = held()?;
    let id = recorded(&selection, named)?;
    let (gone, kept): (Vec<HostedVault>, Vec<HostedVault>) = std::mem::take(&mut selection.vaults)
        .into_iter()
        .partition(|vault| vault.vault_id == id);
    selection.vaults = kept;
    if selection.selected.as_deref() == Some(id.as_str()) {
        selection.selected = None;
    }
    hosted_selection::publish(&selection)?;
    sign_out(&gone);
    Ok(())
}

/// Revokes and removes each OAuth sign-in `login` made among `vaults`. A
/// credential file another surface wrote stays: that surface keeps it.
fn sign_out(vaults: &[HostedVault]) {
    for vault in vaults
        .iter()
        .filter(|vault| vault.auth_mode == HostedAuthMode::OAuth)
    {
        if let Err(error) = hosted_sign_in::sign_out(&vault.credential_file) {
            let _ = writeln!(std::io::stderr().lock(), "{error}");
        }
    }
}

/// Where the selection stands, as one JSON object: its state, the selected
/// vault's id, and every recorded vault; or why it could not be read.
fn status() -> serde_json::Value {
    match hosted_selection::read() {
        Ok(selection) => json!({
            "state": selection.discovery().state(),
            "selected": selection.selected_vault().map(|vault| vault.vault_id.clone()),
            "vaults": selection.vaults,
        }),
        Err(why) => {
            let unavailable = hosted_selection::HostedDiscovery::Unavailable(why.clone());
            json!({ "state": unavailable.state(), "why": why })
        }
    }
}

/// The selection as it is, for an act that changes part of it.
fn held() -> anyhow::Result<Selection> {
    hosted_selection::read().map_err(|why| {
        anyhow::anyhow!("{why}; fix it, or `oneiron hosted logout` to start the selection anew")
    })
}

/// The recorded vault whose id `named` is, or begins: the 12 characters a
/// session line shows are enough when no other recorded id begins so.
fn recorded(selection: &Selection, named: &str) -> anyhow::Result<String> {
    let named = named.trim().to_ascii_lowercase();
    anyhow::ensure!(!named.is_empty(), "name a vault id");
    let mut matching = selection
        .vaults
        .iter()
        .filter(|vault| vault.vault_id.starts_with(&named));
    match (matching.next(), matching.next()) {
        (Some(vault), None) => Ok(vault.vault_id.clone()),
        (Some(_), Some(_)) => {
            anyhow::bail!("more than one recorded hosted vault id begins {named}; name more of it")
        }
        (None, _) => anyhow::bail!(
            "no hosted vault {named} is signed in to here; run `oneiron hosted login` for it first"
        ),
    }
}

/// `text` as an origin `oneiron mcp --url` takes: an http or https URL,
/// without a trailing slash.
fn origin(text: &str) -> anyhow::Result<String> {
    let text = text.trim().trim_end_matches('/');
    let url = reqwest::Url::parse(text)
        .map_err(|error| anyhow::anyhow!("--origin {text} is not a URL: {error}"))?;
    anyhow::ensure!(
        matches!(url.scheme(), "http" | "https") && url.host_str().is_some(),
        "--origin {text} is not an http or https origin"
    );
    Ok(text.to_owned())
}

/// `text` as a vault id: 64 hex characters, lowercased.
fn vault_id(text: &str) -> anyhow::Result<String> {
    let id = text.trim().to_ascii_lowercase();
    anyhow::ensure!(
        id.len() == VAULT_ID_HEX_CHARS && id.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "--vault-id {text} is not a vault id ({VAULT_ID_HEX_CHARS} hex characters)"
    );
    Ok(id)
}

/// The vault the paired slip in `file` names, in hex. The value read is
/// never shown.
fn slip_vault_id(file: &Path) -> anyhow::Result<String> {
    let held = PairedCredentialFile::read(file)?;
    let slip = oneiron::authority::CapabilitySlip::from_token(&held.token).map_err(|_| {
        anyhow::anyhow!(
            "{} does not hold a capability slip; mint one with `oneiron token agent`",
            file.display()
        )
    })?;
    Ok(slip
        .claims
        .vault_id
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| {
            u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
        })
}
