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
//!   names none, so its vault id is the one the exporting surface gives.
//! - `select` selects one recorded vault, or none.
//! - `logout` forgets one recorded vault, or every one. It never deletes a
//!   credential file: the surface that wrote it keeps it.
//! - `status` reads where the selection stands.
//!
//! Each prints the selection's state as one JSON line. It names credential
//! files, never a value in them.

use std::io::Write as _;
use std::path::Path;
use std::time::{Duration, Instant};

use serde_json::json;

use super::hosted_selection::{self, HostedAuthMode, HostedVault, Selection};
use super::recall;
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

/// Records the vault `args` name once its origin admits the credential,
/// and selects it. Nothing is recorded when it does not.
fn login(args: &HostedLoginArgs) -> anyhow::Result<()> {
    let mut selection = held()?;
    let origin = origin(&args.origin)?;
    let (auth_mode, file, id) = match args.auth_mode {
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
            (HostedAuthMode::Slip, file, own)
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
            (HostedAuthMode::Owner, file, vault_id(named)?)
        }
    };
    let mut vault = HostedVault {
        origin,
        vault_id: id,
        auth_mode,
        credential_file: std::path::absolute(file)
            .map_err(|error| anyhow::anyhow!("{}: {error}", file.display()))?,
        verified_at_ms: 0,
    };
    let deadline = Instant::now() + Duration::from_secs(args.timeout_secs);
    let oneiron = super::oneiron(None);
    if let Err(error) = recall::admits(&oneiron, &vault.origin, vault.recall_auth(), deadline) {
        anyhow::bail!(
            "{} did not admit this credential over `oneiron mcp` ({error}); nothing was \
             recorded",
            vault.origin
        );
    }
    vault.verified_at_ms = now_ms();
    selection
        .vaults
        .retain(|kept| kept.vault_id != vault.vault_id);
    selection.selected = Some(vault.vault_id.clone());
    selection.vaults.push(vault);
    hosted_selection::publish(&selection)
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

/// Forgets the recorded vault `args` names, or every one.
fn logout(args: &HostedLogoutArgs) -> anyhow::Result<()> {
    let Some(named) = &args.vault_id else {
        // Every sign-in goes, whatever the file held.
        return hosted_selection::publish(&Selection::default());
    };
    let mut selection = held()?;
    let id = recorded(&selection, named)?;
    selection.vaults.retain(|vault| vault.vault_id != id);
    if selection.selected.as_deref() == Some(id.as_str()) {
        selection.selected = None;
    }
    hosted_selection::publish(&selection)
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
