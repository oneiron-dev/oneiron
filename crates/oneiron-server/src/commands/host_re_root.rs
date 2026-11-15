//! `oneiron host re-root`: moves a stopped self-host vault's root to a new
//! issuer seed, in-chain (OF-455), and the operator's host secret to a new
//! one. The root signs with this install's own independent issuer seed for
//! the vault, never a key the host secret derives (FIX-LIST 3018): the
//! current seed signs one ReRoot for a successor seed this command draws
//! and keeps in the same keystore slot, so the vault keeps its id, and the
//! engine carries its writers and its MACHINE claim histories to the new
//! root in the same transaction (`Vault::re_root_host_to_new_seed`). Every
//! slip the old root minted stops verifying; this command says so and lists
//! them. The current and new host secrets admit the move and the next start.
//!
//! A lost seed has no path here: a re-root needs the current root's
//! signature, and a second Genesis would change the vault id (OF-455).
//! `oneiron host recover-root` moves a lost root with the recovery kit the
//! owner enrolled before the loss (L1-07).

use std::io::{self, Read, Write};
use std::path::Path;

use serde_json::json;
use zeroize::Zeroizing;

use crate::cli::HostReRootArgs;
use crate::config::resolve_serve_config;

use super::MIN_RECOMMENDED_AUTH_SECRET_BYTES;

/// Where the new host secret is read from when no file is given.
const NEW_SECRET_ENV: &str = "ONEIRON_NEW_AUTH_SECRET";

pub fn host_re_root(args: HostReRootArgs) -> anyhow::Result<()> {
    anyhow::ensure!(
        !args.serve.managed_by_hypnos,
        "managed vaults move their root through their supervisor; re-root is self-host only"
    );
    anyhow::ensure!(
        args.serve.auth_secret.is_none(),
        "set ONEIRON_AUTH_SECRET or a protected config file; never pass the issuer key in argv"
    );
    // A TOML error renders the line it failed on, and that line may hold a
    // host secret, so only the outermost message leaves this command.
    let config = resolve_serve_config(&args.serve).map_err(|error| {
        anyhow::anyhow!("{error} (detail withheld: the file may hold a secret)")
    })?;
    anyhow::ensure!(
        config.vault_path.join("data.mdb").is_file(),
        "vault {} does not exist",
        config.vault_path.display()
    );
    let current = match &args.secret_file {
        Some(path) => read_secret_file(path)?,
        None => Zeroizing::new(
            config
                .sync_server_config()
                .auth_secret
                .filter(|secret| !secret.is_empty())
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "the current host secret is required: set ONEIRON_AUTH_SECRET, the config's auth_secret, or --secret-file"
                    )
                })?,
        ),
    };
    let next = match &args.new_secret_file {
        Some(path) => read_secret_file(path)?,
        None => match std::env::var(NEW_SECRET_ENV) {
            Ok(secret) if !secret.is_empty() => Zeroizing::new(secret),
            Ok(_) | Err(std::env::VarError::NotPresent) => anyhow::bail!(
                "the new host secret is required: set {NEW_SECRET_ENV} or pass --new-secret-file"
            ),
            // The error's own Display would quote the value.
            Err(std::env::VarError::NotUnicode(_)) => {
                anyhow::bail!("{NEW_SECRET_ENV} is not valid UTF-8")
            }
        },
    };
    if next.len() < MIN_RECOMMENDED_AUTH_SECRET_BYTES {
        writeln!(
            io::stderr().lock(),
            "warning: the new host secret is shorter than {MIN_RECOMMENDED_AUTH_SECRET_BYTES} bytes; it is what admits this host's commands"
        )?;
    }
    anyhow::ensure!(
        current.as_bytes() != next.as_bytes(),
        "the new host secret is the current one"
    );
    let vault = oneiron::Vault::open_owned(&config.vault_path, config.vault_config()).map_err(
        |error| match error {
            oneiron::Error::ConcurrentWrite(oneiron::VAULT_WRITER_LEASE_HELD) => anyhow::anyhow!(
                "vault {} is open in a running `oneiron serve`; stop it, re-root, and start it with the new secret",
                config.vault_path.display()
            ),
            error => anyhow::anyhow!("open vault {}: {error}", config.vault_path.display()),
        },
    )?;
    let fold = vault.authority_fold()?;
    anyhow::ensure!(
        fold.vault_id.is_some(),
        "vault {} has no host root yet, so no secret is bound to it; use the new secret from now on",
        config.vault_path.display()
    );
    // The current root's issuer is this install's own seed for the vault,
    // loaded only after the vault and its keystore are open.
    let current = super::owner::host_issuer(&config, &vault, false)?;
    match fold.roster.get(&current.public_key()) {
        Some(root) if !root.revoked && root.roles & oneiron::authority::ROLE_OWNER != 0 => {}
        Some(_) => anyhow::bail!(
            "this install's host issuer was this vault's root once, and a re-root retired it; re-root from the install the last re-root moved to"
        ),
        None => anyhow::bail!("this install's host issuer is not this vault's root"),
    }
    let moved = vault.re_root_host_to_new_seed(&current)?;
    let mut steps = vec![
        "Set ONEIRON_AUTH_SECRET (or the config's auth_secret) to the new secret before the next `oneiron serve`; the old secret is refused from now on.".to_owned(),
    ];
    steps.extend(root_move_steps(&vault, &moved, "the old secret")?);
    print_root_move_report(&moved, steps)
}

/// The steps every root move's report gives after its first: the retired
/// credentials (minted by `retired_by`) to mint again, the histories left
/// hidden, and, while the move left the vault with no live recovery key, the
/// three commands that enrol a new kit (L1-07-KIT-AFTER-MOVE = B).
pub(super) fn root_move_steps(
    vault: &oneiron::Vault,
    moved: &oneiron::authority::HostReRoot,
    retired_by: &str,
) -> anyhow::Result<Vec<String>> {
    let mut steps = Vec::new();
    if !moved.retired_slips.is_empty() {
        steps.push(format!(
            "Every credential {retired_by} minted has stopped working, as listed. Mint each agent again with `oneiron token agent --name <name>`, and pair your devices again with `oneiron token bootstrap`."
        ));
    }
    if moved.histories_left > 0 {
        steps.push(format!(
            "{} engine-written claim histories were not readable before the re-root and stay hidden.",
            moved.histories_left
        ));
    }
    if vault.genesis_fragile_now()? {
        steps.push(format!(
            "The move retired every recovery kit key this vault had enrolled, with every other key, so the vault holds no recovery method now, and `oneiron serve` shows the {} flag until you enrol a new kit: `oneiron recovery-kit issue`, then `oneiron recovery-kit confirm`, then `oneiron recovery-kit enroll-authority`.",
            oneiron::authority::GENESIS_FRAGILE_FLAG
        ));
    }
    Ok(steps)
}

/// Prints a root move's report: what moved, the credentials it retired, and
/// `steps`. Never a secret, a seed or a kit piece.
pub(super) fn print_root_move_report(
    moved: &oneiron::authority::HostReRoot,
    steps: Vec<String>,
) -> anyhow::Result<()> {
    let report = json!({
        "vault_id": hex(&moved.vault_id),
        "engine_writers_enrolled": moved.writers_enrolled,
        "machines_carried": moved.machines_carried,
        "machine_histories_carried": moved.histories_carried,
        "machine_histories_left": moved.histories_left,
        "retired_credentials": moved
            .retired_slips
            .iter()
            .map(|slip| json!({
                "slip_id": hex(&slip.slip_id),
                "holder_ref": slip.holder_ref,
                "actor_class": slip.actor_class,
            }))
            .collect::<Vec<_>>(),
        "next": steps,
    });
    writeln!(
        io::stdout().lock(),
        "{}",
        serde_json::to_string_pretty(&report)?
    )?;
    Ok(())
}

/// A secret file holds the secret and nothing else, and only its owner may
/// read it. One trailing line break is not part of the secret.
fn read_secret_file(path: &Path) -> anyhow::Result<Zeroizing<String>> {
    let mut file = std::fs::File::open(path)
        .map_err(|error| anyhow::anyhow!("open {}: {error}", path.display()))?;
    // Owner-only by its mode and, on macOS, by its ACL: an ACL entry can let
    // other users read a file whose mode says 600.
    super::credential_file::admit(path, &file)?;
    let mut text = Zeroizing::new(String::new());
    file.read_to_string(&mut text)
        .map_err(|error| anyhow::anyhow!("read {}: {error}", path.display()))?;
    let secret = text.strip_suffix('\n').map_or(text.as_str(), |line| {
        line.strip_suffix('\r').unwrap_or(line)
    });
    anyhow::ensure!(!secret.is_empty(), "{} holds no secret", path.display());
    Ok(Zeroizing::new(secret.to_owned()))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
