//! `oneiron host re-root`: moves a stopped self-host vault's root to a new
//! host secret, in-chain (OF-455). The current secret signs one ReRoot for
//! the new secret's key, so the vault keeps its id, and the engine carries
//! its writers and its MACHINE claim histories to the new root in the same
//! transaction (`Vault::re_root_host`). Every slip the old secret minted
//! stops verifying; this command says so and lists them.
//!
//! A lost secret has no path here: a re-root needs the current root's
//! signature, and a second Genesis would change the vault id (OF-455).

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
            "warning: the new host secret is shorter than {MIN_RECOMMENDED_AUTH_SECRET_BYTES} bytes; every key this host signs with derives from it"
        )?;
    }
    let current = oneiron::authority::HostSlipIssuer::from_secret(current.as_bytes())?;
    let next = oneiron::authority::HostSlipIssuer::from_secret(next.as_bytes())?;
    anyhow::ensure!(
        current.public_key() != next.public_key(),
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
    match fold.roster.get(&current.public_key()) {
        Some(root) if !root.revoked && root.roles & oneiron::authority::ROLE_OWNER != 0 => {}
        Some(_) => anyhow::bail!(
            "the current host secret's key was this vault's root once, and a re-root retired it; use the secret the last re-root moved to"
        ),
        None => anyhow::bail!("the current host secret is not this vault's host secret"),
    }
    let moved = vault.re_root_host(&current, &next)?;
    let mut steps = vec![
        "Set ONEIRON_AUTH_SECRET (or the config's auth_secret) to the new secret before the next `oneiron serve`; the old secret is refused from now on.".to_owned(),
    ];
    if !moved.retired_slips.is_empty() {
        steps.push(
            "Every credential the old secret minted has stopped working, as listed. Mint each agent again with `oneiron token agent --name <name>`, and pair your devices again with `oneiron token bootstrap`.".to_owned(),
        );
    }
    if moved.histories_left > 0 {
        steps.push(format!(
            "{} engine-written claim histories were not readable before the re-root and stay hidden.",
            moved.histories_left
        ));
    }
    let report = json!({
        "vault_id": hex(&moved.vault_id),
        "engine_writers_enrolled": moved.writers_enrolled,
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
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = file.metadata()?.permissions().mode();
        anyhow::ensure!(
            mode & 0o077 == 0,
            "{} can be read by other users (mode {:o}); run `chmod 600` on it",
            path.display(),
            mode & 0o777
        );
    }
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
