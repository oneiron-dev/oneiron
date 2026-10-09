//! The owner's own commands on a stopped vault: doctor, backup, restore,
//! export, the secret scan switch, import consent and agent-run consent.
//!
//! Holding the vault's writer lease is the owner proof here, the same local
//! door the embedded export uses; a running `serve` answers the same actions
//! at `/v1/owner/*`. Output is JSON on stdout.

use std::io::{self, Read, Write};
use std::path::Path;

use oneiron::run_tree::GateConsentBundleAction;
use serde::Serialize;

use crate::cli::{
    BackupArgs, DoctorArgs, ExportArgs, ImportCommand, RestoreArgs, RunsCommand, SecretScanArgs,
    SecretScanSwitch, WhoamiArgs,
};
use crate::config::{ServeArgs, ServeConfig, resolve_serve_config};
use crate::owner::backup::{self, BackupPlan};
use crate::owner::{imports, local_owner, location, runs};

fn emit(value: &impl Serialize) -> anyhow::Result<()> {
    let mut stdout = io::stdout().lock();
    serde_json::to_writer_pretty(&mut stdout, value)?;
    writeln!(stdout)?;
    Ok(())
}

fn backup_plan(config: &ServeConfig) -> BackupPlan {
    BackupPlan::new(
        &config.vault_path,
        config.backup.dir_for(&config.vault_path),
        config.backup.keep,
    )
}

fn vault_config(config: &ServeConfig) -> oneiron::VaultConfig {
    let mut vault_config = config.vault_config();
    vault_config.dict_search_paths =
        super::resolve_dict_search_paths(&config.dict_search_paths).paths;
    vault_config
}

/// Opens the configured, existing vault for one owner command. `route` names
/// the `/v1/owner` route to use instead while a server holds the vault.
fn open_vault(config: &ServeConfig, route: &str) -> anyhow::Result<oneiron::Vault> {
    let path = &config.vault_path;
    anyhow::ensure!(
        path.join("data.mdb").is_file(),
        "vault {} does not exist; `oneiron init` creates one",
        path.display()
    );
    oneiron::Vault::open_owned(path, vault_config(config)).map_err(|error| match error {
        oneiron::Error::ConcurrentWrite(oneiron::VAULT_WRITER_LEASE_HELD) => anyhow::anyhow!(
            "vault {} is open in a running `oneiron serve`; stop it first, or ask it: \
             `oneiron api raw {route}`",
            path.display()
        ),
        error => anyhow::anyhow!("open vault {}: {error}", path.display()),
    })
}

pub fn doctor(args: DoctorArgs) -> anyhow::Result<()> {
    let config = resolve_serve_config(&ServeArgs {
        config: args.config,
        vault_path: Some(args.vault.path.clone()),
        ..ServeArgs::default()
    })?;
    let plan = backup_plan(&config);
    let every = config.backup.enabled.then_some(config.backup.every_hours);
    let mut vault_config = oneiron::VaultConfig::server();
    vault_config.dimensions = args.vault.dimensions;
    vault_config.map_size = args.vault.map_size;
    vault_config.dict_search_paths =
        super::resolve_dict_search_paths(&args.vault.dict_search_paths.clone().unwrap_or_default())
            .paths;
    let vault = match oneiron::Vault::open_owned(&args.vault.path, vault_config) {
        Ok(vault) => vault,
        Err(oneiron::Error::ConcurrentWrite(oneiron::VAULT_WRITER_LEASE_HELD)) => {
            // The filesystem facts still answer "where is my data".
            let mut report = location::locate(&args.vault.path, None, &plan, every)?;
            report.note = Some(
                "a running `oneiron serve` holds this vault; `oneiron api raw GET /v1/owner/status` reads the rest"
                    .to_owned(),
            );
            return emit(&serde_json::json!({ "location": report }));
        }
        Err(error) => anyhow::bail!("open vault {} failed: {error}", args.vault.path.display()),
    };
    let mut report = serde_json::to_value(vault.doctor()?)?;
    report["location"] = serde_json::to_value(location::locate(
        &args.vault.path,
        Some(&vault),
        &plan,
        every,
    )?)?;
    emit(&report)
}

pub fn backup(args: BackupArgs) -> anyhow::Result<()> {
    let mut config = resolve_serve_config(&args.serve)?;
    if let Some(dir) = args.dir {
        config.backup.dir = Some(dir);
    }
    if let Some(keep) = args.keep {
        anyhow::ensure!(keep > 0, "--keep must be at least 1");
        config.backup.keep = keep;
    }
    let plan = backup_plan(&config);
    if args.list {
        return emit(&backup::list(&plan)?);
    }
    let vault = open_vault(&config, "POST /v1/owner/backups")?;
    emit(&backup::take(&vault, &plan)?)
}

pub fn restore(args: RestoreArgs) -> anyhow::Result<()> {
    let config = resolve_serve_config(&args.serve)?;
    if args.rehearse {
        return emit(&backup::rehearse(
            &args.backup,
            vault_config(&config),
            args.scratch.as_deref(),
        )?);
    }
    emit(&backup::restore_over(
        &args.backup,
        &config.vault_path,
        vault_config(&config),
    )?)
}

#[derive(Serialize)]
struct Whoami {
    /// The PERSON a credential names to act as this vault's owner.
    owner_principal: String,
    /// The class that credential binds for the owner's read lane.
    actor_class: &'static str,
    /// The authority vault id its slips carry; `null` until the vault is
    /// rooted (its first `serve` or `token bootstrap` with an issuer key).
    vault_id: Option<String>,
}

/// Prints who owns the stopped vault: the principal facade credentials name
/// and the vault id they carry. Read-only apart from the housekeeping every
/// open does; it never roots the vault.
pub fn whoami(args: WhoamiArgs) -> anyhow::Result<()> {
    let config = resolve_serve_config(&ServeArgs {
        config: args.config,
        vault_path: Some(args.path),
        ..ServeArgs::default()
    })?;
    let vault = open_vault(
        &config,
        "POST /v1/core/facade/describe --data '{\"self\":true}'",
    )?;
    let owner = vault
        .ensure_embedded_owner_actor()
        .map_err(|error| anyhow::anyhow!("vault owner unavailable: {error}"))?;
    let vault_id = vault
        .authority_fold()?
        .vault_id
        .map(|id| id.iter().map(|byte| format!("{byte:02x}")).collect());
    emit(&Whoami {
        owner_principal: owner.to_hex(),
        actor_class: "human",
        vault_id,
    })
}

#[derive(Serialize)]
struct Exported<'a> {
    file: &'a Path,
    format: String,
    bytes: usize,
}

pub fn export(args: ExportArgs) -> anyhow::Result<()> {
    let config = resolve_serve_config(&args.serve)?;
    let vault = open_vault(&config, "POST /v1/core/facade/export")?;
    let owner = vault
        .ensure_embedded_owner_actor()
        .map_err(|error| anyhow::anyhow!("vault owner unavailable: {error}"))?;
    let export = vault
        .memory(owner, oneiron::edge::EdgeActorClass::Human)
        .export(&oneiron::memory::ExportOptions {
            format: Some(args.format),
        })
        .map_err(|error| anyhow::anyhow!("export failed: {error}"))?;
    let Some(out) = args.out else {
        io::stdout().lock().write_all(export.rendered.as_bytes())?;
        return Ok(());
    };
    write_new_file(&out, |file| {
        file.write_all(export.rendered.as_bytes())?;
        file.sync_all()
    })?;
    emit(&Exported {
        file: &out,
        format: export.format,
        bytes: export.rendered.len(),
    })
}

/// Creates `out` (owner-only, never over an existing file) and fills it with
/// `write`. A failed write removes the partial file, so the same `--out` can
/// be retried.
fn write_new_file(
    out: &Path,
    write: impl FnOnce(&mut std::fs::File) -> io::Result<()>,
) -> anyhow::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(out)
        .map_err(|error| anyhow::anyhow!("create {}: {error}", out.display()))?;
    if let Err(error) = write(&mut file) {
        drop(file);
        let _ = std::fs::remove_file(out);
        anyhow::bail!("write {}: {error}", out.display());
    }
    Ok(())
}

pub fn secret_scan(args: SecretScanArgs) -> anyhow::Result<()> {
    let config = resolve_serve_config(&args.serve)?;
    let vault = open_vault(&config, "GET /v1/owner/secret-scan")?;
    let Some(switch) = args.mode else {
        return emit(&serde_json::json!({
            "mode": vault.secret_scan_mode()?,
            "changes": vault.secret_scan_change_log()?,
        }));
    };
    let mode = match switch {
        SecretScanSwitch::On => oneiron::policy_model::SecretScanMode::On,
        SecretScanSwitch::Off => oneiron::policy_model::SecretScanMode::Off,
    };
    let owner = local_owner(&vault)?;
    emit(&vault.set_secret_scan_mode(&owner, mode, vault.now_recorded_at())?)
}

fn read_batch(source: &str) -> anyhow::Result<imports::ImportBatch> {
    let raw = if source == "-" {
        let mut raw = String::new();
        io::stdin().read_to_string(&mut raw)?;
        raw
    } else {
        std::fs::read_to_string(source)
            .map_err(|error| anyhow::anyhow!("read batch {source}: {error}"))?
    };
    // A saved `import preview` output works as is: take its `batch`.
    let value: serde_json::Value = serde_json::from_str(&raw)?;
    let batch = value.get("batch").cloned().unwrap_or(value);
    serde_json::from_value(batch).map_err(|error| anyhow::anyhow!("batch JSON: {error}"))
}

pub fn import(command: ImportCommand) -> anyhow::Result<()> {
    use oneiron::ingest::history::HistorySource;
    // A batch decision: preview, or approve / decline with the digest.
    let (batch, digest, serve) = match command {
        ImportCommand::Chatgpt(args) => {
            return super::history_import::import_history(HistorySource::Chatgpt, *args);
        }
        ImportCommand::Claude(args) => {
            return super::history_import::import_history(HistorySource::Claude, *args);
        }
        ImportCommand::ClaudeCode(args) => {
            return super::history_import::import_history(HistorySource::ClaudeCode, *args);
        }
        ImportCommand::Codex(args) => {
            return super::history_import::import_history(HistorySource::Codex, *args);
        }
        ImportCommand::Preview(args) => (args.batch, None, args.serve),
        ImportCommand::Approve(args) => (args.batch, Some((true, args.digest)), args.serve),
        ImportCommand::Decline(args) => (args.batch, Some((false, args.digest)), args.serve),
    };
    let config = resolve_serve_config(&serve)?;
    let vault = open_vault(&config, "POST /v1/owner/imports/<preview|approve|decline>")?;
    let owner = local_owner(&vault)?;
    match digest {
        None => emit(&imports::preview(&vault, &owner, read_batch(&batch)?)?),
        Some((true, digest)) => emit(&imports::approve(
            &vault,
            &owner,
            &read_batch(&batch)?,
            &digest,
        )?),
        Some((false, digest)) => emit(&imports::decline(
            &vault,
            &owner,
            &read_batch(&batch)?,
            &digest,
        )?),
    }
}

pub fn runs(command: RunsCommand) -> anyhow::Result<()> {
    let serve = match &command {
        RunsCommand::Pending(args) => &args.serve,
        RunsCommand::Show(args) => &args.serve,
        RunsCommand::Approve(args) | RunsCommand::Decline(args) => &args.serve,
    };
    let config = resolve_serve_config(serve)?;
    let vault = open_vault(&config, "GET /v1/owner/runs")?;
    match command {
        RunsCommand::Pending(_) => emit(&runs::pending(&vault)?),
        RunsCommand::Show(args) => {
            emit(&runs::review(&vault, &local_owner(&vault)?, &args.run_id)?)
        }
        RunsCommand::Approve(args) => emit(&runs::resolve(
            &vault,
            &local_owner(&vault)?,
            &args.run_id,
            &args.bundle,
            GateConsentBundleAction::Approve,
        )?),
        RunsCommand::Decline(args) => emit(&runs::resolve(
            &vault,
            &local_owner(&vault)?,
            &args.run_id,
            &args.bundle,
            GateConsentBundleAction::Decline,
        )?),
    }
}

#[cfg(test)]
mod tests;
