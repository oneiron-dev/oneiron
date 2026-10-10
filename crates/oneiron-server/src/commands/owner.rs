//! The owner's own commands on a stopped vault: doctor, backup, restore,
//! window recovery, export, the secret scan switch, registering and rotating
//! a secret, import consent and agent-run consent.
//!
//! Holding the vault's writer lease is the owner proof here, the same local
//! door the embedded export uses; a running `serve` answers the same actions
//! at `/v1/owner/*`. Output is JSON on stdout.

use std::io::{self, Read, Write};
use std::path::Path;

use oneiron::run_tree::GateConsentBundleAction;
use serde::Serialize;

use crate::cli::{
    BackupArgs, DoctorArgs, ExportArgs, ImportCommand, RecoverWindowArgs, RestoreArgs, RunsCommand,
    SecretClass, SecretRegisterArgs, SecretRotateArgs, SecretScanArgs, SecretScanSwitch,
    SecretsCommand, WhoamiArgs,
};
use crate::config::{
    BackupConfig, ServeArgs, ServeConfig, resolve_backup_config, resolve_serve_config,
};
use crate::owner::backup::{self, BackupPlan};
use crate::owner::{imports, local_owner, location, note_imports, runs, secrets};

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
    open_stopped_vault(config, &format!("or ask it: `oneiron api raw {route}`"))
}

/// [`open_vault`] for a command no running server answers: `instead` says
/// what to do while one holds the vault.
fn open_stopped_vault(config: &ServeConfig, instead: &str) -> anyhow::Result<oneiron::Vault> {
    let path = &config.vault_path;
    anyhow::ensure!(
        path.join("data.mdb").is_file(),
        "vault {} does not exist; `oneiron init` creates one",
        path.display()
    );
    oneiron::Vault::open_owned(path, vault_config(config)).map_err(|error| match error {
        oneiron::Error::ConcurrentWrite(oneiron::VAULT_WRITER_LEASE_HELD) => anyhow::anyhow!(
            "vault {} is open in a running `oneiron serve`; stop it first, {instead}",
            path.display()
        ),
        error => anyhow::anyhow!("open vault {}: {error}", path.display()),
    })
}

pub fn doctor(args: DoctorArgs) -> anyhow::Result<()> {
    emit(&doctor_report(args)?)
}

/// Where the vault lives and how it is, then the rest of its health. Serve
/// settings never stop this report: one that does not resolve is listed in
/// `config_errors` beside it, and backups are read with the defaults if the
/// `[backup]` section itself is what fails.
fn doctor_report(args: DoctorArgs) -> anyhow::Result<serde_json::Value> {
    let serve = ServeArgs {
        config: args.config,
        vault_path: Some(args.path.clone()),
        dimensions: args.dimensions,
        map_size: args.map_size,
        dict_search_paths: args.dict_search_paths.clone(),
        ..ServeArgs::default()
    };
    let mut config_errors = Vec::new();
    let mut note_error = |error: anyhow::Error| {
        let error = format!("{error:#}");
        if !config_errors.contains(&error) {
            config_errors.push(error);
        }
    };
    // The shape `serve` and `import` open the vault in: the config's
    // dimensions, map size and dictionaries, under the flags. The rest stays
    // the server default, so a configured embedder that disagrees with the
    // vault does not keep doctor from reporting it. Settings that do not
    // resolve leave the flags over the defaults.
    let mut vault_config = oneiron::VaultConfig::server();
    let serve_config = resolve_serve_config(&serve);
    let unresolved = serve_config.is_err();
    let dict_search_paths = match serve_config {
        Ok(config) => {
            vault_config.dimensions = config.dimensions;
            vault_config.map_size = config.map_size;
            config.dict_search_paths
        }
        Err(error) => {
            note_error(error);
            vault_config.dimensions = args.dimensions.unwrap_or(vault_config.dimensions);
            vault_config.map_size = args.map_size.unwrap_or(vault_config.map_size);
            args.dict_search_paths.unwrap_or_default()
        }
    };
    vault_config.dict_search_paths = super::resolve_dict_search_paths(&dict_search_paths).paths;
    let backup = resolve_backup_config(&serve).unwrap_or_else(|error| {
        note_error(error.context(
            "the [backup] settings did not resolve, so the backups shown are at the default location",
        ));
        BackupConfig::default()
    });
    let plan = BackupPlan::new(&args.path, backup.dir_for(&args.path), backup.keep);
    let every = backup.enabled.then_some(backup.every_hours);
    let mut report = match oneiron::Vault::open_owned(&args.path, vault_config) {
        Ok(vault) => {
            let mut report = serde_json::to_value(vault.doctor()?)?;
            report["location"] =
                serde_json::to_value(location::locate(&args.path, Some(&vault), &plan, every)?)?;
            report
        }
        Err(oneiron::Error::ConcurrentWrite(oneiron::VAULT_WRITER_LEASE_HELD)) => {
            // The filesystem facts still answer "where is my data".
            let mut location = location::locate(&args.path, None, &plan, every)?;
            location.note = Some(
                "a running `oneiron serve` holds this vault; `oneiron api raw GET /v1/owner/status` reads the rest"
                    .to_owned(),
            );
            serde_json::json!({ "location": location })
        }
        Err(error) if unresolved => anyhow::bail!(
            "open vault {} failed: {error}; it was opened without the config's dimensions and \
             map size, which did not resolve: {}",
            args.path.display(),
            config_errors.join("; ")
        ),
        Err(error) => anyhow::bail!("open vault {} failed: {error}", args.path.display()),
    };
    if !config_errors.is_empty() {
        report["config_errors"] = serde_json::to_value(config_errors)?;
    }
    Ok(report)
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
    if let Some(previous) = &args.activate {
        return emit(&backup::activate(
            previous,
            &config.vault_path,
            vault_config(&config),
        )?);
    }
    let backup = args
        .backup
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("name the backup file to restore"))?;
    if args.rehearse {
        // Read off the disk, beside a `serve` that may hold the vault.
        let source = oneiron::recovery::checkpoint::SideRestoreSource::read(&config.vault_path)?;
        return emit(&backup::rehearse(
            backup,
            vault_config(&config),
            args.scratch.as_deref(),
            &source,
        )?);
    }
    emit(&backup::restore_over(
        backup,
        &config.vault_path,
        vault_config(&config),
    )?)
}

#[derive(Serialize)]
struct RecoveredWindow {
    window: String,
    /// `healthy`, `targeted_chunk_repair` or `full_rebuild`.
    tier: &'static str,
    /// The window's manifest of chunk hashes, kept for the next recovery.
    manifest: std::path::PathBuf,
    /// A bad manifest, renamed intact beside the manifest.
    quarantined: Option<std::path::PathBuf>,
    /// The chunks this recovery rebuilt.
    rebuilt: Vec<String>,
}

/// Recovers one window of the stopped vault from a canonical snapshot of its
/// CRDT state (ARCH-0038). Holding the writer lease stops the window's
/// writers; the engine holds the snapshot in memory and writes none to disk.
pub fn recover_window(args: RecoverWindowArgs) -> anyhow::Result<()> {
    let config = resolve_serve_config(&args.serve)?;
    let vault = open_stopped_vault(
        &config,
        "since a window recovers only with its writers stopped",
    )?;
    let owner = local_owner(&vault)?;
    let dir = config.vault_path.join("recovery");
    let report = vault
        .recover_window_from_canonical_snapshot(
            &owner,
            &args.window,
            &dir,
            oneiron::recovery::RecoveryBudget::default(),
        )
        .map_err(|error| anyhow::anyhow!("recover window {}: {error}", args.window))?;
    emit(&RecoveredWindow {
        window: report.window,
        tier: match report.tier {
            oneiron::recovery::RecoveryTier::Healthy => "healthy",
            oneiron::recovery::RecoveryTier::TargetedChunkRepair => "targeted_chunk_repair",
            oneiron::recovery::RecoveryTier::FullRebuild => "full_rebuild",
        },
        manifest: report.manifest_path,
        quarantined: report.quarantine_path,
        rebuilt: report.obligations,
    })
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
pub(super) fn write_new_file(
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

/// The largest value read from stdin, as for the route's whole body.
const SECRET_VALUE_LIMIT: usize = 1 << 20;

pub fn secrets(command: SecretsCommand) -> anyhow::Result<()> {
    let value = read_secret_value(io::stdin().lock())?;
    match command {
        SecretsCommand::Register(args) => emit(&register_secret(*args, &value)?),
        SecretsCommand::Rotate(args) => emit(&rotate_secret(*args, &value)?),
    }
}

/// The value on stdin, exactly as given, in one buffer sized up front: the
/// read never moves it, so no copy is left behind, and it is wiped on drop.
fn read_secret_value(input: impl Read) -> anyhow::Result<zeroize::Zeroizing<Vec<u8>>> {
    let mut value = zeroize::Zeroizing::new(Vec::with_capacity(SECRET_VALUE_LIMIT + 1));
    input
        .take(SECRET_VALUE_LIMIT as u64 + 1)
        .read_to_end(&mut value)?;
    anyhow::ensure!(
        value.len() <= SECRET_VALUE_LIMIT,
        "a secret value is at most 1 MiB"
    );
    anyhow::ensure!(
        !value.is_empty(),
        "the secret value is read from stdin, and stdin was empty"
    );
    Ok(value)
}

/// Registers through the engine door the route uses, as the local owner.
fn register_secret(args: SecretRegisterArgs, value: &[u8]) -> anyhow::Result<secrets::Registered> {
    use oneiron::secret_custody::{
        CustodyClass, CustodyTier, ManifestSource, OwnerSecretRegistration, RequestedBinding,
    };
    let bindings = args
        .bindings
        .iter()
        .map(|binding| {
            let (effector, scopes) = binding.split_once('=').unwrap_or((binding, ""));
            RequestedBinding {
                effector: effector.to_owned(),
                tier_ceiling: None,
                scopes: scopes
                    .split(',')
                    .filter(|scope| !scope.is_empty())
                    .map(str::to_owned)
                    .collect(),
            }
        })
        .collect();
    let config = resolve_serve_config(&args.serve)?;
    let vault = open_vault(&config, "POST /v1/owner/secrets/register --data -")?;
    let owner = local_owner(&vault)?;
    let registered = vault.register_secret_as_owner(
        &owner,
        &OwnerSecretRegistration {
            name: &args.name,
            class: match args.class {
                SecretClass::CustodyPortable => CustodyClass::CustodyPortable,
                SecretClass::CustodyDeviceBound => CustodyClass::CustodyDeviceBound,
                SecretClass::CrossVault => CustodyClass::CrossVault,
            },
            device_only: args.device_only,
            rung: CustodyTier::from_u8(args.rung)
                .ok_or_else(|| anyhow::anyhow!("a rung is 0, 1 or 2"))?,
            bindings,
            manifest: args.repo.map(|repo| ManifestSource {
                repo,
                git_ref: args.git_ref,
            }),
            value,
        },
        vault.now_recorded_at(),
    )?;
    Ok(registered.into())
}

fn rotate_secret(args: SecretRotateArgs, value: &[u8]) -> anyhow::Result<secrets::Rotated> {
    let config = resolve_serve_config(&args.serve)?;
    let vault = open_vault(&config, "POST /v1/owner/secrets/rotate --data -")?;
    let owner = local_owner(&vault)?;
    Ok(vault
        .rotate_secret_as_owner(&owner, &args.name, value, vault.now_recorded_at())?
        .into())
}

/// A batch file: imported claims, or the notes `import notes` wrote.
enum Batch {
    Claims(imports::ImportBatch),
    Notes(note_imports::NoteBatch),
}

fn read_batch(source: &str) -> anyhow::Result<Batch> {
    let raw = if source == "-" {
        let mut raw = String::new();
        io::stdin().read_to_string(&mut raw)?;
        raw
    } else {
        std::fs::read_to_string(source)
            .map_err(|error| anyhow::anyhow!("read batch {source}: {error}"))?
    };
    // A saved `import preview` output works as is: take its `batch`. A notes
    // batch holds a folder's text, so it is moved, never copied.
    let mut value: serde_json::Value = serde_json::from_str(&raw)?;
    drop(raw);
    let batch = if value.get("batch").is_some() {
        value["batch"].take()
    } else {
        value
    };
    let read = if batch.get("notes").is_some() {
        serde_json::from_value(batch).map(Batch::Notes)
    } else {
        serde_json::from_value(batch).map(Batch::Claims)
    };
    read.map_err(|error| anyhow::anyhow!("batch JSON: {error}"))
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
        ImportCommand::Notes(args) => return super::history_import::notes::import_notes(*args),
        ImportCommand::Preview(args) => (args.batch, None, args.serve),
        ImportCommand::Approve(args) => (args.batch, Some((true, args.digest)), args.serve),
        ImportCommand::Decline(args) => (args.batch, Some((false, args.digest)), args.serve),
    };
    let config = resolve_serve_config(&serve)?;
    let vault = open_vault(&config, "POST /v1/owner/imports/<preview|approve|decline>")?;
    let owner = local_owner(&vault)?;
    match (read_batch(&batch)?, digest) {
        (Batch::Claims(batch), None) => emit(&imports::preview(&vault, &owner, batch)?),
        (Batch::Claims(batch), Some((true, digest))) => {
            emit(&imports::approve(&vault, &owner, &batch, &digest)?)
        }
        (Batch::Claims(batch), Some((false, digest))) => {
            emit(&imports::decline(&vault, &owner, &batch, &digest)?)
        }
        (Batch::Notes(batch), None) => emit(&note_imports::preview(&vault, &owner, batch)?),
        (Batch::Notes(batch), Some((true, digest))) => {
            emit(&note_imports::approve(&vault, &owner, batch, &digest)?)
        }
        (Batch::Notes(batch), Some((false, digest))) => {
            emit(&note_imports::decline(&vault, &owner, batch, &digest)?)
        }
    }
}

/// Deciding a Dreamer proposal writes its signed history with the host's
/// machine key (ONE-1634), so the command holds the host root as `serve` does
/// when the config names its secret. Without one, a run the Dreamer proposed
/// stays undecided here; a running server decides it at `/v1/owner/runs`.
fn hold_host_root(config: &ServeConfig, vault: &oneiron::Vault) -> anyhow::Result<()> {
    let Some(secret) = config
        .sync_server_config()
        .auth_secret
        .filter(|secret| !secret.is_empty())
    else {
        return Ok(());
    };
    let issuer = oneiron::authority::HostSlipIssuer::from_secret(secret.as_bytes())?;
    vault.ensure_host_root_slip(&issuer)?;
    vault.provision_engine_machine_identities(&issuer)?;
    Ok(())
}

pub fn runs(command: RunsCommand) -> anyhow::Result<()> {
    let serve = match &command {
        RunsCommand::Pending(args) => &args.serve,
        RunsCommand::Show(args) => &args.serve,
        RunsCommand::Approve(args) | RunsCommand::Decline(args) => &args.serve,
    };
    let config = resolve_serve_config(serve)?;
    let vault = open_vault(&config, "GET /v1/owner/runs")?;
    if matches!(command, RunsCommand::Approve(_) | RunsCommand::Decline(_)) {
        hold_host_root(&config, &vault)?;
    }
    match command {
        RunsCommand::Pending(_) => emit(&runs::pending(&vault)?),
        RunsCommand::Show(args) => {
            let run = runs::RunName::from_fields(args.run_id.as_deref(), args.run_ref.as_deref())?;
            emit(&runs::review(&vault, &local_owner(&vault)?, run)?)
        }
        RunsCommand::Approve(args) => {
            let run = runs::RunName::from_fields(args.run_id.as_deref(), args.run_ref.as_deref())?;
            emit(&runs::resolve(
                &vault,
                &local_owner(&vault)?,
                run,
                &args.bundle,
                GateConsentBundleAction::Approve,
            )?)
        }
        RunsCommand::Decline(args) => {
            let run = runs::RunName::from_fields(args.run_id.as_deref(), args.run_ref.as_deref())?;
            emit(&runs::resolve(
                &vault,
                &local_owner(&vault)?,
                run,
                &args.bundle,
                GateConsentBundleAction::Decline,
            )?)
        }
    }
}

#[cfg(test)]
mod tests;
