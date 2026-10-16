//! The owner's own commands on a stopped vault: doctor, backup, restore,
//! window and clock recovery, export, the secret scan switch, registering and
//! rotating a secret, import consent and agent-run consent.
//!
//! Holding the vault's writer lease is the owner proof here, the same local
//! door the embedded export uses; a running `serve` answers the same actions
//! at `/v1/owner/*`. Output is JSON on stdout.

use std::io::{self, Read, Write};
use std::path::Path;

use oneiron::claim::CallerLocality;
use oneiron::run_tree::GateConsentBundleAction;
use serde::Serialize;

use crate::cli::{
    BackupArgs, DoctorArgs, ExportArgs, HandoffAlarmsCommand, ImportCommand, RecoverClockArgs,
    RecoverWindowArgs, RestoreArgs, RunsCommand, SecretClass, SecretRegisterArgs, SecretRotateArgs,
    SecretScanArgs, SecretScanSwitch, SecretsCommand, WhoamiArgs,
};
use crate::config::{
    BackupConfig, ServeArgs, ServeConfig, resolve_backup_config, resolve_serve_config,
};
use crate::owner::backup::{self, BackupPlan};
use crate::owner::embedder::EmbedderReport;
use crate::owner::stamp::rfc3339_secs;
use crate::owner::{imports, local_owner, location, note_imports, runs, secrets};

pub(super) fn emit(value: &impl Serialize) -> anyhow::Result<()> {
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

pub(super) fn vault_config(config: &ServeConfig) -> oneiron::VaultConfig {
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
    open_stopped_vault_with(config, vault_config(config), instead)
}

/// [`open_stopped_vault`] under a vault config the command adjusted.
pub(super) fn open_stopped_vault_with(
    config: &ServeConfig,
    vault_config: oneiron::VaultConfig,
    instead: &str,
) -> anyhow::Result<oneiron::Vault> {
    let path = &config.vault_path;
    anyhow::ensure!(
        path.join("data.mdb").is_file(),
        "vault {} does not exist; `oneiron init` creates one",
        path.display()
    );
    let vault = oneiron::Vault::open_owned(path, vault_config).map_err(|error| match error {
        oneiron::Error::ConcurrentWrite(oneiron::VAULT_WRITER_LEASE_HELD) => anyhow::anyhow!(
            "vault {} is open in a running `oneiron serve`; stop it first, {instead}",
            path.display()
        ),
        error => anyhow::anyhow!("open vault {}: {error}", path.display()),
    })?;
    // A command that signs (a delete's receipt, a settings edit) needs this
    // install's keys from the keystore.
    config.keystore.install_on(&vault, path);
    Ok(vault)
}

pub fn doctor(args: DoctorArgs) -> anyhow::Result<()> {
    emit(&doctor_report(args)?)
}

/// Where the vault lives and how it is, then the rest of its health. Serve
/// settings never stop this report: one that does not resolve is listed in
/// `config_errors` beside it, and backups are read with the defaults if the
/// `[backup]` section itself is what fails.
fn doctor_report(args: DoctorArgs) -> anyhow::Result<serde_json::Value> {
    let vectors_from = args.vectors_from;
    let vectors_runtime = args.vectors_runtime;
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
    let mut embedder = None;
    let dict_search_paths = match serve_config {
        Ok(config) => {
            vault_config.dimensions = config.dimensions;
            vault_config.map_size = config.map_size;
            embedder = config.embedder;
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
    // A vault that holds vectors opens only under its own model (bug repro:
    // doctor opened every vault under none and failed on each that holds
    // vectors). It is read without opening the vault; opening under it pins
    // nothing new. A vault that cannot be read, or whose stored id is not one
    // a vault opens under, is opened as before, and the doctor reports it.
    vault_config.embedding_model = oneiron::Vault::stored_embedding_model(&args.path)
        .ok()
        .flatten()
        .filter(|model| oneiron::store::validate_embedding_model_id(model).is_ok());
    let mut report = match oneiron::Vault::open_owned(&args.path, vault_config) {
        Ok(vault) => {
            let doctor = vault.doctor()?;
            let mut report = serde_json::to_value(&doctor)?;
            // Which device and runtime computed the stored vectors, so one
            // device's can be found and embedded again (ARCH-0036).
            report["vector_provenance"] =
                serde_json::to_value(vault.embedding_provenance_counts()?)?;
            if let Some(device) = vectors_from {
                let ids = vault.vectors_by_provenance(device, vectors_runtime.as_deref())?;
                report["vectors_from"] = serde_json::json!({
                    "device": device,
                    "runtime": vectors_runtime,
                    "ids": ids.iter().map(oneiron::EntityId::to_hex).collect::<Vec<_>>(),
                });
            }
            report["location"] =
                serde_json::to_value(location::locate(&args.path, Some(&vault), &plan, every)?)?;
            report["embedder"] = serde_json::to_value(EmbedderReport::unobserved(
                embedder.as_ref(),
                Some(&doctor),
                "doctor reads the vault, not a running server, and loads no model; \
                 `oneiron api raw GET /v1/owner/status` reports what a running server loaded",
            ))?;
            report
        }
        Err(oneiron::Error::ConcurrentWrite(oneiron::VAULT_WRITER_LEASE_HELD)) => {
            // The filesystem facts still answer "where is my data".
            let mut location = location::locate(&args.path, None, &plan, every)?;
            location.note = Some(
                "a running `oneiron serve` holds this vault; `oneiron api raw GET /v1/owner/status` reads the rest"
                    .to_owned(),
            );
            let embedder = EmbedderReport::unobserved(
                embedder.as_ref(),
                None,
                "a running `oneiron serve` holds this vault; `oneiron api raw GET /v1/owner/status` \
                 reports the model it loaded",
            );
            serde_json::json!({ "location": location, "embedder": embedder })
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
    // A backup opens with this install's keystore, as configured.
    let keystore = config.keystore.open(&config.vault_path)?;
    if args.rehearse {
        // Read off the disk, beside a `serve` that may hold the vault.
        let mut source =
            oneiron::recovery::checkpoint::SideRestoreSource::read(&config.vault_path)?;
        if let Some(keystore) = keystore {
            source = source.with_keystore(keystore);
        }
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
        keystore,
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
struct RecoveredClock {
    /// Where the clock holder proofs are judged on stood.
    old_floor: String,
    /// Where it stands now: this host's clock.
    new_floor: String,
    /// How far ahead it was, in seconds.
    gap_secs: u64,
    /// No proof signed before this is admitted again.
    not_before: String,
}

/// Lets agents back in after the host clock ran ahead and was set back:
/// while the vault's proof clock sits ahead, every fresh holder proof gets
/// 401. Holding the writer lease keeps a running `serve` out; the engine
/// refuses when the clock is not ahead, or when lowering it would reopen a
/// proof it no longer remembers.
pub fn recover_clock(args: RecoverClockArgs) -> anyhow::Result<()> {
    use oneiron::authority::ProofClockRecovery;
    let config = resolve_serve_config(&args.serve)?;
    let vault = open_stopped_vault(&config, "then run this again")?;
    let owner = local_owner(&vault)?;
    match vault.recover_proof_clock(&owner)? {
        ProofClockRecovery::Recovered {
            old_floor,
            new_floor,
            not_before,
        } => emit(&RecoveredClock {
            old_floor: rfc3339_secs(old_floor),
            new_floor: rfc3339_secs(new_floor),
            gap_secs: old_floor - new_floor,
            not_before: rfc3339_secs(not_before),
        }),
        ProofClockRecovery::NotAhead { floor, wall } => anyhow::bail!(
            "nothing to recover: the vault's proof clock ({}) is not ahead of this host's \
             clock ({})",
            rfc3339_secs(floor),
            rfc3339_secs(wall)
        ),
        ProofClockRecovery::Forgotten {
            floor,
            forgotten_before,
            wall,
        } => anyhow::bail!(
            "not recovered: agents connected while the host clock was ahead, and the vault \
             no longer remembers every proof it admitted then (up to {}): the clock stayed \
             ahead for over a day, or an older version kept each proof for a minute only. \
             It must keep refusing every proof signed before then, so lowering its clock \
             would not let agents in. Agents get in again once this host's clock ({}) \
             reaches {}",
            rfc3339_secs(forgotten_before),
            rfc3339_secs(wall),
            rfc3339_secs(floor)
        ),
    }
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
    let vault = open_vault(&config, "POST /v1/core/facade/vault.export")?;
    let owner = vault
        .ensure_embedded_owner_actor()
        .map_err(|error| anyhow::anyhow!("vault owner unavailable: {error}"))?;
    // The owner's own `vault.export`, so its verb hooks run around it
    // (ARCH-0080 §3).
    let memory = vault.memory(owner, oneiron::edge::EdgeActorClass::Human);
    let export = oneiron::task_verb::verb_hook_boundary::typed_row(
        &memory,
        "vault.export",
        oneiron::memory::ExportOptions {
            format: Some(args.format),
            include_secrets: Some(args.include_secrets),
        },
        |input| memory.export(&input),
    )
    .map_err(|error| anyhow::anyhow!("export failed: {error}"))?;
    let Some(out) = args.out else {
        io::stdout().lock().write_all(&export.archive)?;
        return Ok(());
    };
    write_new_file(&out, |file| {
        file.write_all(&export.archive)?;
        file.sync_all()
    })?;
    emit(&Exported {
        file: &out,
        format: export.format,
        bytes: export.archive.len(),
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
    let value = read_secret_value(raw_stdin()?)?;
    match command {
        SecretsCommand::Register(args) => emit(&register_secret(*args, &value)?),
        SecretsCommand::Rotate(args) => emit(&rotate_secret(*args, &value)?),
    }
}

/// Stdin's own file, unbuffered. `io::Stdin` copies a short read through a
/// process-wide buffer that is never wiped.
fn raw_stdin() -> io::Result<std::fs::File> {
    #[cfg(unix)]
    let owned = std::os::fd::AsFd::as_fd(&io::stdin()).try_clone_to_owned()?;
    #[cfg(windows)]
    let owned = std::os::windows::io::AsHandle::as_handle(&io::stdin()).try_clone_to_owned()?;
    Ok(std::fs::File::from(owned))
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

#[derive(Serialize)]
struct ImportedArchive {
    inserted_entities: usize,
    unchanged_entities: usize,
    omitted_entities: usize,
    archived_receipt_sources: usize,
    imported_results: usize,
    withheld_results: usize,
    restored_secrets: usize,
    unchanged_secrets: usize,
    /// Secrets the archive carried as handles only: re-enter each one.
    missing_secrets: Vec<String>,
}

/// Re-imports a whole-vault archive through the vault's import doors.
fn import_archive(args: crate::cli::ImportArchiveArgs) -> anyhow::Result<()> {
    let bytes = std::fs::read(&args.path)
        .map_err(|error| anyhow::anyhow!("read {}: {error}", args.path.display()))?;
    let config = resolve_serve_config(&args.serve)?;
    let vault = open_stopped_vault(&config, "stop `serve` to import an archive")?;
    let receipt = vault
        .import_whole_vault_archive(&bytes)
        .map_err(|error| anyhow::anyhow!("archive import failed: {error}"))?;
    emit(&ImportedArchive {
        inserted_entities: receipt.inserted_entities,
        unchanged_entities: receipt.unchanged_entities,
        omitted_entities: receipt.omitted_entities,
        archived_receipt_sources: receipt.archived_receipt_sources,
        imported_results: receipt.imported_results,
        withheld_results: receipt.withheld_results,
        restored_secrets: receipt.restored_secrets,
        unchanged_secrets: receipt.unchanged_secrets,
        missing_secrets: receipt
            .missing_secrets
            .into_iter()
            .map(|secret| secret.name)
            .collect(),
    })
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
        ImportCommand::HookTranscript(args) => {
            return super::history_import::import_history(HistorySource::HookTranscript, *args);
        }
        ImportCommand::Notes(args) => return super::history_import::notes::import_notes(*args),
        ImportCommand::Archive(args) => return import_archive(*args),
        ImportCommand::Folder(command) => {
            return super::history_import::notes::folder::import_folder(command);
        }
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

/// The saved fork alarms a held root handoff left, and the owner's
/// acknowledgement of one; `serve` answers the same at
/// `/v1/owner/authority/handoff-alarms`.
pub fn handoff_alarms(command: HandoffAlarmsCommand) -> anyhow::Result<()> {
    let serve = match &command {
        HandoffAlarmsCommand::List(args) => &args.serve,
        HandoffAlarmsCommand::Acknowledge(args) => &args.serve,
    };
    let config = resolve_serve_config(serve)?;
    let vault = open_vault(&config, "GET /v1/owner/authority/handoff-alarms")?;
    match command {
        HandoffAlarmsCommand::List(_) => emit(&vault.authority_handoff_alarms()?),
        HandoffAlarmsCommand::Acknowledge(args) => {
            emit(&vault.acknowledge_authority_handoff_alarm(&local_owner(&vault)?, &args.signer)?)
        }
    }
}

/// The owner's legal holds (OF-470) on a stopped vault; `serve` answers the
/// same at `/v1/owner/legal-holds`. Lifting a hold is only the one "Lift the
/// hold and erase?" confirm: its title and prompt are printed first, and it
/// acts only with `--yes`.
pub fn legal_holds(command: crate::cli::LegalHoldsCommand) -> anyhow::Result<()> {
    use crate::cli::{LegalHoldPlaceArgs, LegalHoldWidenArgs, LegalHoldsCommand};
    use oneiron::deletion::{LIFT_AND_ERASE_PROMPT, LIFT_AND_ERASE_TITLE};

    let (serve, route) = match &command {
        LegalHoldsCommand::List(args) => (&args.serve, "GET /v1/owner/legal-holds"),
        LegalHoldsCommand::Log(args) => (&args.serve, "GET /v1/owner/legal-holds/log"),
        LegalHoldsCommand::Place(args) => (&args.serve, "POST /v1/owner/legal-holds --data -"),
        LegalHoldsCommand::Widen(args) => {
            (&args.serve, "POST /v1/owner/legal-holds/widen --data -")
        }
        LegalHoldsCommand::LiftAndErase(args) => {
            eprintln!("{LIFT_AND_ERASE_TITLE}\n{LIFT_AND_ERASE_PROMPT}");
            anyhow::ensure!(
                args.yes,
                "nothing was lifted or erased; run it again with --yes to confirm"
            );
            (
                &args.serve,
                "POST /v1/owner/legal-holds/lift-and-erase --data -",
            )
        }
    };
    let config = resolve_serve_config(serve)?;
    let vault = open_vault(&config, route)?;
    let owner = local_owner(&vault)?;
    match command {
        LegalHoldsCommand::List(_) => emit(&vault.legal_holds(&owner)?),
        LegalHoldsCommand::Log(_) => emit(&vault.legal_hold_log(&owner)?),
        LegalHoldsCommand::Place(args) => {
            let LegalHoldPlaceArgs {
                targets,
                matter_ref,
                ..
            } = *args;
            emit(&vault.place_legal_hold(&owner, hold_targets(&targets)?, matter_ref)?)
        }
        LegalHoldsCommand::Widen(args) => {
            let LegalHoldWidenArgs {
                hold_id, targets, ..
            } = *args;
            let hold = hold_id_arg(&hold_id)?;
            emit(&vault.widen_legal_hold(&owner, hold, hold_targets(&targets)?)?)
        }
        LegalHoldsCommand::LiftAndErase(args) => {
            let records = args
                .records
                .iter()
                .map(|record| hold_id_arg(record))
                .collect::<anyhow::Result<Vec<_>>>()?;
            let outcome = vault.confirm_lift_legal_hold_and_erase(&owner, &records)?;
            emit(&oneiron::task_verb::sdk::LegalHoldLiftAndErased::from(
                outcome,
            ))
        }
    }
}

/// A 32-hex id given on the command line.
fn hold_id_arg(hex: &str) -> anyhow::Result<oneiron::EntityId> {
    oneiron::EntityId::from_hex(hex).map_err(|_| anyhow::anyhow!("{hex} is not a 32-hex id"))
}

/// The engine's hold targets from `--record` and `--gate-partition`.
fn hold_targets(
    args: &crate::cli::LegalHoldTargetArgs,
) -> anyhow::Result<Vec<oneiron::deletion::LegalHoldTarget>> {
    use oneiron::deletion::LegalHoldTarget;
    let mut targets = Vec::with_capacity(args.records.len() + args.gate_partitions.len());
    for record in &args.records {
        targets.push(LegalHoldTarget::Record(hold_id_arg(record)?));
    }
    for partition in &args.gate_partitions {
        targets.push(LegalHoldTarget::GatePartition(match partition.as_str() {
            "none" => None,
            claim => Some(hold_id_arg(claim)?),
        }));
    }
    Ok(targets)
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
        // The CLI runs on this device.
        RunsCommand::Pending(_) => emit(&runs::pending(&vault, CallerLocality::OnDevice)?),
        RunsCommand::Show(args) => {
            let run = runs::RunName::from_fields(args.run_id.as_deref(), args.run_ref.as_deref())?;
            emit(&runs::review(
                &vault,
                &local_owner(&vault)?,
                run,
                CallerLocality::OnDevice,
            )?)
        }
        RunsCommand::Approve(args) => {
            let run = runs::RunName::from_fields(args.run_id.as_deref(), args.run_ref.as_deref())?;
            emit(&runs::resolve(
                &vault,
                &local_owner(&vault)?,
                run,
                &args.bundle,
                GateConsentBundleAction::Approve,
                CallerLocality::OnDevice,
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
                CallerLocality::OnDevice,
            )?)
        }
    }
}

#[cfg(test)]
mod tests;
