//! `oneiron doctor`: where the vault lives and how it is, read on a
//! stopped vault or beside a running `serve` (moved out of `owner` whole).

use crate::cli::DoctorArgs;
use crate::commands::resolve_dict_search_paths;
use crate::config::{BackupConfig, ServeArgs, resolve_backup_config, resolve_serve_config};
use crate::owner::backup::BackupPlan;
use crate::owner::embedder::EmbedderReport;
use crate::owner::location;

/// Where the vault lives and how it is, then the rest of its health. Serve
/// settings never stop this report: one that does not resolve is listed in
/// `config_errors` beside it, and backups are read with the defaults if the
/// `[backup]` section itself is what fails.
pub(super) fn doctor_report(args: DoctorArgs) -> anyhow::Result<serde_json::Value> {
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
    // dimensions, map size and dictionaries, under the flags, and a sealed
    // vault's page seal from this device's keystore (FIX 1944). The rest stays
    // the server default, so a configured embedder that disagrees with the
    // vault does not keep doctor from reporting it. Settings that do not
    // resolve leave the flags over the defaults, and no seal.
    let mut vault_config = oneiron::VaultConfig::server();
    let serve_config = resolve_serve_config(&serve);
    let unresolved = serve_config.is_err();
    let mut embedder = None;
    let dict_search_paths = match serve_config {
        Ok(config) => {
            vault_config.page_seal = config.device_page_seal();
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
    vault_config.dict_search_paths = resolve_dict_search_paths(&dict_search_paths).paths;
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
