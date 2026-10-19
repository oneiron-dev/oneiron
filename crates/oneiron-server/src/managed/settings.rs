//! The vault's settings file (`--settings-file`): the owner's feature settings
//! for a vault our cloud hosts, in the server's own config schema.
//!
//! The file is the one layer a managed vault reads settings from, and it is
//! read once, before anything uses the configuration. Before any file it
//! names is read, it is refused leaf by leaf: a leaf the supervisor owns, a
//! key named by an environment variable and a key the schema does not have
//! are refused by presence alone, and every owner path must lie in this
//! vault's own storage. The rest is settled over the configuration argv
//! built, through the config file's own apply and validators
//! ([`crate::config::merge::settle_managed_settings`]). Nothing here reads
//! the environment, HOME or a default config path.

use std::path::{Component, Path, PathBuf};

use anyhow::Context as _;

use crate::config::merge::{settings_schema_keys, settle_managed_settings};
use crate::config::{EmbedderProvider, KeystoreBackend, ServeArgs, ServeConfig};
use crate::runtime::RuntimeMode;

use super::args::{ManagedArgs, ManagedError, SettingsRefusal};

/// The leaves the supervisor owns, as dotted fields (`*` is any one key): the
/// listener, ingress and auth, the tenant's identity, posture and custody,
/// the machine's declared class, the credential broker's process and roots,
/// the voice loop's socket and the key directory.
const SUPERVISOR_OWNED: &[&str] = &[
    "vault_path",
    "host",
    "port",
    "artifact_port",
    "auth_secret",
    "oauth_issuer",
    "oauth_jwks_uri",
    "oauth_resource_indicator",
    "allow_unauthenticated",
    "allowed_origins",
    "artifact_domains",
    "artifact_vault_name",
    "trusted_proxies",
    "lease_vault_id",
    "privacy_posture",
    "hosted_kms_key_ref",
    "device_class",
    "models.broker.socket",
    "models.broker.uid",
    "models.broker.program",
    "models.broker.extra_roots",
    "models.voice.socket",
    "keystore.dir",
];

/// The leaves that name a key by the environment variable holding it.
const ENVIRONMENT_KEYS: &[&str] = &[
    "runtime.byo_key_env",
    "embedder.api_key_env",
    "embedder.remote.api_key_env",
    "gpu.api_key_env",
    "models.providers.*.key_env",
    "models.decisions.system_one.key_env",
];

/// The leaves that name a file or directory the server reads or writes. An
/// array's items are its own leaf's.
const OWNER_PATHS: &[&str] = &[
    "dict_search_paths",
    "embedder.model_dir",
    "embedder.models_dir",
    "oneironer.model_dir",
    "oneironer.tiers.*.model_dir",
    "backup.dir",
    "import.queue_dir",
    "import.claude_code_root",
    "import.codex_root",
    "import.hook_transcript_roots",
    "failure_signals.candidates.*.instructions_file",
    "device_sync.credential_file",
    "browser.runtime",
    "desktop.runtime",
    "models.prompt_file",
    "models.roles.*.prompt_file",
    "models.roles.*.rungs.prompt_file",
    "models.dreamer.summary_prompt_file",
    "models.dreamer.resident_prompt_file",
    "models.dreamer.task_prompt_file",
    "models.dreamer.person_about_prompt_file",
    "models.code_mode.prompt_package",
    "models.code_mode.check.microsoft_tsc",
    "models.decision_read.recipe",
    "models.voice.extraction_prompt_file",
];

/// Settles the settings file `managed` names onto `config`, the
/// configuration [`ManagedArgs::serve_config`] built from argv; nothing
/// without one.
///
/// A setting the supervisor also passed on argv keeps the supervisor's
/// value: argv stands over the file. An explicit `[feedback]` destination
/// stands whole, in place of our cloud's default. The supervisor's voice
/// socket is set on the file's `[models.voice]` after the file is refused,
/// so the owner's voice settings turn the loop on and the supervisor names
/// where it listens.
pub(super) fn settle(
    managed: &ManagedArgs,
    args: &ServeArgs,
    config: &mut ServeConfig,
) -> anyhow::Result<()> {
    let Some(path) = &managed.settings_file else {
        return Ok(());
    };
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("read settings file {}", path.display()))?;
    let mut table: toml::Table =
        toml::from_str(&raw).with_context(|| format!("parse settings file {}", path.display()))?;
    refuse_unknown(&table)?;
    visit(&table, &mut Vec::new(), &mut |field, _| {
        if matches_any(field, SUPERVISOR_OWNED) {
            return Err(refused(field, SettingsRefusal::SupervisorOwned));
        }
        if matches_any(field, ENVIRONMENT_KEYS) {
            return Err(refused(field, SettingsRefusal::EnvironmentSecret));
        }
        Ok(())
    })?;
    refuse_default_import_roots(&table)?;
    let roots = owner_roots(&managed.data_dir, path.parent());
    visit(&table, &mut Vec::new(), &mut |field, value| match value {
        toml::Value::String(text)
            if matches_any(field, OWNER_PATHS) && !in_vault(Path::new(text), &roots) =>
        {
            Err(refused(field, SettingsRefusal::OutsideVault))
        }
        _ => Ok(()),
    })?;

    for (key, given) in [
        ("dimensions", args.dimensions.is_some()),
        ("fast_dims", args.fast_dims.is_some()),
        ("map_size", args.map_size.is_some()),
        ("log_level", args.log_level.is_some()),
        ("dict_search_paths", args.dict_search_paths.is_some()),
        (
            "assistant_display_names",
            args.assistant_display_names.is_some(),
        ),
        (
            "failure_signal_export",
            args.failure_signal_export.is_some(),
        ),
        (
            "failure_signal_training",
            args.failure_signal_training.is_some(),
        ),
        ("maximum_tier", args.maximum_tier.is_some()),
    ] {
        if given {
            table.remove(key);
        }
    }
    if table
        .get("feedback")
        .and_then(toml::Value::as_table)
        .is_some_and(|feedback| {
            feedback.contains_key("destination") || feedback.contains_key("endpoint")
        })
    {
        config.feedback.destination = None;
        config.feedback.endpoint = None;
    }
    if let Some(socket) = &managed.voice_socket
        && let Some(voice) = table
            .get_mut("models")
            .and_then(toml::Value::as_table_mut)
            .and_then(|models| models.get_mut("voice"))
            .and_then(toml::Value::as_table_mut)
    {
        let socket = socket
            .to_str()
            .context("--voice-socket must be a UTF-8 path")?;
        voice.insert("socket".into(), toml::Value::String(socket.to_owned()));
    }
    let names_runtime = table.contains_key("runtime");

    settle_managed_settings(config, table, path.parent())
        .with_context(|| format!("settings file {}", path.display()))?;

    // A bring-your-own-key route reads its key from the environment, which
    // managed mode never reads.
    if names_runtime && config.runtime.byo_key_env.is_some() {
        let field = if config.runtime.mode == RuntimeMode::ByoCloudKey {
            "runtime.mode"
        } else {
            "runtime.role_defaults"
        };
        return Err(refused(&[field], SettingsRefusal::EnvironmentSecret).into());
    }
    // The key directory is the supervisor's: a keystore without one would
    // be looked for under HOME.
    if config.keystore.backend != KeystoreBackend::Off && config.keystore.dir.is_none() {
        return Err(ManagedError::MissingFlag {
            flag: "keystore-dir",
        }
        .into());
    }
    if let Some(embedder) = &config.embedder
        && embedder.provider == EmbedderProvider::Local
        && embedder.local.model_dir.is_none()
        && embedder.local.models_dir.is_none()
    {
        anyhow::bail!(
            "settings file {}: a local [embedder] needs model_dir or models_dir, because managed mode never reads HOME or XDG_DATA_HOME",
            path.display()
        );
    }
    Ok(())
}

/// Refuses a top-level key, or a key of a section, that the config file's
/// schema does not have. A section's deeper tables refuse their own unknown
/// keys when the file is read.
fn refuse_unknown(table: &toml::Table) -> Result<(), ManagedError> {
    let known = settings_schema_keys(None).unwrap_or_default();
    for (key, value) in table {
        if !known.contains(&key.as_str()) {
            return Err(refused(&[key], SettingsRefusal::UnknownField));
        }
        if let (toml::Value::Table(section), Some(keys)) =
            (value, settings_schema_keys(Some(key.as_str())))
            && let Some(field) = section.keys().find(|field| !keys.contains(&field.as_str()))
        {
            return Err(refused(&[key, field], SettingsRefusal::UnknownField));
        }
    }
    Ok(())
}

/// Refuses an import queue that would read a source's default root: the
/// session-log folders under HOME, outside the vault.
fn refuse_default_import_roots(table: &toml::Table) -> Result<(), ManagedError> {
    let Some(import) = table.get("import").and_then(toml::Value::as_table) else {
        return Ok(());
    };
    let queue = import.get("queue").and_then(toml::Value::as_bool) == Some(true);
    if queue && !(import.contains_key("claude_code_root") && import.contains_key("codex_root")) {
        return Err(refused(&["import", "queue"], SettingsRefusal::OutsideVault));
    }
    Ok(())
}

/// Calls `check` on every key of `table`, depth first, with its dotted field.
fn visit(
    table: &toml::Table,
    field: &mut Vec<String>,
    check: &mut impl FnMut(&[String], &toml::Value) -> Result<(), ManagedError>,
) -> Result<(), ManagedError> {
    for (key, value) in table {
        field.push(key.clone());
        visit_value(value, field, check)?;
        field.pop();
    }
    Ok(())
}

/// [`visit`] for one value: the value, then its keys or, for an array, each
/// item under the array's own field.
fn visit_value(
    value: &toml::Value,
    field: &mut Vec<String>,
    check: &mut impl FnMut(&[String], &toml::Value) -> Result<(), ManagedError>,
) -> Result<(), ManagedError> {
    check(field, value)?;
    match value {
        toml::Value::Table(table) => visit(table, field, check),
        toml::Value::Array(items) => items
            .iter()
            .try_for_each(|item| visit_value(item, field, check)),
        _ => Ok(()),
    }
}

/// Whether `field` is one of `patterns`, dotted fields where `*` is any key.
fn matches_any(field: &[String], patterns: &[&str]) -> bool {
    patterns.iter().any(|pattern| {
        pattern.split('.').count() == field.len()
            && pattern
                .split('.')
                .zip(field)
                .all(|(segment, key)| segment == "*" || segment == key.as_str())
    })
}

/// The vault's data directory and the settings file's own directory, links
/// resolved. One that does not exist yet, or is the filesystem root, holds
/// no owner path.
fn owner_roots(data_dir: &Path, settings_dir: Option<&Path>) -> Vec<PathBuf> {
    [Some(data_dir), settings_dir]
        .into_iter()
        .flatten()
        .filter_map(|dir| dir.canonicalize().ok())
        .filter(|dir| dir.parent().is_some())
        .collect()
}

/// Whether an owner path lies in this vault's own storage: absolute, with
/// no `~` or `..` part, present, and under one of `roots` once its links are
/// resolved.
fn in_vault(path: &Path, roots: &[PathBuf]) -> bool {
    let plain = path.is_absolute()
        && path.components().all(|part| match part {
            Component::ParentDir => false,
            Component::Normal(name) => !name.as_encoded_bytes().starts_with(b"~"),
            _ => true,
        });
    plain
        && path
            .canonicalize()
            .is_ok_and(|real| roots.iter().any(|root| real.starts_with(root)))
}

/// The typed refusal of one dotted field; its section is the first key of a
/// nested field, empty for a top-level one.
fn refused<S: AsRef<str>>(field: &[S], reason: SettingsRefusal) -> ManagedError {
    let parts: Vec<&str> = field.iter().map(AsRef::as_ref).collect();
    let section = match parts.as_slice() {
        [section, _, ..] => (*section).to_owned(),
        _ => String::new(),
    };
    ManagedError::SettingsRefused {
        section,
        field: parts.join("."),
        reason,
    }
}
