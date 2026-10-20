//! The vault's settings file (`--settings-file`): the owner's feature settings
//! for a vault our cloud hosts, in the server's own config schema.
//!
//! The file is the one layer a managed vault reads settings from, and it is
//! read once, before anything uses the configuration, in two steps:
//! [`prepare`] reads and refuses it, and [`settle`] resolves and applies it,
//! so tracing starts between them at the level the settled configuration
//! runs at. Before any file it names is read, it is refused leaf by leaf: a
//! leaf the supervisor owns, a key named by an environment variable (the
//! contract's tables in
//! [`oneiron_vault_contract::settings_policy`], which the supervisor reads
//! too) and a key the schema does not have are refused by presence alone,
//! and every owner path must lie in this vault's own storage, or be a
//! model bundle's own directory in the node's read-only shared model root
//! the supervisor declared (`--shared-model-root`), by the rule the
//! supervisor checks at intake too
//! ([`oneiron_vault_contract::settings_paths`]). The rest is
//! settled over the configuration argv built, through the config file's own
//! apply and validators ([`crate::config::merge::settle_managed_settings`]).
//! Nothing here reads the environment, HOME or a default config path.

use std::path::{Path, PathBuf};

use anyhow::Context as _;
use oneiron_vault_contract::settings_paths::{
    OwnerPathOrigin, OwnerRoots, SHARED_MODEL_ROOT_IGNORED, SHARED_MODEL_STACK, SharedModelRoot,
    check_owner_path, is_owner_path, owner_roots, queue_reads_default_root,
};
use oneiron_vault_contract::settings_policy::{ENVIRONMENT_KEYS, SUPERVISOR_OWNED, matches_any};

use crate::config::merge::{settings_schema_keys, settle_managed_settings};
use crate::config::{EmbedderProvider, KeystoreBackend, ServeArgs, ServeConfig};

use super::args::{ManagedArgs, ManagedError, SettingsRefusal};
use super::listener::init_managed_tracing;

/// The reason token of the notice that the owner's voice settings name no
/// socket to listen on (FIX 5017).
const VOICE_SOCKET_MISSING: &str = "voice_socket_missing";

/// The settings file, read and refused, ready for [`settle`]: its table with
/// the leaves argv stands over removed and the supervisor's own leaves set.
pub(super) struct PreparedSettings {
    path: PathBuf,
    table: toml::Table,
    names_runtime: bool,
    /// The owner's `[models.voice]` is there and the supervisor named no
    /// voice socket for it.
    voice_socket_missing: bool,
    /// The owner's `[keystore]` sets `backend = "off"` itself.
    keystore_off: bool,
}

/// What settling decided that the settled configuration does not say by
/// itself.
#[derive(Clone, Copy, Debug)]
pub(super) struct Settled {
    /// No keystore is installed for want of the supervisor's key directory
    /// (`--keystore-dir`), where the owner's file did not turn it off
    /// itself: the vault serves on without one, the facility named missing
    /// in its readiness (WILL-PLAN L14 row 17).
    pub(super) keystore_unbound: bool,
}

/// The configuration a managed start serves on: the one argv builds
/// ([`ManagedArgs::serve_config`]), with the node's shared model root
/// checked, and the owner's settings file read and refused ([`prepare`]) and
/// settled over it ([`settle`]), tracing started between the two.
pub(super) fn configure(
    args: &ServeArgs,
    managed: &ManagedArgs,
) -> anyhow::Result<(ServeConfig, Settled)> {
    let mut config = managed.serve_config(args);
    // The shared model root the supervisor declared, checked before the
    // settings file names a model directory in it. One that fails is
    // ignored, and logged once tracing starts, never a refused start.
    let shared_model = managed
        .shared_model_root
        .as_deref()
        .map(|declared| (declared, SharedModelRoot::validate(declared)));
    config.shared_model_root = shared_model
        .as_ref()
        .and_then(|(_, checked)| checked.as_ref().ok().cloned());
    // The owner's settings file, refused leaf by leaf and settled once,
    // before anything reads the configuration: its `[oneironer]` arms the
    // write-time marker in `ServeConfig::base_vault_config`. Tracing starts
    // between its refusal and its settling, at the level the settled
    // configuration runs at (argv over the file), so what settling decides
    // is logged.
    let settings = prepare(managed, args, &mut config)?;
    init_managed_tracing(log_level(settings.as_ref(), &config));
    if let Some((declared, Err(cause))) = shared_model {
        tracing::warn!(
            reason = SHARED_MODEL_ROOT_IGNORED,
            cause = cause.as_str(),
            root = %declared.display(),
            "the shared model root the supervisor declared failed its check and is ignored: the vault starts without it, and a model directory only it would admit is refused"
        );
    }
    let settled = settle(settings, &mut config)?;
    Ok((config, settled))
}

/// The log level the settled configuration runs at: the settings file's,
/// unless argv named one, else `config`'s, the one argv built.
pub(super) fn log_level<'a>(
    prepared: Option<&'a PreparedSettings>,
    config: &'a ServeConfig,
) -> &'a str {
    prepared
        .and_then(|prepared| prepared.table.get("log_level"))
        .and_then(toml::Value::as_str)
        .unwrap_or(config.log_level.as_str())
}

/// Reads and refuses the settings file `managed` names, for [`settle`] to
/// settle onto `config`, the configuration [`ManagedArgs::serve_config`]
/// built from argv; `None` without one.
///
/// A setting the supervisor also passed on argv keeps the supervisor's
/// value: argv stands over the file. An explicit `[feedback]` destination
/// stands whole, in place of our cloud's default. The supervisor's voice
/// socket is set on the file's `[models.voice]` after the file is refused,
/// so the owner's voice settings turn the loop on and the supervisor names
/// where it listens. A direct `[linear]` mirror is given its host's response
/// custody the same way, and an owner's `[browser]` or `[desktop]` the
/// container CLI the supervisor binds for its guest.
pub(super) fn prepare(
    managed: &ManagedArgs,
    args: &ServeArgs,
    config: &mut ServeConfig,
) -> anyhow::Result<Option<PreparedSettings>> {
    let Some(path) = &managed.settings_file else {
        return Ok(None);
    };
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("read settings file {}", path.display()))?;
    let mut table: toml::Table =
        toml::from_str(&raw).with_context(|| format!("parse settings file {}", path.display()))?;
    // The supervisor's leaves are refused first: an argv-only binding the
    // schema has no key for (the training outbox, OF-420; a guest's
    // container CLI, the organ directory and the mesh) reads as the
    // supervisor's, never as unknown.
    visit(&table, &mut Vec::new(), &mut |field, _| {
        if matches_any(field, SUPERVISOR_OWNED) {
            return Err(refused(field, SettingsRefusal::SupervisorOwned));
        }
        if matches_any(field, ENVIRONMENT_KEYS) {
            return Err(refused(field, SettingsRefusal::EnvironmentSecret));
        }
        Ok(())
    })?;
    refuse_unknown(&table)?;
    refuse_default_import_roots(&table)?;
    let roots = owner_roots(
        &managed.data_dir,
        path.parent(),
        config.shared_model_root.clone(),
    );
    visit(&table, &mut Vec::new(), &mut |field, value| match value {
        toml::Value::String(text) if is_owner_path(field) => {
            admit_owner_path(&table, field, Path::new(text), &roots)
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
    let voice = table
        .get_mut("models")
        .and_then(toml::Value::as_table_mut)
        .and_then(|models| models.get_mut("voice"))
        .and_then(toml::Value::as_table_mut);
    let voice_socket_missing = voice.is_some() && managed.voice_socket.is_none();
    if let Some(socket) = &managed.voice_socket
        && let Some(voice) = voice
    {
        let socket = socket
            .to_str()
            .context("--voice-socket must be a UTF-8 path")?;
        voice.insert("socket".into(), toml::Value::String(socket.to_owned()));
    }
    if let Some(linear) = table.get_mut("linear").and_then(toml::Value::as_table_mut)
        && linear.get("mode").and_then(toml::Value::as_str) == Some("direct")
    {
        let responses = super::owner_storage::linear_response_dir(&managed.data_dir);
        let responses = responses
            .to_str()
            .context("--data-dir must be a UTF-8 path")?;
        linear.insert(
            "response_dir".into(),
            toml::Value::String(responses.to_owned()),
        );
    }
    // A guest's container CLI the supervisor binds stands in the section the
    // owner wrote, set once his paths are refused, so it may lie outside the
    // vault (the VM's root filesystem). His section turns the guest on; the
    // flag alone turns on none (FIX 5015).
    for (name, runtime) in [
        ("browser", &managed.browser_runtime),
        ("desktop", &managed.desktop_runtime),
    ] {
        if let Some(runtime) = runtime
            && let Some(section) = table.get_mut(name).and_then(toml::Value::as_table_mut)
        {
            let runtime = runtime
                .to_str()
                .with_context(|| format!("--{name}-runtime must be a UTF-8 path"))?;
            section.insert("runtime".into(), toml::Value::String(runtime.to_owned()));
        }
    }
    let names_runtime = table.contains_key("runtime");
    let keystore_off = table
        .get("keystore")
        .and_then(toml::Value::as_table)
        .and_then(|keystore| keystore.get("backend"))
        .and_then(toml::Value::as_str)
        == Some("off");
    Ok(Some(PreparedSettings {
        path: path.clone(),
        table,
        names_runtime,
        voice_socket_missing,
        keystore_off,
    }))
}

/// Settles the settings file [`prepare`] read onto `config`, through the
/// config file's own apply and validators; nothing without one. Owner voice
/// settings with no voice socket are logged, typed: the private voice loop
/// stays off and live voice sessions still run. With or without a file, a
/// keystore with no supervisor key directory is settled off
/// ([`settle_keystore`]).
pub(super) fn settle(
    prepared: Option<PreparedSettings>,
    config: &mut ServeConfig,
) -> anyhow::Result<Settled> {
    let Some(PreparedSettings {
        path,
        table,
        names_runtime,
        voice_socket_missing,
        keystore_off,
    }) = prepared
    else {
        return Ok(settle_keystore(config, false));
    };
    settle_managed_settings(config, table, path.parent())
        .with_context(|| format!("settings file {}", path.display()))?;
    if voice_socket_missing {
        tracing::warn!(
            reason = VOICE_SOCKET_MISSING,
            "voice: the settings file has owner voice settings but the supervisor passed no --voice-socket; the private voice loop is off, and live voice sessions still run"
        );
    }

    // Managed mode reads no environment: a bring-your-own-key route takes
    // its key from `runtime.byo_key_secret` alone, and the default variable
    // a BYO mode names when the file names no source is dropped, never read.
    if names_runtime {
        config.runtime.byo_key_env = None;
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
    Ok(settle_keystore(config, keystore_off))
}

/// The key directory is the supervisor's: a keystore without one would be
/// looked for under HOME, so none is opened, and the vault serves on without
/// it. Where the owner's file did not turn the keystore off itself
/// (`keystore_off`), the facility is named missing, never a stopped start.
fn settle_keystore(config: &mut ServeConfig, keystore_off: bool) -> Settled {
    let unbound = config.keystore.dir.is_none();
    if unbound {
        config.keystore.backend = KeystoreBackend::Off;
    }
    Settled {
        keystore_unbound: unbound && !keystore_off,
    }
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
    if queue_reads_default_root(queue, |leaf| import.contains_key(leaf)) {
        return Err(refused(&["import", "queue"], SettingsRefusal::OutsideVault));
    }
    Ok(())
}

/// Admits one owner path the settings file names at `field`, by the rule
/// the supervisor checks too ([`check_owner_path`]). A model directory the
/// shared model root admits must also hold the bundle its name says: the
/// stack its manifest states, read here before any model loads; the loader
/// still checks every file it reads.
fn admit_owner_path(
    table: &toml::Table,
    field: &[String],
    path: &Path,
    roots: &OwnerRoots,
) -> Result<(), ManagedError> {
    let stack = declared_stack(table, field);
    let admitted = check_owner_path(field, path, stack, roots)
        .map_err(|_| refused(field, SettingsRefusal::OutsideVault))?;
    if admitted.origin == OwnerPathOrigin::SharedModel {
        let manifest = crate::oneironer::engines::bundle_identity(&admitted.path)
            .map(|identity| identity.stack_sha16);
        if manifest.ok().as_deref() != stack {
            return Err(refused(field, SettingsRefusal::OutsideVault));
        }
    }
    Ok(())
}

/// The stack the settings pin beside the leaf at `field`: the
/// [`SHARED_MODEL_STACK`] key of the same table, if it holds text.
fn declared_stack<'a>(table: &'a toml::Table, field: &[String]) -> Option<&'a str> {
    let (_, sections) = field.split_last()?;
    let mut section = table;
    for key in sections {
        section = section.get(key)?.as_table()?;
    }
    section.get(SHARED_MODEL_STACK)?.as_str()
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
