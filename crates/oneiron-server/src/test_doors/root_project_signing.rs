//! A serve start's root-project signing (`commands::sign_root_project`) and
//! server construction (`commands::construct_sync_server`) on a store no
//! root has reached, for `tests/joined_store_roots_nothing.rs` (R6 1.5:
//! mel's first start rooted its joined store, 26 Nov 01:22).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use oneiron::Vault;

use crate::config::ServeConfig;
use crate::device_sync::EnrolmentFiles;
use crate::device_sync::enrolment::DeviceEnrolment;

/// A store no root has reached, at `dir/vault`, with its keystore in memory and the serve config
/// naming `dir/keys` as its key directory.
///
/// # Errors
///
/// The vault does not open.
pub fn fresh_store(dir: &Path) -> anyhow::Result<(Arc<Vault>, ServeConfig)> {
    store_at(dir, oneiron::VaultConfig::device())
}

/// [`fresh_store`] in the Hosted posture, whose server boot bootstraps a host
/// issuer with no secret.
///
/// # Errors
///
/// The vault does not open.
pub fn fresh_hosted_store(dir: &Path) -> anyhow::Result<(Arc<Vault>, ServeConfig)> {
    let mut vault_config = oneiron::VaultConfig::device();
    vault_config.privacy.posture = oneiron::HostingPrivacyPosture::Hosted;
    store_at(dir, vault_config)
}

fn store_at(
    dir: &Path,
    vault_config: oneiron::VaultConfig,
) -> anyhow::Result<(Arc<Vault>, ServeConfig)> {
    let vault_path = dir.join("vault");
    let vault = Vault::open(&vault_path, vault_config)?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let mut config = ServeConfig {
        vault_path,
        ..ServeConfig::default()
    };
    config.keystore.dir = Some(dir.join("keys"));
    Ok((Arc::new(vault), config))
}

/// The device enrolment record a join leaves for `vault` beside `config`'s key directory before
/// its first sync, naming a home. Answers its path.
///
/// # Errors
///
/// No key directory, or the record was not written.
pub fn write_join_record(config: &ServeConfig, vault: &Vault) -> anyhow::Result<PathBuf> {
    let files = EnrolmentFiles::for_vault(&config.keystore, vault)?;
    let record = DeviceEnrolment {
        home_machine: oneiron::EntityId::now().to_hex(),
        home_node_id: 1,
        home_url: "ws://127.0.0.1:9/ws".to_owned(),
        authority_checkpoint_pin: None,
        home_mesh: None,
    };
    if let Some(parent) = files.record.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&files.record, serde_json::to_vec_pretty(&record)?)?;
    Ok(files.record)
}

/// [`crate::commands::sign_root_project`] for `vault` under `config`'s key directory, with
/// `secret`, as a serve start calls it.
///
/// # Errors
///
/// Why the root project was not signed.
pub fn sign_root_project(
    vault: &Vault,
    config: &ServeConfig,
    secret: Option<&str>,
) -> anyhow::Result<()> {
    crate::commands::sign_root_project(vault, secret, &config.keystore)
}

/// The server a serve start builds over `vault` under `config`
/// ([`crate::commands::construct_sync_server`]), with `secret` as its `auth_secret`. Answers
/// the `auth_secret` the built server holds.
///
/// # Errors
///
/// The server's boot.
pub fn construct_sync_server(
    vault: Arc<Vault>,
    config: &ServeConfig,
    secret: Option<&str>,
) -> anyhow::Result<Option<String>> {
    let server = crate::commands::construct_sync_server(
        vault,
        config,
        crate::config::SyncServerConfig {
            auth_secret: secret.map(str::to_owned),
            ..crate::config::SyncServerConfig::default()
        },
    )?;
    Ok(server.config.auth_secret.clone())
}
