//! A serve start's root-project signing (`commands::sign_root_project`) on a
//! store no root has reached, for `tests/joined_store_roots_nothing.rs`
//! (R6 1.5: mel's first start rooted its joined store, 26 Nov 01:22).

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
    let vault_path = dir.join("vault");
    let vault = Vault::open(&vault_path, oneiron::VaultConfig::device())?;
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
