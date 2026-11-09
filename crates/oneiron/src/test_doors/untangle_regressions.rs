//! Doors for the untangle regression tests (`tests/untangle_regressions.rs`;
//! lead 19:05 9 Nov, TESTS-MUST-RUN): each is a thin door over one
//! crate-private item, or a port of a seed helper of the `#[cfg(test)]`
//! fixtures, so the ruled behaviour tests of X01, X02, CONSENT-RAMP and the
//! repeat revoke (#6874) run from an integration target while the lib test
//! target does not compile. Compiled only under `--cfg oneiron_test_support`
//! (`test_doors`); the existing `test_support` doors they call are on in every
//! test build through the crate's self dev-dependency. Hidden; never API.
//! Every assertion stays in the test file: these return plain values.

use std::sync::Arc;

use crate::config::VaultConfig;
use crate::vault::Vault;

// ─── vaults ─────────────────────────────────────────────────────────────

/// A temporary vault opened with `cfg` as the crate's legacy test opener
/// (`test_util::open_test_vault_with`) opens it: the seeded default policy
/// manifest cleared and a process-memory device keystore installed.
#[doc(hidden)]
#[must_use]
pub fn open_test_vault_with(cfg: VaultConfig) -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), cfg).expect("open vault");
    let id = crate::gate::default_policy_manifest_id().expect("default policy manifest id");
    vault
        .with_write_txn(|wtxn| crate::batch::deindex_entity_for_test(&vault.store, wtxn, &id))
        .expect("clear default policy manifest for legacy test fixture");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    (dir, vault)
}

/// The crate's embedding test config (`test_util::embedding_test_config`).
#[doc(hidden)]
#[must_use]
pub fn embedding_test_config() -> VaultConfig {
    let mut config = VaultConfig::device();
    config.map_size = 16 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = Some("test/model@v1".to_owned());
    config.max_readers = 16;
    config
}
