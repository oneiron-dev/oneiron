//! Temporary test vault openers and the configs and clocks they share.

use crate::config::VaultConfig;
use crate::vault::Vault;

/// Canonical embedding-enabled test config: 16 MiB map, 4 dimensions,
/// `test/model@v1` embedding model, 16 readers. Everything else is the
/// `VaultConfig::device()` preset — HNSW and text-analyzer defaults
/// included, so do NOT re-assign defaults here.
pub(crate) fn embedding_test_config() -> VaultConfig {
    let mut config = VaultConfig::device();
    config.map_size = 16 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = Some("test/model@v1".to_owned());
    config.max_readers = 16;
    config
}

/// A store clock pinned at `now` with fresh ids, for fixtures whose records
/// carry fixed timestamps that the engine's clock must agree with.
pub(crate) fn pinned_store_clock(now: u64) -> crate::ports::StoreClock {
    struct Pinned(u64);
    impl crate::ports::Clock for Pinned {
        fn now_recorded_at(&self) -> u64 {
            self.0
        }
    }
    impl crate::ports::IdGen for Pinned {
        fn ulid(&self) -> [u8; 16] {
            uuid::Uuid::now_v7().into_bytes()
        }
    }
    let pinned = std::sync::Arc::new(Pinned(now));
    crate::ports::StoreClock::new(pinned.clone(), pinned)
}

/// Opens a temporary vault while keeping the seeded default policy manifest.
/// Pipeline runs read claim-aging profiles and fail closed without that row
/// (PIPELINE-LIBTEST-CLEARED-MANIFEST-ENTITYNOTFOUND). #7822 kept it for two
/// pipeline tests; consuming fixtures share that opener here.
pub(crate) fn open_test_vault_with_manifest(cfg: VaultConfig) -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), cfg).expect("open vault");
    // Signing doors load this install's keys from a keystore (P6c).
    vault.install_device_keystore(std::sync::Arc::new(
        oneiron_keystore::MemoryKeystore::default(),
    ));
    (dir, vault)
}
