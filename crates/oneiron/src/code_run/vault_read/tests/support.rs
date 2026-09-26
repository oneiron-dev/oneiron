//! Shared retrieval-telemetry fixture for vault-read tests.

use crate::config::VaultConfig;

pub(super) fn telemetry_config() -> VaultConfig {
    let mut config = crate::test_util::embedding_test_config();
    config.retrieval_telemetry_capture = true;
    config
}
