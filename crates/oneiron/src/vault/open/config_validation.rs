use super::*;

const MIN_MAP_SIZE_BYTES: usize = 1 << 20;

/// Config preconditions every opener checks before the environment is mapped.
pub(super) fn validate_open_config(config: &VaultConfig) -> Result<()> {
    // FIRST, before any other gate and before any opener reaches `Store::open`:
    // an unsupported posture/custody pairing must never bring a storage
    // environment into existence. Every door (`open`, `open_existing`,
    // `open_seeded`, and the test-only ABI opener) funnels through here.
    config.privacy.validate()?;
    if config.dimensions == 0 {
        return Err(Error::InvalidConfig(
            "dimensions must be greater than zero".to_owned(),
        ));
    }
    if config.hnsw.m_max_0 == 0 {
        return Err(Error::InvalidConfig(
            "hnsw m_max_0 must be greater than zero".to_owned(),
        ));
    }
    if config.map_size < MIN_MAP_SIZE_BYTES {
        return Err(Error::InvalidConfig(format!(
            "map_size must be at least {MIN_MAP_SIZE_BYTES} bytes"
        )));
    }
    Ok(())
}
