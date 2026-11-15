//! Doors for the vault data-key generation test: read a published custody
//! head back from its folder, and open one with a checkpoint key's data-key
//! subkey alone.
//! Compiled only under `--cfg oneiron_test_support`; never API.

use crate::recovery::checkpoint::CheckpointKey;

/// The published custody head under `folder` (`<folder>/oneiron-custody/*/
/// head`), as `Vault::publish_custody` wrote it.
pub fn read_published_head(folder: &std::path::Path) -> crate::error::Result<Vec<u8>> {
    let custody = folder.join("oneiron-custody");
    let mut entries: Vec<std::path::PathBuf> = Vec::new();
    for entry in std::fs::read_dir(&custody)? {
        entries.push(entry?.path());
    }
    entries.sort();
    for dir in entries {
        let head = dir.join("head");
        if head.is_file() {
            return Ok(std::fs::read(&head)?);
        }
    }
    Err(crate::error::Error::InvalidConfig(
        "no published custody head".into(),
    ))
}

/// Opens `head` with `key`'s custody subkey alone (no kit, no machine key).
/// Returns the debug names of the scopes that stayed unopened. Control
/// always opens, so an `Ok` proves a data-key wrap opened.
pub fn open_custody_head_with_checkpoint_key(
    head: &[u8],
    key: &CheckpointKey,
) -> crate::error::Result<Vec<String>> {
    crate::store::Store::custody_head_unopened_scopes(head, key.custody_wrap())
}
