//! Doors for the provenance-body checkpoint owner-erasure tests.
//! Compiled only under `--cfg oneiron_test_support`; never API.

use std::path::Path;
use std::sync::Arc;

use crate::code_run::CodeRunRawOutput;
use crate::recovery::checkpoint::CheckpointKey;
use crate::store::owned_body::{BODY, BODY_DIGEST};
use crate::{EntityId, Result, Vault};

/// Installs the process-memory device keystore used by checkpoint fixtures.
pub fn install_memory_keystore(vault: &Vault) {
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
}

/// Publishes a complete owned result through the real sink and publisher.
pub fn publish_owned_result(
    vault: &Vault,
    owner: EntityId,
    path: &str,
    bytes: &[u8],
) -> Result<CodeRunRawOutput> {
    let mut sink = vault.code_run_output_sink()?;
    sink.write(bytes)?;
    vault.publish_code_run_output(path.to_owned(), sink, true, Some(owner))
}

/// Reads the live digest-holder row for one attachment occurrence.
pub fn live_holder(
    vault: &Vault,
    digest: &[u8; 32],
    occurrence: EntityId,
) -> Result<Option<EntityId>> {
    let txn = vault.store.env.read_txn()?;
    BODY_DIGEST.get(&vault.store, &txn, &(*digest, occurrence))
}

/// Encodes the descriptor key through the owning table's key codec.
pub fn descriptor_key(owner: EntityId, occurrence: EntityId) -> Vec<u8> {
    BODY.key_bytes(&(owner, occurrence))
}

/// Encodes the digest-holder key through the owning table's key codec.
pub fn holder_key(digest: [u8; 32], occurrence: EntityId) -> Vec<u8> {
    BODY_DIGEST.key_bytes(&(digest, occurrence))
}

/// Reads only raw decoded descriptor and holder rows, without a restore.
pub fn raw_checkpoint_body_rows(
    path: &Path,
    key: &CheckpointKey,
) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    crate::recovery::checkpoint::raw_vault_meta_rows_with_prefixes(
        path,
        key,
        &[BODY.decl().prefix, BODY_DIGEST.decl().prefix],
    )
}
