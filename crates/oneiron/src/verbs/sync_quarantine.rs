//! Owner-only retained held-edit evidence from the sync quarantine.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::memory::MemoryResult;
use crate::sync::QuarantineContainer;

use super::EmptyRequest;

/// Retained held-edit metadata with lossless hash strings on every transport.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SyncHeldEditEvidence {
    pub window_key: String,
    pub container: QuarantineContainer,
    /// The stored `xxh3_64` key hash as sixteen lowercase hexadecimal digits.
    pub crdt_key_hash: String,
    pub crdt_key_len: u32,
    pub reason_code: String,
    /// The stored `xxh3_64` payload hash as sixteen lowercase hexadecimal digits.
    pub payload_hash: String,
    pub quarantined_at: u64,
}

/// Lists retained hash-only evidence, not live pending work or settlement.
pub fn sync_quarantine_held_edits_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    _input: EmptyRequest,
) -> MemoryResult<Vec<(u64, SyncHeldEditEvidence)>> {
    Ok(vault
        .held_edits_as_owner(owner)?
        .into_iter()
        .map(|(sequence, record)| {
            (
                sequence,
                SyncHeldEditEvidence {
                    window_key: record.window_key,
                    container: record.container,
                    crdt_key_hash: format!("{:016x}", record.crdt_key_hash),
                    crdt_key_len: record.crdt_key_len,
                    reason_code: record.reason_code,
                    payload_hash: format!("{:016x}", record.payload_hash),
                    quarantined_at: record.quarantined_at,
                },
            )
        })
        .collect())
}
