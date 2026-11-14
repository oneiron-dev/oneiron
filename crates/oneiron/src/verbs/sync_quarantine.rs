//! Owner-only retained held-edit evidence from the sync quarantine.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::memory::MemoryResult;
use crate::sync::QuarantineContainer;

use super::EmptyRequest;

#[doc(hidden)]
pub use oneiron_verb_wire::verbs::sync_quarantine::SyncHeldEditEvidence;

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
