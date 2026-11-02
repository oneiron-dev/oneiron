//! A post's intent key (FIX 9002, Rule 5): the caller's key, qualified by
//! the host's parent attempt as every highway key is, then hashed to a fixed
//! length. The post's TASK id, its parked proposal and its provenance carry
//! the hash, so a key of any length posts; its receipt shows the caller's
//! own text beside the hash, and a lookup by that text hashes it again.
//! Entry: `PostKey::of`.

use super::*;

/// Derivation context of a post's hashed intent key.
const POST_KEY_CONTEXT: &str = "oneiron tasks post intent key v1";

/// One post's intent key, as the caller wrote it and as its records key it.
pub(super) struct PostKey {
    /// The caller's key, qualified by the host's parent attempt on a host
    /// post. The receipt shows it and the request digest binds it.
    pub(super) text: String,
    /// The hash of `text`, as 64 hex: the identity the post's records carry.
    pub(super) stored: String,
}

impl PostKey {
    /// `key` as `via` posts it. A blank key is refused; a key of any length
    /// is taken, its length observed ([`observe_key_in`]).
    pub(super) fn of(via: &TaskVia, key: &str) -> MemoryResult<Self> {
        if key.trim().is_empty() {
            return Err(MemoryError::bad_request("intent key must not be blank"));
        }
        let text = qualify(via, key);
        let mut hasher = blake3::Hasher::new_derive_key(POST_KEY_CONTEXT);
        hasher.update(text.as_bytes());
        let stored = hasher.finalize().to_hex().to_string();
        Ok(Self { text, stored })
    }
}

/// Observes the length of `caller_key`, the key as the caller sent it, on
/// its scan row (FIX 9002): once refused past 256 bytes, now measured and
/// taken. Read in `txn`, the post's own read before its writer; the row is
/// written after it, and an observation that does not start changes
/// nothing.
pub(super) fn observe_key_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    caller_key: &str,
    task_ref: EntityId,
) {
    if let Ok(mut count) = crate::scan_check::ScanCount::start(
        &vault.store,
        txn,
        crate::scan_check::EngineScan::TaskPostIntentKeyBytes,
        task_ref.as_bytes(),
    ) {
        count.rows(caller_key.len());
        count.defer(&vault.store);
    }
}
