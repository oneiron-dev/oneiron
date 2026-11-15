//! Moved from `crates/oneiron/src/task_verb/report_journal.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::memory::MemoryError;
use oneiron_contracts::memory::MemoryResult;
use serde::Serialize;

/// Domain of the key digest one try's entry is stored under.
pub const KEY_DIGEST_DOMAIN: &[u8] = b"oneiron.tasks.report.key.v1";

/// The try, its count, and a digest of who reported what key on which TASK.
pub type ReportKey = ([u8; 16], u64, [u8; 32]);

pub fn digest(domain: &[u8], value: &impl Serialize) -> MemoryResult<[u8; 32]> {
    let bytes = rmp_serde::to_vec_named(value)
        .map_err(|_| MemoryError::bad_request("the report does not encode"))?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&bytes);
    Ok(*hasher.finalize().as_bytes())
}
