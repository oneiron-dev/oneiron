//! A replicated authority batch in the caller's row order, for integration tests.
//!
//! Each row runs through the replicated commit door, judged on the fold with
//! the rows before it staged, and one refusal rolls the whole batch back. No
//! public path commits authority rows in a caller-chosen order: the signed
//! import orders its page and judges the page as a whole.

use crate::authority::{
    AuthorityLogEntry, authority_log_entity_id, encode_authority_log_entry_body,
};
use crate::error::Result;
use crate::registry::ENTITY_TYPE_AUTHORITY_LOG;
use crate::temporal::TimeRange;
use crate::vault::Vault;

/// Commits `entries` as one replicated batch, in the order given: each row
/// is judged by the replicated commit door on the fold with the rows before
/// it staged, and one refusal rolls the whole batch back.
///
/// # Errors
///
/// The batch chokepoint's refusal.
pub fn commit_replicated_authority_rows(
    vault: &Vault,
    entries: &[AuthorityLogEntry],
) -> Result<()> {
    let mut batch = vault.batch();
    for entry in entries {
        let id = authority_log_entity_id(entry)?;
        let body = encode_authority_log_entry_body(entry)?;
        batch = batch.put_replicated(
            &id,
            ENTITY_TYPE_AUTHORITY_LOG,
            TimeRange { start: 2, end: 2 },
            2,
            None,
            &body,
        );
    }
    batch.commit()
}
