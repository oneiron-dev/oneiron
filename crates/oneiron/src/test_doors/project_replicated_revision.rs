//! Door for `tests/frozen_project_answer_narrowing.rs` (FIX
//! STANDING-ANSWER-FROZEN-CHILD-PARENT-NARROWING-TEST): a peer's PROJECT
//! state stored as a sync pass stores it. A live write must build on the
//! current head, so only a replicated row can add a sibling revision beside
//! it, the shape two devices writing the same project leave.

use crate::error::Result;
use crate::workspace_roster::ProjectRecord;
use crate::{EntityId, TimeRange, Vault};

/// Commits `body`, a signed state of project `id`, as a replicated PROJECT
/// put at `at`, as a sync pass stores a peer's row.
///
/// # Errors
///
/// The vault binds no project kind, the body does not encode, or the batch
/// chokepoint refuses the put.
pub fn put_replicated_project_state(
    vault: &Vault,
    id: EntityId,
    body: &ProjectRecord,
    at: u64,
) -> Result<()> {
    vault
        .batch()
        .put_replicated(
            &id,
            vault.project_type_byte()?,
            TimeRange { start: at, end: at },
            at,
            None,
            &oneiron_records::workspace_roster::project::encode(body)?,
        )
        .commit()
}
