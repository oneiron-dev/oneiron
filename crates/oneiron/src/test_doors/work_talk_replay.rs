//! A replicated-shape CONVERSATION put for the work-talk tests (L7-05 Astra T3).
//!
//! Sync replay lands a peer's CONVERSATION row through the replicated put,
//! which runs the production body validation with `replicated = true`
//! (`validate_put_in_txn` in `conversation/body.rs`): a structurally valid
//! body lands without the local ledger checks (PERSON members, membership
//! rows, `vault_meta` binding registrations). No public door reaches that
//! shape (`BatchBuilder::put_replicated` is crate-private), so this door
//! stands it for the test that clones a legitimate work-talk body under a
//! fresh id without its local registration.

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::temporal::TimeRange;
use crate::vault::Vault;

/// Puts `body` (a `ConversationBody` encoding) at `id` through the
/// production sync-replay door, at occurrence/learned time `at`.
///
/// # Errors
///
/// The put's: a body the replicated validation refuses, or the vault's.
pub fn put_replicated_conversation(
    vault: &Vault,
    id: &EntityId,
    body: &[u8],
    at: u64,
) -> Result<()> {
    vault
        .batch()
        .put_replicated(
            id,
            crate::registry::ENTITY_TYPE_CONVERSATION,
            TimeRange { start: at, end: at },
            at,
            None,
            body,
        )
        .commit()?;
    Ok(())
}
