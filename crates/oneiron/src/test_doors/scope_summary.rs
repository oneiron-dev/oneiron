//! Doors for `tests/summary_as_record_permit.rs` (SUMMARY-AS-RECORD-PERMIT):
//! a summary minted as the Dreamer writes one, so the test lands it through
//! `Vault::land_header` with no model.

use crate::Vault;
use crate::conversation_dag::ScopeSelector;
use crate::entity_id::EntityId;
use crate::error::Result;

/// Mints a summary of `text` over every source `scope` resolves to, written
/// as the Dreamer, and returns its id.
///
/// # Errors
/// The mint's: a scope that does not resolve, or an actor the vault lacks.
pub fn mint_scope_summary(vault: &Vault, scope: &ScopeSelector, text: &str) -> Result<EntityId> {
    crate::scope_summary::mint_scope_summary_for_test(vault, scope, text)
}
