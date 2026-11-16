//! Doors for `tests/campaign_member_index.rs` (census L3-28C): the claims the
//! campaign member index nominates on each membership axis, the index's
//! drop and completeness flag, and a cooperative-review restriction on one
//! record and its lift.

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;

/// The claims a campaign's membership page nominates from the index, in id
/// order; `None` when the page would scan every CLAIM.
pub fn indexed_campaign_claims(vault: &Vault, campaign: EntityId) -> Option<Vec<EntityId>> {
    crate::campaign::member_index::indexed_campaign_member_claims(vault, campaign)
}

/// The claims a saved query's membership page nominates from the index, in
/// id order; `None` when the page would scan every CLAIM.
pub fn indexed_saved_query_claims(vault: &Vault, query: EntityId) -> Option<Vec<EntityId>> {
    crate::campaign::member_index::indexed_saved_query_member_claims(vault, query)
}

/// Drops the indexes and their completeness flag, as a vault older than the
/// indexes holds them.
pub fn drop_index(vault: &Vault) -> Result<()> {
    vault.drop_campaign_member_index_for_test()
}

/// Whether the indexes are complete.
pub fn index_complete(vault: &Vault) -> Result<bool> {
    vault.campaign_member_index_complete_for_test()
}

/// Restricts `record` under one fixed courtesy ask, in the row the
/// cooperative-deletion answer writes: every visibility-filtered read hides
/// it until [`lift_restriction`].
pub fn restrict_record(vault: &Vault, record: EntityId) -> Result<()> {
    vault.restrict_record_for_test(record)
}

/// Lifts [`restrict_record`]'s restriction as the answer's notice-given lift
/// does: the row goes, and the record is not rewritten.
pub fn lift_restriction(vault: &Vault, record: EntityId) -> Result<()> {
    vault.lift_record_restriction_for_test(record)
}
