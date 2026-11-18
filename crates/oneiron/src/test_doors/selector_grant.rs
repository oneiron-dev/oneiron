//! A sync selector's standing member grant, for integration tests.
//!
//! A residence selector names a grant over the residence scope, which no
//! production door writes on a fixture vault. This door writes the same row
//! `sync::put_selector_test_federation_grant` writes, for the integration
//! builds that do not enable `test-hooks`.

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::federation::{
    FederationGrant, FederationGrantPreset, FederationGrantRole, FederationGrantScope,
    encode_federation_grant_body,
};
use crate::temporal::TimeRange;
use crate::vault::Vault;

/// Stands `member`'s live Member grant over `scope`, as a founding grant is
/// written, for a sync selector to name. Returns the grant's id.
///
/// # Errors
///
/// The vault's.
pub fn stand_selector_grant(
    vault: &Vault,
    scope: FederationGrantScope,
    member: EntityId,
    learned_at: u64,
) -> Result<EntityId> {
    let grant = FederationGrant::new(
        scope,
        member,
        FederationGrantRole::Member,
        FederationGrantPreset::Member,
    );
    let id = EntityId::now();
    vault
        .batch()
        .put_replicated(
            &id,
            crate::registry::ENTITY_TYPE_FEDERATION_GRANT,
            TimeRange {
                start: learned_at,
                end: learned_at,
            },
            learned_at,
            None,
            &encode_federation_grant_body(&grant)?,
        )
        .commit()?;
    Ok(id)
}
