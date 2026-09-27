//! Vault access-grant query for a companion PERSON profile.

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;

impl Vault {
    /// Returns the active grant id authorizing a companion profile, if any.
    pub fn companion_profile_access_grant(
        &self,
        principal_ref: &EntityId,
        person_ref: &EntityId,
        persona_ref: &EntityId,
    ) -> Result<Option<EntityId>> {
        let now = self.store.authorization_now()?;
        let rtxn = self.store.env.read_txn()?;
        crate::gate::companion_profile_access_grant(
            &self.store,
            &rtxn,
            principal_ref,
            person_ref,
            persona_ref,
            now,
        )
    }
}
