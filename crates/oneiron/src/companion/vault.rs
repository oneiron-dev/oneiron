//! Vault access-grant query for a companion PERSON profile.

use crate::Vault;
use crate::access_grant::decode_access_grant_body;
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::error::Result;
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_ACCESS_GRANT;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use std::collections::BTreeSet;

impl Vault {
    /// Returns the active grant id authorizing a read of `person_ref`'s
    /// companion profile at `facet_ref` (`None`: the unfaceted profile), if any.
    pub fn companion_profile_access_grant(
        &self,
        principal_ref: &EntityId,
        person_ref: &EntityId,
        facet_ref: Option<&EntityId>,
    ) -> Result<Option<EntityId>> {
        let now = self.store.authorization_now()?;
        let rtxn = self.store.env.read_txn()?;
        crate::gate::companion_profile_access_grant(
            &self.store,
            &rtxn,
            principal_ref,
            person_ref,
            facet_ref,
            now,
        )
    }
    /// Lists the facets of `person_ref` this principal holds a profile grant
    /// for, using the same persisted authorization clock as
    /// `companion_profile_access_grant`. `None` is a person-wide grant.
    /// Deleted grants are skipped; malformed live grants still fail closed.
    /// Every grant is read: past the threshold row the read raises the
    /// owner's check and reads on (rule 5).
    pub fn authorized_companion_profile_facets(
        &self,
        principal_ref: &EntityId,
        person_ref: &EntityId,
    ) -> Result<Vec<Option<EntityId>>> {
        let now = self.store.authorization_now()?;
        let txn = self.store.env.read_txn()?;
        let mut count = crate::scan_check::ScanCount::start(
            &self.store,
            &txn,
            crate::scan_check::EngineScan::AccessGrantRows,
            &[],
        )?;
        let mut facets = BTreeSet::new();
        for entry in self
            .store
            .port_entity_ids_by_type(&txn, ENTITY_TYPE_ACCESS_GRANT, None)?
        {
            count.row();
            let id = entry?;
            let body = match live_entity_row_in_txn(&self.store, &txn, &id)? {
                LiveEntityRow::Absent | LiveEntityRow::DeletedShell => continue,
                LiveEntityRow::Live {
                    entity_type: ENTITY_TYPE_ACCESS_GRANT,
                    body,
                } => body,
                LiveEntityRow::Live { .. } => {
                    return Err(Error::CorruptedIndex("access grant entity type"));
                }
            };
            let grant = decode_access_grant_body(&body)?;
            if let Some((grant_person, facet)) = grant.scope.companion_profile_refs()
                && grant_person == *person_ref
                && grant.allows_companion_profile_read(
                    principal_ref,
                    person_ref,
                    facet.as_ref(),
                    now,
                )
            {
                facets.insert(facet);
            }
        }
        drop(txn);
        count.finish(self);
        Ok(facets.into_iter().collect())
    }
}
