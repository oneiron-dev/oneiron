//! Transaction-bound shared-vault membership write authorization.

use super::{
    FederationGrant, FederationGrantRole, FederationGrantScope, OrgAdminPower, Scope, ScopeAxis,
    decode_federation_grant_body,
};
use crate::Vault;
use crate::authority::{FederationGrantActivation, federation_grant_activation};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::error::{ClaimError, Error, Result};
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_FEDERATION_GRANT;
use crate::write_envelope::WriteActor;
use std::collections::BTreeSet;

/// A requested shared-vault mutation. Personal roots never inherit shared authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SharedVaultWrite {
    /// Content with its resolved six-axis record scope; a missing axis is bottom.
    Content(Scope),
    /// One named organization-administration power.
    Admin(OrgAdminPower),
    /// A conflict review ruling in this shared vault.
    RuleConflict,
    /// Change a shared workspace setting; enrollment authority alone does not confer it.
    WorkspaceSettings,
    /// Mutate the organization root.
    OrgRoot,
    /// Mutate a member's separate personal root.
    PersonalVault,
    /// Object during a catastrophic-act veto window.
    Veto,
}

fn denied() -> Error {
    Error::Claim(ClaimError::ActorLacksClaimAuthority {
        reason: "shared-vault role or named power does not authorize this write",
    })
}

impl Vault {
    /// Checks the current stored roster, role, named verb, and scope in one snapshot.
    /// A grant over another vault or an inactive pact never contributes a power.
    pub fn authorize_shared_vault_write(
        &self,
        vault_id: u64,
        writer: &WriteActor,
        requested: &SharedVaultWrite,
    ) -> Result<()> {
        let txn = self.store.env.read_txn()?;
        self.authorize_shared_vault_write_in_txn(&txn, vault_id, writer, requested)
    }

    pub(crate) fn authorize_shared_vault_write_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        vault_id: u64,
        writer: &WriteActor,
        requested: &SharedVaultWrite,
    ) -> Result<()> {
        let fold = self.verify_write_actor_in_txn(txn, writer)?;
        if vault_id == 0 || matches!(requested, SharedVaultWrite::PersonalVault) {
            return Err(denied());
        }
        for entry in self
            .store
            .port_entity_ids_by_type(txn, ENTITY_TYPE_FEDERATION_GRANT, None)?
        {
            let id = entry?;
            let raw = self
                .store
                .port_entity_record(txn, &id)?
                .ok_or_else(denied)?
                .encode();
            if EntityMetadataHeader::parse(&raw)
                .is_none_or(|header| header.entity_type != ENTITY_TYPE_FEDERATION_GRANT)
            {
                return Err(denied());
            }
            let grant = decode_federation_grant_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
            if grant.scope != FederationGrantScope::vault(vault_id)
                || grant.member_ref != writer.entity_ref()
                || grant
                    .expires_at
                    .is_some_and(|expires| self.store.clock.now_recorded_at() >= expires)
                || matches!(
                    federation_grant_activation(&fold, &id),
                    FederationGrantActivation::Inactive(_)
                )
            {
                continue;
            }
            if let SharedVaultWrite::Content(scope) = requested {
                if grant_allows_content_write(&grant, scope) {
                    return Ok(());
                }
                continue;
            }
            let role_permits = match requested {
                SharedVaultWrite::Admin(_)
                | SharedVaultWrite::RuleConflict
                | SharedVaultWrite::WorkspaceSettings => grant.role.is_admin(),
                SharedVaultWrite::OrgRoot | SharedVaultWrite::Veto => {
                    grant.role == FederationGrantRole::Owner
                }
                SharedVaultWrite::PersonalVault | SharedVaultWrite::Content(_) => false,
            };
            if !role_permits {
                continue;
            }
            let (verb, mut record) = match requested {
                SharedVaultWrite::Admin(power) => (power.as_str(), Scope::top()),
                SharedVaultWrite::RuleConflict => ("admin", Scope::top()),
                SharedVaultWrite::WorkspaceSettings => ("write", Scope::top()),
                SharedVaultWrite::OrgRoot => ("org:root", Scope::top()),
                SharedVaultWrite::Veto => ("owner:veto", Scope::top()),
                SharedVaultWrite::PersonalVault | SharedVaultWrite::Content(_) => unreachable!(),
            };
            record.verbs = ScopeAxis::Some(BTreeSet::from([verb.to_owned()]));
            if grant.authority_scope.admits(verb, &record, &Scope::top()) {
                return Ok(());
            }
        }
        Err(denied())
    }
}

/// Shared role and resolved record-scope check used by local and sync write doors.
pub(crate) fn grant_allows_content_write(grant: &FederationGrant, scope: &Scope) -> bool {
    if !matches!(
        grant.role,
        FederationGrantRole::Owner
            | FederationGrantRole::Admin
            | FederationGrantRole::Member
            | FederationGrantRole::Delegate
    ) {
        return false;
    }
    let mut record = scope.clone();
    record.verbs = ScopeAxis::Some(BTreeSet::from(["write".to_owned()]));
    grant
        .authority_scope
        .admits("write", &record, &Scope::top())
}

impl Vault {
    /// Check a staged content row in the same writer that commits its mutation.
    /// Personal vaults have no shared-creation row and keep their own authority.
    pub(crate) fn authorize_shared_content_write_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        id: crate::EntityId,
        writer: &WriteActor,
    ) -> Result<()> {
        let Some(creation) = self.shared_vault_creation_in_txn(txn)? else {
            return Ok(());
        };
        let raw = self.get_raw_in(txn, &id)?.ok_or_else(denied)?;
        let header = EntityMetadataHeader::parse(&raw).ok_or_else(denied)?;
        let scope = match super::record_scope::scope_for_blob(&self.store, txn, id, &raw)? {
            Some(scope) => scope,
            None if header.entity_type == crate::registry::ENTITY_TYPE_NOTE => {
                // A NOTE born without a FacetOf edge has the ordinary base/default
                // position. Never use this fallback for another record kind.
                super::record_scope::default_stamp(
                    header.entity_type,
                    crate::claim::substrate_facet_id(id),
                )
            }
            None => return Err(denied()),
        };
        self.authorize_shared_vault_write_in_txn(
            txn,
            creation.vault_id,
            writer,
            &SharedVaultWrite::Content(scope),
        )
    }

    /// NOTE-specific spelling for the actor-bound editor doors.
    pub(crate) fn authorize_shared_note_write_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        note: crate::EntityId,
        writer: &WriteActor,
    ) -> Result<()> {
        self.authorize_shared_content_write_in_txn(txn, note, writer)
    }
}
