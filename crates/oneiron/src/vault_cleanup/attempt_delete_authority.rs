//! Restore-equivalent owner and live vault Admin authority for attempt cleanup.
//! Attempts have no disclosure position: this is a vault control-plane act.

use std::collections::BTreeSet;

use crate::EntityId;
use crate::edge::EdgeActorClass;
use crate::federation::{
    FederationGrantScope, MembershipStanding, Scope, ScopeAxis, decode_federation_grant_body,
};
use crate::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_FEDERATION_GRANT;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};

pub(super) struct DeleteAuthority {
    pub(super) actor: EntityId,
    pub(super) role: &'static str,
    pub(super) grant: Option<EntityId>,
}

pub(super) fn require_delete_in_txn(
    memory: &Memory<'_>,
    txn: &heed::RoTxn<'_>,
) -> MemoryResult<DeleteAuthority> {
    let vault = memory.vault();
    let actor = memory.actor();
    if let Some(owner) = memory.owner_authorship() {
        let proven = owner.revalidate_in_txn(vault, txn)?;
        if proven != actor || memory.actor_class() != EdgeActorClass::Human {
            return Err(forbidden("attempt_delete_owner_binding"));
        }
        return Ok(DeleteAuthority {
            actor,
            role: "owner",
            grant: None,
        });
    }
    if memory.actor_class() != EdgeActorClass::Human {
        return Err(forbidden("attempt_delete_no_standing"));
    }
    vault.verify_write_actor_in_txn(txn, &memory.write_actor())?;
    if !credential_reaches(memory, txn)? {
        return Err(forbidden("attempt_delete_credential_bounds"));
    }
    let Some(shared) = vault.shared_vault_creation_in_txn(txn)? else {
        return Err(forbidden("attempt_delete_no_standing"));
    };
    let scope = FederationGrantScope::vault(shared.vault_id);
    for id in vault
        .store
        .port_entity_ids_by_type(txn, ENTITY_TYPE_FEDERATION_GRANT, None)?
    {
        let id = id?;
        let LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_FEDERATION_GRANT,
            body,
        } = live_entity_row_in_txn(&vault.store, txn, &id)?
        else {
            continue;
        };
        let grant = decode_federation_grant_body(&body)?;
        if grant.member_ref != actor || grant.scope != scope {
            continue;
        }
        if matches!(
            vault.authenticated_grant_membership_in_txn(txn, scope, actor, id)?,
            Some(MembershipStanding::Member { role, .. }) if role.is_admin()
        ) && admits_operation(&grant.authority_scope)
        {
            return Ok(DeleteAuthority {
                actor,
                role: "admin",
                grant: Some(id),
            });
        }
    }
    Err(forbidden("attempt_delete_no_standing"))
}

/// This is the existing vault-wide Admin operation record (membership_gate),
/// not an attempt's disclosure position. Both ceilings must admit it.
fn admits_operation(scope: &Scope) -> bool {
    let mut operation = Scope::top();
    operation.verbs = ScopeAxis::Some(BTreeSet::from(["admin".to_owned()]));
    scope.admits("admin", &operation, &Scope::top())
}

fn credential_reaches(memory: &Memory<'_>, txn: &heed::RoTxn<'_>) -> crate::Result<bool> {
    let Some(proof) = memory.presented_credential() else {
        return Ok(true);
    };
    let claims = proof.claims();
    Ok(claims.holder_ref == memory.actor().to_hex()
        && claims.invitation_ref.is_none()
        && claims.records.is_empty()
        && claims.channels.is_empty()
        && admits_operation(proof.scope())
        && memory.vault().capability_slip_is_live_in_txn(txn, proof)?)
}

fn forbidden(reason: &str) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_FORBIDDEN,
        reason,
        &["Use the authenticated vault owner's proof or a live vault Admin credential."],
    )
}
