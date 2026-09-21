//! Durable request/response lifecycle. Approval and its grant share one transaction.

use super::codec::invalid_grant;
use super::{
    AccessGrant, AccessGrantScope, AccessGrantStatus, decode_access_grant_body,
    encode_access_grant_body,
};
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result};
use crate::{EntityId, Vault};

/// Terminal responses cannot be changed by a second responder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AccessRequestStatus {
    Pending,
    Approved,
    Denied,
}

/// The request retains the requested grant and the authenticated responder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessRequest {
    pub id: EntityId,
    pub grant: AccessGrant,
    pub status: AccessRequestStatus,
    pub decided_by: Option<EntityId>,
    pub decided_at: Option<u64>,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestRow {
    grant: Vec<u8>,
    status: AccessRequestStatus,
    decided_by: Option<String>,
    decided_at: Option<u64>,
}

fn key(id: &EntityId) -> Vec<u8> {
    let mut key = b"access-request:v1:".to_vec();
    key.extend_from_slice(id.as_bytes());
    key
}

impl AccessRequest {
    fn encode(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(&RequestRow {
            grant: encode_access_grant_body(&self.grant)?,
            status: self.status,
            decided_by: self.decided_by.map(|id| id.to_hex()),
            decided_at: self.decided_at,
        })
        .map_err(|_| invalid_grant())
    }

    fn decode(id: EntityId, bytes: &[u8]) -> Result<Self> {
        let row: RequestRow = serde_json::from_slice(bytes).map_err(|_| invalid_grant())?;
        let grant = decode_access_grant_body(&row.grant)?;
        let decided_by = row
            .decided_by
            .as_deref()
            .map(EntityId::from_hex)
            .transpose()?;
        let pending = row.status == AccessRequestStatus::Pending;
        if pending != row.decided_at.is_none()
            || pending != decided_by.is_none()
            || row.decided_at.is_some_and(|at| at < grant.created_at)
        {
            return Err(invalid_grant());
        }
        Ok(Self {
            id,
            grant,
            status: row.status,
            decided_by,
            decided_at: row.decided_at,
        })
    }
}

impl Vault {
    /// Requests cross-relationship access. Requesting confers no authority.
    pub fn request_access(&self, id: EntityId, grant: AccessGrant) -> Result<AccessRequest> {
        grant.validate()?;
        if grant.status != AccessGrantStatus::Active
            || !matches!(
                grant.scope,
                AccessGrantScope::Messages { .. }
                    | AccessGrantScope::Summaries { .. }
                    | AccessGrantScope::RelationshipClaims { .. }
                    | AccessGrantScope::CompanionProfile { .. }
            )
        {
            return Err(invalid_grant());
        }
        let request = AccessRequest {
            id,
            grant,
            status: AccessRequestStatus::Pending,
            decided_by: None,
            decided_at: None,
        };
        let mut txn = self.store.env.write_txn()?;
        if self.store.vault_meta.get(&txn, &key(&id))?.is_some() {
            return Err(Error::Record(
                crate::error::RecordError::AccessGrantAlreadyExists,
            ));
        }
        self.store
            .vault_meta
            .put(&mut txn, &key(&id), &request.encode()?)?;
        txn.commit()?;
        Ok(request)
    }

    pub fn get_access_request(&self, id: EntityId) -> Result<Option<AccessRequest>> {
        let txn = self.store.env.read_txn()?;
        self.store
            .vault_meta
            .get(&txn, &key(&id))?
            .map(|bytes| AccessRequest::decode(id, &bytes))
            .transpose()
    }

    /// Owner-bound response. The request id is also the resulting grant id,
    /// so the request/grant link is stable and cannot point at another grant.
    pub fn respond_access_request(
        &self,
        owner: &AuthenticatedOwner,
        id: EntityId,
        approve: bool,
        now: u64,
    ) -> Result<AccessRequest> {
        let mut txn = self.store.env.write_txn()?;
        owner.revalidate_in_txn(self, &txn)?;
        let raw = self
            .store
            .vault_meta
            .get(&txn, &key(&id))?
            .ok_or(Error::EntityNotFound)?;
        let mut request = AccessRequest::decode(id, &raw)?;
        if request.status != AccessRequestStatus::Pending || now < request.grant.created_at {
            return Err(invalid_grant());
        }
        request.status = if approve {
            AccessRequestStatus::Approved
        } else {
            AccessRequestStatus::Denied
        };
        request.decided_by = Some(owner.actor());
        request.decided_at = Some(now);
        if approve {
            if self.store.entities.get(&txn, id.as_bytes())?.is_some() {
                return Err(invalid_grant());
            }
            self.apply_access_grant_body(
                &mut txn,
                &id,
                now,
                encode_access_grant_body(&request.grant)?,
            )?;
        }
        self.store
            .vault_meta
            .put(&mut txn, &key(&id), &request.encode()?)?;
        txn.commit()?;
        Ok(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{embedding_test_config, entity, open_test_vault_with};
    #[test]
    fn request_approve_and_deny_are_durable_terminal_and_atomic() -> Result<()> {
        let (_dir, vault) = open_test_vault_with(embedding_test_config());
        let actor = entity(0x51);
        vault.put_entity(
            &actor,
            crate::registry::ENTITY_TYPE_PERSON,
            crate::TimeRange { start: 1, end: 1 },
            1,
            b"owner",
        )?;
        let owner = vault.authenticate_owner(
            actor,
            "principal:owner",
            true,
            crate::store::GateDecisionId::now(),
        )?;
        for approve in [true, false] {
            let id = EntityId::now();
            let grant = AccessGrant {
                principal_ref: entity(0x52),
                scope: AccessGrantScope::Messages {
                    space_ref: entity(0x53),
                },
                capability: super::super::AccessGrantCapability::MessagesRead,
                status: AccessGrantStatus::Active,
                created_at: 1,
                revoked_at: None,
                expires_at: None,
            };
            assert_eq!(
                vault.request_access(id, grant.clone())?.status,
                AccessRequestStatus::Pending
            );
            assert!(vault.get_access_grant(&id)?.is_none());
            let answered = vault.respond_access_request(&owner, id, approve, 2)?;
            assert_eq!(
                answered.status,
                if approve {
                    AccessRequestStatus::Approved
                } else {
                    AccessRequestStatus::Denied
                }
            );
            assert_eq!(vault.get_access_request(id)?, Some(answered));
            assert_eq!(vault.get_access_grant(&id)?, approve.then_some(grant));
            assert!(
                vault
                    .respond_access_request(&owner, id, !approve, 3)
                    .is_err()
            );
        }
        Ok(())
    }
}
