//! Resident submissions and revocation. Only owned witnesses reach mutation.
use super::pair::{OwnedDiaryEndpoint, candidate_author_in};
use crate::access_grant::{
    AccessGrant, AccessGrantCapability, AccessGrantScope, AccessGrantStatus,
};
use crate::batch::{BatchOp, apply_ops};
use crate::edge::EdgeKind;
use crate::error::Result;
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::ports::EntityStoreRead;
use crate::{EntityId, Vault};

fn owned_endpoint(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: EntityId,
    a: EntityId,
    b: EntityId,
) -> MemoryResult<OwnedDiaryEndpoint> {
    OwnedDiaryEndpoint::admit(vault, txn, actor, a, b)?
        .ok_or_else(|| MemoryError::bad_request("resident must own exactly one diary endpoint"))
}

/// Unilateral intent. Only `access::pair_access_in` promotes two live
/// consents and a validated link into a shared relation.
struct DiaryConsent(AccessGrant);
impl DiaryConsent {
    fn new(owner: EntityId, endpoint: OwnedDiaryEndpoint, created_at: u64) -> Self {
        let pair = endpoint.pair;
        Self(AccessGrant {
            authority_scope: crate::federation::scope_codec::read_preset(),
            principal_ref: owner,
            scope: AccessGrantScope::DiaryCoreference {
                left_ref: pair.left,
                right_ref: pair.right,
            },
            capability: AccessGrantCapability::DiaryCoreferenceRead,
            status: AccessGrantStatus::Active,
            created_at,
            revoked_at: None,
            expires_at: None,
        })
    }
}

/// The only object that may reach the revoke write. Foreign, missing,
/// malformed and wrong-kind references never construct it.
struct OwnedDiaryConsent(AccessGrant);
impl OwnedDiaryConsent {
    fn find(memory: &Memory<'_>, txn: &heed::RoTxn<'_>, id: EntityId) -> MemoryResult<Self> {
        let hidden = || MemoryError::not_found("diary consent unavailable");
        let Some(raw) = memory.vault().store.port_entity_record(txn, &id)? else {
            return Err(hidden());
        };
        if raw.entity_type != crate::registry::ENTITY_TYPE_ACCESS_GRANT {
            return Err(hidden());
        }
        let Ok(grant) = crate::access_grant::decode_access_grant_body(&raw.body) else {
            return Err(hidden());
        };
        let AccessGrantScope::DiaryCoreference {
            left_ref,
            right_ref,
        } = grant.scope
        else {
            return Err(hidden());
        };
        if grant.principal_ref != memory.actor()
            || grant.capability != AccessGrantCapability::DiaryCoreferenceRead
            || OwnedDiaryEndpoint::admit(memory.vault(), txn, memory.actor(), left_ref, right_ref)?
                .is_none()
        {
            return Err(hidden());
        }
        Ok(Self(grant))
    }
    fn revoke(self, now: u64) -> Result<AccessGrant> {
        self.0.revoked(now.max(self.0.created_at))
    }
}

impl Memory<'_> {
    /// Accept a resident's own diary link submission. An absent, wrong-kind,
    /// existing or valid foreign candidate returns the SAME acknowledgement.
    pub fn link_diary_coreference(&self, a: EntityId, b: EntityId) -> MemoryResult<()> {
        self.with_verified_actor_write_txn(|txn| {
            let owned = owned_endpoint(self.vault(), txn, self.actor(), a, b)?;
            let pair = owned.pair;
            if candidate_author_in(self.vault(), txn, owned.foreign)?.is_none()
                || pair.linked_in(self.vault(), txn)?
            {
                return Ok(());
            }
            apply_ops(
                &self.vault().store,
                &self.vault().config,
                &self.vault().analyzer,
                txn,
                vec![BatchOp::Edge {
                    src: pair.left,
                    kind: EdgeKind::SameAs,
                    tgt: pair.right,
                    weight: 0.0,
                    vad: crate::Vad::NEUTRAL,
                }],
                self.vault()
                    .text_index_trusted
                    .load(std::sync::atomic::Ordering::Acquire),
                false,
                true,
            )?;
            Ok(())
        })
    }

    /// Store one resident-owned exact-pair consent intent. The foreign id is
    /// opaque until the pair evaluator proves both consents and an actual edge.
    pub fn grant_diary_coreference(&self, a: EntityId, b: EntityId) -> MemoryResult<EntityId> {
        self.with_verified_actor_write_txn(|txn| {
            let owned = owned_endpoint(self.vault(), txn, self.actor(), a, b)?;
            let id = self.vault().store.clock.entity_id()?;
            let created_at = self.vault().store.clock.now_recorded_at();
            let data = crate::access_grant::encode_access_grant_body(
                &DiaryConsent::new(self.actor(), owned, created_at).0,
            )?;
            self.vault()
                .apply_access_grant_body(txn, &id, created_at, data)?;
            Ok(id)
        })
    }

    /// Only a resident-owned consent is revocable. All other candidate IDs
    /// give the same *full* public error, irrespective of stored row/type.
    pub fn revoke_diary_coreference_grant(&self, id: EntityId) -> MemoryResult<()> {
        self.with_verified_actor_write_txn(|txn| {
            let owned = OwnedDiaryConsent::find(self, txn, id)?;
            let now = self.vault().store.clock.now_recorded_at();
            let revoked = owned.revoke(now)?;
            let data = crate::access_grant::encode_access_grant_body(&revoked)?;
            self.vault()
                .apply_access_grant_body(txn, &id, now.max(revoked.created_at), data)?;
            Ok(())
        })
    }
}
