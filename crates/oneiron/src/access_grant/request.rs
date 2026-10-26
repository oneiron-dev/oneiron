//! Durable request/response lifecycle. Approval and its grant share one transaction.

use super::codec::invalid_grant;
use super::{
    AccessGrant, AccessGrantScope, AccessGrantStatus, decode_access_grant_body,
    encode_access_grant_body,
};
use crate::authority::VerifiedSlip;
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, GateError, Result};
use crate::side_table::{self, LegacyJson, SideTable};
use crate::{EntityId, Vault};
use std::ops::Bound;

/// One access request, keyed by its own id (also the eventual grant id).
const REQUESTS: SideTable<EntityId, RequestRow, LegacyJson> =
    SideTable::new(&side_table::ACCESS_REQUEST);

/// Terminal responses cannot be changed by a second responder.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
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
    /// The person or agent the request asks (FIX 1379), who may answer it
    /// beside the owner. None: the owner answers it alone.
    pub addressed_to: Option<EntityId>,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestRow {
    grant: Vec<u8>,
    status: AccessRequestStatus,
    decided_by: Option<String>,
    decided_at: Option<u64>,
    addressed_to: Option<String>,
}

/// Who answers an access request through the addressed door (FIX 1379).
#[derive(Clone, Copy)]
pub enum AccessRequestResponder<'a> {
    /// A live person on their own proof: an owner of the vault, co-Owners
    /// included, or the person the request asks.
    Person(&'a AuthenticatedOwner),
    /// An agent on its own verified credential, which names it as holder.
    Agent {
        actor: EntityId,
        credential: &'a VerifiedSlip,
    },
}

impl AccessRequest {
    fn to_row(&self) -> Result<RequestRow> {
        Ok(RequestRow {
            grant: encode_access_grant_body(&self.grant)?,
            status: self.status,
            decided_by: self.decided_by.map(|id| id.to_hex()),
            decided_at: self.decided_at,
            addressed_to: self.addressed_to.map(|id| id.to_hex()),
        })
    }

    fn from_row(id: EntityId, row: RequestRow) -> Result<Self> {
        let grant = decode_access_grant_body(&row.grant)?;
        let decided_by = row
            .decided_by
            .as_deref()
            .map(EntityId::from_hex)
            .transpose()?;
        let addressed_to = row
            .addressed_to
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
            addressed_to,
        })
    }
}

impl Vault {
    /// Requests cross-relationship access. Requesting confers no authority.
    pub fn request_access(&self, id: EntityId, grant: AccessGrant) -> Result<AccessRequest> {
        self.request_access_to(id, grant, None)
    }

    /// [`Self::request_access`], asking `addressed_to` (FIX 1379): that
    /// person or agent may answer it beside the owner. Asking confers no
    /// authority, on the asker or on the one asked.
    pub fn request_access_to(
        &self,
        id: EntityId,
        grant: AccessGrant,
        addressed_to: Option<EntityId>,
    ) -> Result<AccessRequest> {
        let mut txn = self.store.env.write_txn()?;
        let request = self.insert_access_request_in(&mut txn, id, grant, addressed_to)?;
        txn.commit()?;
        Ok(request)
    }

    /// Files a pending request for `grant` at `id` in the caller's write
    /// transaction, so a writer that decides to propose rather than grant
    /// (FIX 8140) files it in the same transaction it decided in.
    pub(super) fn insert_access_request_in(
        &self,
        txn: &mut heed::RwTxn<'_>,
        id: EntityId,
        grant: AccessGrant,
        addressed_to: Option<EntityId>,
    ) -> Result<AccessRequest> {
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
            addressed_to,
        };
        if REQUESTS.contains(&self.store, txn, &id)? {
            return Err(Error::Record(
                crate::error::RecordError::AccessGrantAlreadyExists,
            ));
        }
        REQUESTS.put(&self.store, txn, &id, &request.to_row()?)?;
        Ok(request)
    }

    /// Whether a request, pending or answered, already holds `id`.
    pub(super) fn access_request_exists_in(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<bool> {
        REQUESTS.contains(&self.store, txn, id)
    }

    pub fn get_access_request(&self, id: EntityId) -> Result<Option<AccessRequest>> {
        let txn = self.store.env.read_txn()?;
        REQUESTS
            .get(&self.store, &txn, &id)?
            .map(|row| AccessRequest::from_row(id, row))
            .transpose()
    }

    /// Page pending requests from the existing request keyspace without minting authority.
    /// The cursor is the last returned request id; terminal rows never consume a page slot.
    /// The caller must enforce the owner/control-plane boundary before surfacing them.
    pub fn pending_access_requests_page(
        &self,
        after: Option<&EntityId>,
        limit: usize,
    ) -> Result<(Vec<AccessRequest>, Option<EntityId>)> {
        if limit == 0 {
            return Ok((Vec::new(), None));
        }
        let txn = self.store.env.read_txn()?;
        // Keys order by request id, so the rows after the cursor start past it.
        let start = after.map_or(Bound::Unbounded, Bound::Excluded);
        let mut requests: Vec<AccessRequest> = Vec::new();
        for entry in REQUESTS.iter_range(&self.store, &txn, start, Bound::Unbounded)? {
            let (id, row) = entry?;
            let request = AccessRequest::from_row(id, row)?;
            if request.status != AccessRequestStatus::Pending {
                continue;
            }
            if requests.len() == limit {
                let next = requests.last().map(|request| request.id);
                return Ok((requests, next));
            }
            requests.push(request);
        }
        Ok((requests, None))
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
        self.respond_access_request_admitted(owner, id, approve, now, |_| Ok(()))
    }

    /// Answers only a companion-profile request; scope admission, target checks,
    /// owner revalidation and the terminal answer share the grant transaction.
    pub fn respond_companion_access_request(
        &self,
        owner: &AuthenticatedOwner,
        id: EntityId,
        approve: bool,
        now: u64,
    ) -> Result<AccessRequest> {
        self.respond_access_request_admitted(owner, id, approve, now, |request| {
            if request.grant.scope.companion_profile_refs().is_some() {
                Ok(())
            } else {
                Err(Error::EntityNotFound)
            }
        })
    }

    fn respond_access_request_admitted(
        &self,
        owner: &AuthenticatedOwner,
        id: EntityId,
        approve: bool,
        now: u64,
        admit: impl FnOnce(&AccessRequest) -> Result<()>,
    ) -> Result<AccessRequest> {
        let mut txn = self.store.env.write_txn()?;
        // A grant is the vault's to give: a native host's proof shows a live
        // person, not whose vault this is.
        let actor = owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
        let request = self.answer_access_request_in(&mut txn, actor, id, approve, now, admit)?;
        txn.commit()?;
        Ok(request)
    }

    /// The addressed answer door (FIX 1379). An owner of the vault,
    /// co-Owners included, answers any request as
    /// [`Self::respond_access_request`] does. The person or agent a request
    /// asks answers that request on their own proof, revalidated in the
    /// answering transaction: they deny it, or approve access to their own
    /// companion profile, the one thing here that is theirs to give. Any
    /// other approval stays pending for the owner. A request not addressed
    /// to them reads as one that does not exist.
    pub fn respond_addressed_access_request(
        &self,
        responder: AccessRequestResponder<'_>,
        id: EntityId,
        approve: bool,
        now: u64,
    ) -> Result<AccessRequest> {
        let mut txn = self.store.env.write_txn()?;
        let actor = match responder {
            AccessRequestResponder::Person(proof) => {
                match proof.revalidate_as_vault_owner_in_txn(self, &txn) {
                    Ok(owner) => {
                        let request = self.answer_access_request_in(
                            &mut txn,
                            owner,
                            id,
                            approve,
                            now,
                            |_| Ok(()),
                        )?;
                        txn.commit()?;
                        return Ok(request);
                    }
                    Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(_))) => {
                        proof.revalidate_person_in_txn(self, &txn)?
                    }
                    Err(error) => return Err(error),
                }
            }
            AccessRequestResponder::Agent { actor, credential } => {
                if credential.is_transferred()
                    || credential.claims().holder_ref != actor.to_hex()
                    || !self.capability_slip_is_live_in_txn(&txn, credential)?
                {
                    return Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(
                        "the answering agent's own credential does not hold",
                    )));
                }
                actor
            }
        };
        let request =
            self.answer_access_request_in(&mut txn, actor, id, approve, now, |request| {
                if request.addressed_to != Some(actor) {
                    return Err(Error::EntityNotFound);
                }
                if approve && !own_companion_profile(&request.grant, &actor) {
                    return Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(
                        ADDRESSED_APPROVAL_PAST_OWN_DATA,
                    )));
                }
                Ok(())
            })?;
        txn.commit()?;
        Ok(request)
    }

    /// Records `actor`'s answer to request `id` in `txn`: the terminal
    /// answer, and on approval its exact grant at the request's id.
    fn answer_access_request_in(
        &self,
        txn: &mut heed::RwTxn<'_>,
        actor: EntityId,
        id: EntityId,
        approve: bool,
        now: u64,
        admit: impl FnOnce(&AccessRequest) -> Result<()>,
    ) -> Result<AccessRequest> {
        let row = REQUESTS
            .get(&self.store, txn, &id)?
            .ok_or(Error::EntityNotFound)?;
        let mut request = AccessRequest::from_row(id, row)?;
        admit(&request)?;
        if request.status != AccessRequestStatus::Pending || now < request.grant.created_at {
            return Err(invalid_grant());
        }
        request.status = if approve {
            AccessRequestStatus::Approved
        } else {
            AccessRequestStatus::Denied
        };
        request.decided_by = Some(actor);
        request.decided_at = Some(now);
        if approve {
            self.check_companion_profile_target(txn, &request.grant)?;
            if crate::ports::EntityStoreRead::port_entity_present(&self.store, &**txn, &id)? {
                return Err(invalid_grant());
            }
            self.apply_access_grant_body(txn, &id, now, encode_access_grant_body(&request.grant)?)?;
        }
        REQUESTS.put(&self.store, txn, &id, &request.to_row()?)?;
        Ok(request)
    }
}

/// The refusal of an addressed member's approval past their own data (CALLS
/// "OF-1379 addressed member approval", open): the request stays pending
/// for the owner, never approved with a partial grant.
const ADDRESSED_APPROVAL_PAST_OWN_DATA: &str = "an addressed member approves access only to their own companion profile; the owner answers the rest";

/// Whether `grant` reads only `actor`'s own companion profile.
fn own_companion_profile(grant: &AccessGrant, actor: &EntityId) -> bool {
    grant
        .scope
        .companion_profile_refs()
        .is_some_and(|(person, _)| person == *actor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{embedding_test_config, entity, open_test_vault_with};
    #[test]
    fn request_approve_and_deny_are_durable_terminal_and_atomic() -> Result<()> {
        let (_dir, vault) = open_test_vault_with(embedding_test_config());
        let actor = vault.ensure_embedded_owner_actor().expect("the owner");
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
                authority_scope: crate::federation::scope_codec::read_preset(),
            };
            assert_eq!(
                vault.request_access(id, grant.clone())?.status,
                AccessRequestStatus::Pending
            );
            assert!(vault.get_access_grant(&id)?.is_none());
            assert!(vault.pending_access_requests_page(None, 0)?.0.is_empty());
            assert_eq!(
                vault.pending_access_requests_page(None, 1)?.0,
                vec![vault.get_access_request(id)?.unwrap()]
            );
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
            assert!(vault.pending_access_requests_page(None, 1)?.0.is_empty());
            assert_eq!(vault.get_access_grant(&id)?, approve.then_some(grant));
            assert!(
                vault
                    .respond_access_request(&owner, id, !approve, 3)
                    .is_err()
            );
        }
        Ok(())
    }

    /// Astra r1 on #1458: a native host's proof shows a live person, not
    /// whose vault this is. A person who does not own it answers no request.
    #[test]
    fn a_non_owner_persons_proof_answers_no_access_request() -> Result<()> {
        let (_dir, vault) = open_test_vault_with(embedding_test_config());
        let person = entity(0x54);
        vault.put_entity(
            &person,
            crate::registry::ENTITY_TYPE_PERSON,
            crate::TimeRange { start: 1, end: 1 },
            1,
            b"a member",
        )?;
        let id = EntityId::now();
        let grant = AccessGrant {
            principal_ref: person,
            scope: AccessGrantScope::Messages {
                space_ref: entity(0x53),
            },
            capability: super::super::AccessGrantCapability::MessagesRead,
            status: AccessGrantStatus::Active,
            created_at: 1,
            revoked_at: None,
            expires_at: None,
            authority_scope: crate::federation::scope_codec::read_preset(),
        };
        vault.request_access(id, grant.clone())?;
        let proof = vault.authenticate_owner(
            person,
            &person.to_hex(),
            true,
            crate::store::GateDecisionId::now(),
        )?;

        assert!(matches!(
            vault.respond_access_request(&proof, id, true, 2),
            Err(Error::Gate(
                crate::error::GateError::ConsentOwnerNotAuthenticated(_)
            ))
        ));
        assert!(vault.get_access_grant(&id)?.is_none());
        assert_eq!(
            vault.get_access_request(id)?.map(|request| request.status),
            Some(AccessRequestStatus::Pending)
        );
        let owner = vault.ensure_embedded_owner_actor().expect("the owner");
        let owner = vault.authenticate_owner(
            owner,
            &owner.to_hex(),
            true,
            crate::store::GateDecisionId::now(),
        )?;
        vault.respond_access_request(&owner, id, true, 2)?;
        assert_eq!(vault.get_access_grant(&id)?, Some(grant));
        Ok(())
    }
}
