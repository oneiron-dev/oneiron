//! The audit_read power (RULING AUDIT-READ-POWER-LIST = B, the lead 15 Nov
//! 21:1x; Engine RULING AUDITREAD-GRANT-HOME = A, 15 Nov 22:00). The 7 Nov
//! ROLES ruling retired `auditor` as a role: what it granted, the audit and
//! receipt reads, became this one power, which any person or agent can hold
//! whatever role or preset it has. One power, not one per family: an auditor
//! either audits or does not.
//!
//! - It is an AccessGrant of scope [`AccessGrantScope::VaultAudit`] and
//!   capability [`AccessGrantCapability::AuditRead`], one per holder, at the
//!   id the holder derives ([`audit_read_grant_id`]).
//! - The owner alone grants and revokes it, as his own act
//!   (`vault.audit_read.grant`, `vault.audit_read.revoke`). His proof is
//!   revalidated in the write's own transaction. Every generic AccessGrant
//!   door refuses the scope, so no other path writes, overwrites or revokes
//!   one.
//! - Each change records the owner's act in the access-grant owner-act index
//!   in the same write. `vault.authority.audit` lists those acts
//!   ([`Vault::audit_read_acts_in_txn`]), so an auditor sees who else audits,
//!   and both owner verbs answer the live holders.
//! - [`Vault::audit_read_live_in_txn`] is the one check. Each covered door
//!   asks it in its own read, so a revoke or an expiry refuses at the very
//!   next read. Labels still apply to what a door returns: a door that reads
//!   rows reads them through the holder's own lane.
//!
//! Stored change: keep. The scope and capability strings are new; every row a
//! vault holds decodes as before.

use crate::Vault;
use crate::authority::ActSurface;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::{Error, GateError, RecordError, Result};
use crate::ports::EntityStoreRead;
use crate::registry::{ENTITY_TYPE_ACCESS_GRANT, ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_PERSON};
use crate::vault::LiveEntityRow;

use super::{
    AccessGrant, AccessGrantActChange, AccessGrantCapability, AccessGrantScope, AccessGrantStatus,
    access_grant_owner_acts_in_txn, decode_access_grant_body, decode_erased_grant_body,
    decode_live_access_grant_body, encode_access_grant_body, erased_grant, invalid_grant,
    record_access_grant_owner_act_in_txn,
};

use oneiron_records::receipt::authority_audit::AuditReadActRow;
use oneiron_verb_wire::verbs::audit_read::AuditReadHolderRow;

/// An audit_read grant. Parts: the holder.
const AUDIT_READ_GRANT_DOMAIN: &[u8] = b"oneiron.access_grant.audit_read.v1";

/// What an audit door answers a reader that is neither the owner nor a live
/// holder of the audit_read power.
const AUDIT_READ_REFUSAL: &str = "an audit read needs the owner's proof or a live audit_read power";

/// What a generic delete door answers for an audit_read grant. A replayed
/// peer tombstone's refusal matches it exactly.
pub(crate) const AUDIT_READ_DELETE_REFUSAL: &str =
    "an audit_read grant ends only through the owner's vault.audit_read.revoke, never a delete";

/// Who reads an audit door (RULING AUDIT-READ-POWER-LIST = B): the vault's
/// owner on his own proof, or an actor that holds the audit_read power. A
/// host builds the owner's from the proof the request carries; a holder
/// comes only from a bound handle ([`crate::memory::Memory::audit_reader`]).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum AuditReader {
    /// The vault's owner. The door revalidates his proof in its own read.
    Owner(AuthenticatedOwner),
    /// Any other actor. The door reads for it only while its audit_read power
    /// is live in the door's own read.
    Holder(AuditHolder),
}

/// The actor a bound handle names as an audit door's reader. Only the handle
/// builds one; the door checks its power.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditHolder {
    actor: EntityId,
}

impl AuditHolder {
    /// The reader `actor`, as its bound handle names it.
    pub(crate) const fn of(actor: EntityId) -> Self {
        Self { actor }
    }

    /// The actor this reader is.
    #[must_use]
    pub const fn actor(self) -> EntityId {
        self.actor
    }
}

impl AuditReader {
    /// Admits this reader in the door's own read `txn` and answers the actor
    /// it reads as: the owner's proof revalidates, or the holder's audit_read
    /// power is live at the vault's clock.
    ///
    /// # Errors
    /// The owner's proof no longer proves the vault's owner; the holder holds
    /// no live audit_read power; or the read fails.
    pub(crate) fn admit_in_txn(&self, vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<EntityId> {
        match self {
            Self::Owner(owner) => owner.revalidate_in_txn(vault, txn),
            Self::Holder(holder) if vault.audit_read_live_in_txn(txn, holder.actor)? => {
                Ok(holder.actor)
            }
            Self::Holder(_) => Err(audit_read_refused()),
        }
    }
}

/// An audit door's refusal of a reader that is neither the owner nor a live
/// holder.
fn audit_read_refused() -> Error {
    Error::Gate(GateError::ConsentOwnerNotAuthenticated(AUDIT_READ_REFUSAL))
}

/// What the owner's grant or revoke of the audit_read power did.
pub(crate) struct AuditReadChange {
    /// The holder's grant row.
    pub(crate) grant_ref: EntityId,
    /// The grant as it now stands.
    pub(crate) grant: AccessGrant,
    /// Its status at the act, at the vault's clock.
    pub(crate) status: AccessGrantStatus,
    /// False when the grant already stood so and the call changed nothing.
    pub(crate) changed: bool,
    /// Every live holder after the call.
    pub(crate) holders: Vec<AuditReadHolderRow>,
}

impl Vault {
    /// The one audit_read check: whether `actor` holds a live audit_read
    /// power as `txn` reads it, at the vault's clock. The grant must be the
    /// live row at the id `actor` derives, name `actor`, and be active.
    ///
    /// Fable pass 26 A0 takes it over by its last line: `live` becomes the
    /// read's `Permitted` (`Nothing` when false).
    ///
    /// # Errors
    /// The row or the clock does not read, or the row there does not decode.
    pub(crate) fn audit_read_live_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        actor: EntityId,
    ) -> Result<bool> {
        let id = audit_read_grant_id(actor)?;
        let LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_ACCESS_GRANT,
            body,
        } = crate::vault::live_entity_row_in_txn(&self.store, txn, &id)?
        else {
            return Ok(false);
        };
        // An erased principal's grant is inert history: no power.
        let Some(grant) = decode_live_access_grant_body(&body)? else {
            return Ok(false);
        };
        let live = audit_read_holder(&id, &grant) == Some(actor)
            && grant.allows_audit_read(actor, self.instant_in_txn(txn)?.secs());
        Ok(live)
    }

    /// Grants `holder` the audit_read power on `owner`'s word, at the
    /// holder's own grant id, active from the vault's clock and ending at
    /// `expires_at` when it names an end. A grant that stands active with the
    /// same end is answered as it stands, unchanged; a revoked or expired
    /// one is granted anew. The owner's proof, the holder and the grant are
    /// read in the write's own transaction, and a change records the owner's
    /// act in it.
    ///
    /// # Errors
    /// `owner` no longer proves the vault's owner; `EntityNotFound` when
    /// `holder` names no live PERSON or AGENT_DEF; `AccessGrantAlreadyExists`
    /// when another row holds its grant id; an invalid grant when
    /// `expires_at` is not after the vault's clock; or the vault write fails.
    pub(crate) fn grant_audit_read(
        &self,
        owner: &AuthenticatedOwner,
        surface: ActSurface,
        holder: EntityId,
        expires_at: Option<u64>,
    ) -> Result<AuditReadChange> {
        let id = audit_read_grant_id(holder)?;
        let mut wtxn = self.store.env.write_txn()?;
        let actor = owner.revalidate_in_txn(self, &wtxn)?;
        if !matches!(
            crate::vault::live_entity_row_in_txn(&self.store, &wtxn, &holder)?,
            LiveEntityRow::Live {
                entity_type: ENTITY_TYPE_PERSON | ENTITY_TYPE_AGENT_DEF,
                ..
            }
        ) {
            return Err(Error::EntityNotFound);
        }
        let now = self.instant_in_txn(&wtxn)?.secs();
        if expires_at.is_some_and(|end| end <= now) {
            return Err(invalid_grant());
        }
        let standing = self.audit_read_grant_at_in(&wtxn, &id)?;
        let (grant, changed) = match standing {
            Some(grant)
                if grant.effective_status_at(now) == AccessGrantStatus::Active
                    && grant.expires_at == expires_at =>
            {
                (grant, false)
            }
            _ => {
                let grant = audit_read_grant(holder, now, expires_at);
                crate::share::check_generic_grant_write(self, &wtxn, &id, &grant)?;
                self.apply_access_grant_body(
                    &mut wtxn,
                    &id,
                    now,
                    encode_access_grant_body(&grant)?,
                )?;
                record_access_grant_owner_act_in_txn(
                    self,
                    &mut wtxn,
                    actor,
                    id,
                    surface,
                    AccessGrantActChange::Grant,
                )?;
                (grant, true)
            }
        };
        let holders = self.audit_read_holders_in_txn(&wtxn)?;
        wtxn.commit()?;
        Ok(AuditReadChange {
            grant_ref: id,
            status: grant.effective_status_at(now),
            grant,
            changed,
            holders,
        })
    }

    /// Revokes `holder`'s audit_read power on `owner`'s word: its grant is
    /// rewritten as revoked at the vault's clock, so the holder's next read
    /// is refused. A grant already revoked is answered as it stands,
    /// unchanged. The owner's proof and the grant are read in the write's own
    /// transaction, and a change records the owner's act in it.
    ///
    /// # Errors
    /// `owner` no longer proves the vault's owner; `EntityNotFound` when
    /// `holder` was never granted the power; `AccessGrantAlreadyExists` when
    /// another row holds its grant id; or the vault write fails.
    pub(crate) fn revoke_audit_read(
        &self,
        owner: &AuthenticatedOwner,
        surface: ActSurface,
        holder: EntityId,
    ) -> Result<AuditReadChange> {
        let id = audit_read_grant_id(holder)?;
        let mut wtxn = self.store.env.write_txn()?;
        let actor = owner.revalidate_in_txn(self, &wtxn)?;
        let standing = self
            .audit_read_grant_at_in(&wtxn, &id)?
            .ok_or(Error::EntityNotFound)?;
        let now = self.instant_in_txn(&wtxn)?.secs();
        let (grant, changed) = if standing.status == AccessGrantStatus::Revoked {
            (standing, false)
        } else {
            let revoked = standing.revoked(now.max(standing.created_at))?;
            self.apply_access_grant_body(&mut wtxn, &id, now, encode_access_grant_body(&revoked)?)?;
            record_access_grant_owner_act_in_txn(
                self,
                &mut wtxn,
                actor,
                id,
                surface,
                AccessGrantActChange::Revoke,
            )?;
            (revoked, true)
        };
        let holders = self.audit_read_holders_in_txn(&wtxn)?;
        wtxn.commit()?;
        Ok(AuditReadChange {
            grant_ref: id,
            status: grant.effective_status_at(now),
            grant,
            changed,
            holders,
        })
    }

    /// The audit_read grant at `id` as `txn` reads it, any status: none when
    /// no row is there.
    ///
    /// # Errors
    /// `AccessGrantAlreadyExists` when another row holds the id: a deleted
    /// row, or a grant that is no audit_read grant at its holder's id. Any
    /// caller that chooses its own id can place one there, so the owner's
    /// verbs name that case apart from a holder never granted. Also an
    /// erased grant; another kind of row; or a read that fails.
    fn audit_read_grant_at_in(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<Option<AccessGrant>> {
        match crate::vault::live_entity_row_in_txn(&self.store, txn, id)? {
            LiveEntityRow::Live {
                entity_type: ENTITY_TYPE_ACCESS_GRANT,
                body,
            } => {
                let grant = match decode_access_grant_body(&body) {
                    Ok(grant) => grant,
                    Err(_) if decode_erased_grant_body(&body).is_ok() => {
                        return Err(erased_grant());
                    }
                    Err(error) => return Err(error),
                };
                if audit_read_holder(id, &grant).is_none() {
                    return Err(id_held_by_another_row());
                }
                Ok(Some(grant))
            }
            LiveEntityRow::Live { entity_type, .. } => Err(Error::InvalidEntityType(entity_type)),
            LiveEntityRow::Absent => Ok(None),
            LiveEntityRow::DeletedShell => Err(id_held_by_another_row()),
        }
    }

    /// Every live holder of the audit_read power as `txn` reads it, at the
    /// vault's clock, in grant id order. A grant row that does not decode is
    /// no holder's and is left out.
    ///
    /// # Errors
    /// The clock or the grant index does not read.
    pub(crate) fn audit_read_holders_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
    ) -> Result<Vec<AuditReadHolderRow>> {
        let now = self.instant_in_txn(txn)?.secs();
        let mut holders = Vec::new();
        for id in EntityStoreRead::port_entity_ids_by_type(
            &self.store,
            txn,
            ENTITY_TYPE_ACCESS_GRANT,
            None,
        )? {
            let id = id?;
            let Some(grant) = self.audit_read_grant_row_in(txn, &id) else {
                continue;
            };
            if grant.effective_status_at(now) == AccessGrantStatus::Active {
                holders.push(AuditReadHolderRow {
                    holder: grant.principal_ref,
                    grant_ref: id,
                    granted_at: grant.created_at,
                    expires_at: grant.expires_at,
                });
            }
        }
        Ok(holders)
    }

    /// The owner's acts on the audit_read power, oldest first: each grant
    /// and revoke his verbs recorded, with the holder its grant names (none
    /// once that principal was erased). `vault.authority.audit` lists them,
    /// so an auditor sees who else audits.
    ///
    /// # Errors
    /// The owner-act index does not read.
    pub(crate) fn audit_read_acts_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
    ) -> Result<Vec<AuditReadActRow>> {
        let mut rows = Vec::new();
        for (sequence, receipt) in access_grant_owner_acts_in_txn(self, txn)? {
            let grant_ref = receipt.act.target;
            let holder = match crate::vault::live_entity_row_in_txn(&self.store, txn, &grant_ref)? {
                LiveEntityRow::Live {
                    entity_type: ENTITY_TYPE_ACCESS_GRANT,
                    body,
                } => match decode_access_grant_body(&body) {
                    Ok(grant) => match audit_read_holder(&grant_ref, &grant) {
                        Some(holder) => Some(holder),
                        // Another grant's act: not the audit_read power's.
                        None => continue,
                    },
                    Err(_)
                        if decode_erased_grant_body(&body).is_ok_and(|terms| {
                            matches!(terms.scope, AccessGrantScope::VaultAudit)
                        }) =>
                    {
                        None
                    }
                    Err(_) => continue,
                },
                _ => continue,
            };
            rows.push(AuditReadActRow {
                sequence,
                owner: receipt.act.owner,
                holder,
                grant_ref,
                change: receipt.change,
                at: receipt.at,
            });
        }
        Ok(rows)
    }

    /// The audit_read grant at `id`, any status, when the live row there is
    /// one; `None` for any other row or one that does not read.
    fn audit_read_grant_row_in(&self, txn: &heed::RoTxn<'_>, id: &EntityId) -> Option<AccessGrant> {
        let LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_ACCESS_GRANT,
            body,
        } = crate::vault::live_entity_row_in_txn(&self.store, txn, id).ok()?
        else {
            return None;
        };
        let grant = decode_live_access_grant_body(&body).ok().flatten()?;
        audit_read_holder(id, &grant).map(|_| grant)
    }
}

/// What the owner's verbs answer when another row holds a holder's
/// audit_read grant id.
fn id_held_by_another_row() -> Error {
    Error::Record(RecordError::AccessGrantAlreadyExists)
}

/// Refuses a generic delete of an audit_read grant, whoever asks it (Astra
/// review auditread-8435-pr1 T1): the owner's revoke verb alone ends one, and
/// it records his act, which a delete does not. An erased principal's grant
/// stays too, as the history the authority audit lists. Every other row
/// passes. The record delete guard, its headerless leg, the batch delete arm
/// and a replayed peer tombstone's protection gate all ask it.
///
/// It reads the stored row, whatever its deletion state (Astra delta D4): a
/// row marked stale keeps its whole body, so it is still the grant. Only a
/// row whose body is gone (a shell) passes.
///
/// # Errors
/// The row at `id` is an audit_read grant, live or erased; or it does not
/// read.
pub(crate) fn reject_audit_read_grant_delete_in_txn(
    store: &impl crate::store::ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    if stored_audit_read_grant_in_txn(store, txn, id)? {
        return Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(
            AUDIT_READ_DELETE_REFUSAL,
        )));
    }
    Ok(())
}

/// Whether `error` is the refusal [`reject_audit_read_grant_delete_in_txn`]
/// answers: a removal of an audit_read grant that is not the owner's revoke.
/// The sync receiver quarantines a peer's tombstone it refuses.
#[cfg(feature = "sync")]
pub(crate) fn is_audit_read_delete_refusal(error: &Error) -> bool {
    matches!(
        error,
        Error::Gate(GateError::ConsentOwnerNotAuthenticated(
            AUDIT_READ_DELETE_REFUSAL
        ))
    )
}

/// Whether the row stored at `id` is an audit_read grant, live or erased,
/// whatever its deletion state: its body still decodes as one.
///
/// # Errors
/// The row does not read.
pub(crate) fn stored_audit_read_grant_in_txn(
    store: &impl crate::store::ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    Ok(store
        .port_entity_record(txn, id)?
        .is_some_and(|row| is_audit_read_grant_row(row.entity_type, &row.body)))
}

/// Whether a row of type `entity_type` holding `body` is an audit_read grant,
/// live or erased. A shell's empty body is none.
pub(crate) fn is_audit_read_grant_row(entity_type: u8, body: &[u8]) -> bool {
    entity_type == ENTITY_TYPE_ACCESS_GRANT
        && match decode_access_grant_body(body) {
            Ok(grant) => matches!(grant.scope, AccessGrantScope::VaultAudit),
            Err(_) => decode_erased_grant_body(body)
                .is_ok_and(|terms| matches!(terms.scope, AccessGrantScope::VaultAudit)),
        }
}

/// The id of `holder`'s audit_read grant.
pub(crate) fn audit_read_grant_id(holder: EntityId) -> Result<EntityId> {
    EntityId::derive(AUDIT_READ_GRANT_DOMAIN, &[holder.as_bytes().as_slice()])
}

/// The holder `grant`, stored at `id`, names when it is an audit_read grant
/// at the id its holder derives.
pub(crate) fn audit_read_holder(id: &EntityId, grant: &AccessGrant) -> Option<EntityId> {
    (matches!(grant.scope, AccessGrantScope::VaultAudit)
        && grant.capability == AccessGrantCapability::AuditRead
        && audit_read_grant_id(grant.principal_ref).is_ok_and(|derived| derived == *id))
    .then_some(grant.principal_ref)
}

/// `holder`'s audit_read grant, active from `granted_at`.
fn audit_read_grant(holder: EntityId, granted_at: u64, expires_at: Option<u64>) -> AccessGrant {
    AccessGrant {
        authority_scope: crate::federation::scope_codec::read_preset(),
        principal_ref: holder,
        scope: AccessGrantScope::VaultAudit,
        capability: AccessGrantCapability::AuditRead,
        status: AccessGrantStatus::Active,
        created_at: granted_at,
        revoked_at: None,
        expires_at,
        companion_bounds: None,
    }
}
