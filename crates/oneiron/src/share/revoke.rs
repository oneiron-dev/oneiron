//! Stopping a share (OF-491, FIX 1610). The owner's or issuer's revoke
//! always lands; a revoke that may not land answers one typed
//! [`crate::error::ErrorKind::AuthorityRefused`] whether the named share is
//! missing or the revoker may not stop it, so a refused revoke never proves a
//! share exists.

use crate::Vault;
use crate::access_grant::{AccessGrantStatus, encode_access_grant_body};
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, RecordError, Result};
use crate::write_envelope::WriteActor;

use super::{ADMISSIONS, Share, read_admitted_share_in_txn, verify_share_actor};

/// The one reason every refused revoke names, a missing share included.
const SHARE_REVOKE_REFUSED: &str = "share revocation requires issuer or owner";

fn revoke_refused() -> Error {
    Error::Record(RecordError::AuthorityRefused(SHARE_REVOKE_REFUSED))
}

impl Vault {
    /// Revokes the same grant immediately. Only the authenticated original issuer
    /// or a live authority-log owner may stop it. No new consent is requested.
    /// A missing share, a revoker with no actor entity and a revoker who is
    /// neither issuer nor owner all answer the same typed `AuthorityRefused`.
    pub fn revoke_share(
        &self,
        share_id: &EntityId,
        actor: &WriteActor,
        revoked_at: u64,
    ) -> Result<Share> {
        let mut txn = self.store.env.write_txn()?;
        let (mut share, mut admission) =
            read_admitted_share_in_txn(&self.store, &txn, share_id)?.ok_or_else(revoke_refused)?;
        verify_share_actor(&self.store, &txn, actor).map_err(|error| match error {
            Error::EntityNotFound => revoke_refused(),
            error => error,
        })?;
        if Some(*actor) != admission.issuer {
            let fold = self.authority_fold_readonly_in_txn(&txn)?;
            if actor.actor_class() != EdgeActorClass::Human
                || fold.vault_root_is_conflicted()
                || !crate::authority::actor_binding_is_active(&fold, &actor.entity_ref(), "human")
            {
                return Err(revoke_refused());
            }
        }
        if share.status == AccessGrantStatus::Revoked {
            return Ok(share);
        }
        let revoked = share.grant().revoked(revoked_at)?;
        self.apply_access_grant_body(
            &mut txn,
            share_id,
            revoked_at,
            encode_access_grant_body(&revoked)?,
        )?;
        admission.revoked_at = Some(revoked_at);
        admission.revoker = Some(*actor);
        ADMISSIONS.put(&self.store, &mut txn, share_id, &admission.encode())?;
        txn.commit()?;
        share.status = AccessGrantStatus::Revoked;
        share.revoked_at = Some(revoked_at);
        Ok(share)
    }
}
