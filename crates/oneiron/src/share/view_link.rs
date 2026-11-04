//! One live brief share, bound to the recipient who redeems its view link.

use super::{Share, read_share_in_txn, verify_share_actor};
use crate::access_grant::AccessGrantStatus;
use crate::edge::EdgeActorClass;
use crate::error::{Error, RecordError, Result};
use crate::write_envelope::WriteActor;
use crate::{EntityId, Vault};

pub(crate) fn live_share_for_holder_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    share_id: &EntityId,
    holder: &EntityId,
    now: u64,
) -> Result<Option<Share>> {
    let Some((share, _)) = read_share_in_txn(&vault.store, txn, share_id)? else {
        return Ok(None);
    };
    if share.recipient_ref != *holder
        || share.grant().effective_status_at(now) != AccessGrantStatus::Active
        || !crate::vault::live_entity_row_in_txn(&vault.store, txn, share_id)?.is_live()
    {
        return Ok(None);
    }
    Ok(Some(share))
}

pub(crate) fn authorize_share_link_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    share_id: &EntityId,
    actor: &WriteActor,
    now: u64,
) -> Result<Share> {
    let refused = || {
        Error::Record(RecordError::AuthorityRefused(
            "share link requires issuer or owner",
        ))
    };
    let (share, admission) = read_share_in_txn(&vault.store, txn, share_id)?.ok_or_else(refused)?;
    verify_share_actor(&vault.store, txn, actor).map_err(|error| match error {
        Error::EntityNotFound => refused(),
        error => error,
    })?;
    if Some(*actor) != admission.issuer {
        let fold = vault.authority_fold_readonly_in_txn(txn)?;
        if actor.actor_class() != EdgeActorClass::Human
            || fold.vault_root_is_conflicted()
            || !crate::authority::actor_binding_is_active(&fold, &actor.entity_ref(), "human")
        {
            return Err(refused());
        }
    }
    live_share_for_holder_in_txn(vault, txn, share_id, &share.recipient_ref, now)?
        .ok_or_else(refused)
}
