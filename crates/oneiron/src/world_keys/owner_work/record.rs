//! Recording one owner work request in the act's own transaction, and the
//! one rule that names its executor.

use std::collections::BTreeSet;

use ed25519_dalek::SigningKey;

use super::{OWNER_WORK_NO_EXECUTOR, OwnerWorkReceipt, OwnerWorkUnassigned};
use crate::authority::{
    ActSurface, AuthorityFold, AuthorityKey, AuthorityOp, MAX_PARENTS, OwnerAct, OwnerWorkBody,
    OwnerWorkRequest, WrapRecipient, authority_entry_hash, invalid_authority, next_sequence,
    owner_act_signer_admits, sign_side_entry,
};
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result};
use crate::secret_custody::custody_work_executor;
use crate::world_keys::bundle::bundle_publish_executor;
use crate::world_keys::recipients;
use crate::world_keys::root_work::root_work_executor;
use crate::{EntityId, TimeRange, Vault};

/// This install cannot carry the owner's act: it has no machine identity or
/// install key, or the roster holds no live profile of it under that key.
/// Key possession and integrity: an act is signed by the install that
/// carries it, never by a roster key (FIX 2222). Nothing was written.
fn no_carrier() -> Error {
    Error::InvalidConfig(
        "this install has no live machine profile in the vault's roster to carry the owner's \
         work request; nothing was written"
            .to_owned(),
    )
}

/// The request would name more rows than one authority entry may: the log's
/// encoding bound, never a possession test. Nothing was written.
fn parent_bound(named: usize) -> Error {
    Error::InvalidConfig(format!(
        "this owner work request would name {named} parent rows, more than the {MAX_PARENTS} one \
         authority entry names; nothing was written"
    ))
}

/// The install pinned to do an act's work (CALLS OWNER_WORK_EXECUTOR), or
/// why none can (CALLS OWNER_WORK_NO_EXECUTOR). One executor, read from
/// `fold` alone: no election, no expiry and no clock takeover; only a new
/// owner act names another. For key work `recorder` is not named while
/// another can do the work: an install that could do it all does it in the
/// act's own commit. It names itself only when it alone holds the key the
/// work needs (FIX 4634). A root change names its target exactly (CALLS
/// ROOT_WORK_EXECUTOR); a bundle publication the lowest install that holds
/// every key the bundle seals (CALLS BUNDLE_PUBLISH_EXECUTOR); a custody
/// change its explicit holder, and a revoke `recorder` (CALLS
/// CUSTODY_EXECUTOR).
pub(crate) fn owner_work_executor(
    fold: &AuthorityFold,
    work: &OwnerWorkBody,
    target: EntityId,
    recorder: EntityId,
) -> std::result::Result<EntityId, OwnerWorkUnassigned> {
    match work {
        OwnerWorkBody::WorldKey { .. } => {
            world_key_executor(fold, target, recorder).ok_or(OWNER_WORK_NO_EXECUTOR)
        }
        OwnerWorkBody::Root { .. } => root_work_executor(fold, target, recorder),
        OwnerWorkBody::PublishBundle { .. } => bundle_publish_executor(fold, target),
        OwnerWorkBody::Custody { change, holder, .. } => {
            custody_work_executor(fold, *change, *holder, recorder)
        }
    }
}

/// A world's key work goes to the lowest machine id among its eligible
/// readers other than `recorder` that hold a counted wrap of its current
/// key. When `recorder` alone holds one, it names itself: a first key it
/// minted on a bridge record (Docs Q06), or a frontier too wide for its
/// wraps in the act's commit, leaves no other reader able to open the key,
/// so its own pickup wraps them once one record names the world's frontier
/// (FIX 4634). With no holder at all, the work goes to the lowest eligible
/// reader other than `recorder`, which mints the first key when the world
/// has none it can see.
fn world_key_executor(
    fold: &AuthorityFold,
    world: EntityId,
    recorder: EntityId,
) -> Option<EntityId> {
    let readers: BTreeSet<EntityId> = eligible_readers(fold, world).collect();
    let holders: BTreeSet<EntityId> = fold
        .current_world_key(world)
        .into_iter()
        .flat_map(|current| current.wraps.iter())
        .filter(|(_, wraps)| !wraps.is_empty())
        .filter_map(|(to, _)| match to {
            WrapRecipient::Machine(id) => Some(*id),
            WrapRecipient::RecoveryRoot(_) => None,
        })
        .filter(|id| readers.contains(id))
        .collect();
    let others = |ids: &BTreeSet<EntityId>| ids.iter().copied().find(|id| *id != recorder);
    others(&holders)
        .or_else(|| holders.contains(&recorder).then_some(recorder))
        .or_else(|| others(&readers))
}

/// The machines the world's settings let read it, each with an importable
/// encryption key under its trusted identity ([`recipients`]) and a proof
/// key that stands here: who may do its key work.
pub(crate) fn eligible_readers(
    fold: &AuthorityFold,
    world: EntityId,
) -> impl Iterator<Item = EntityId> + '_ {
    recipients(fold, world, None)
        .into_iter()
        .filter_map(|(to, _)| match to {
            WrapRecipient::Machine(id) => Some(id),
            WrapRecipient::RecoveryRoot(_) => None,
        })
        .filter(|id| fold.machine_proof_key(*id).is_some())
}

impl Vault {
    /// This install as the carrier of an owner act in `txn`: its machine id
    /// and install key, when the roster holds a live profile of it under
    /// that key (mesh contract §3); `None` otherwise.
    pub(crate) fn owner_work_carrier_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        fold: &AuthorityFold,
    ) -> Result<Option<(EntityId, SigningKey)>> {
        let Some(machine) = crate::identity::read_machine_id_in_txn(self, txn)? else {
            return Ok(None);
        };
        let Some(signing) = crate::identity::read_machine_signing_key_in_txn(self, txn)? else {
            return Ok(None);
        };
        let public_key = signing.verifying_key().to_bytes();
        Ok(
            owner_act_signer_admits(fold.machine(machine), &fold.roster, &public_key)
                .then_some((machine, signing)),
        )
    }

    /// Records the work the owner's act needs, in the act's own write
    /// transaction, signed by this install as the carrier of the act. The
    /// owner is revalidated as a live vault owner here. `surface` is audit
    /// only; `seen` is the target's revision right after the act, which the
    /// work is for. With no install to name, nothing is written and the
    /// receipt says why; the act stands. The fold is the judge: a request it
    /// did not admit refuses the transaction.
    pub(crate) fn record_owner_work_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        owner: &AuthenticatedOwner,
        surface: ActSurface,
        target: EntityId,
        seen: [u8; 32],
        work: OwnerWorkBody,
    ) -> Result<OwnerWorkReceipt> {
        let actor = owner.revalidate_as_vault_owner_in_txn(self, txn)?;
        self.record_owner_work_for_in_txn(txn, actor, surface, target, seen, work)
    }

    /// [`Self::record_owner_work_in_txn`] for `actor`, the owner PERSON the
    /// act is by, whom the caller revalidated, or checked a live vault owner,
    /// in this same transaction.
    pub(crate) fn record_owner_work_for_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        actor: EntityId,
        surface: ActSurface,
        target: EntityId,
        seen: [u8; 32],
        work: OwnerWorkBody,
    ) -> Result<OwnerWorkReceipt> {
        let fold = self.authority_view_readonly_in_txn(txn)?;
        // Key possession: this install carries the act with its own install
        // key, under a live profile of any role (mesh contract §3).
        let (machine, signing) = self
            .owner_work_carrier_in_txn(txn, &fold)?
            .ok_or_else(no_carrier)?;
        let public_key = signing.verifying_key().to_bytes();
        let kind = work.kind();
        let executor = match owner_work_executor(&fold, &work, target, machine) {
            Ok(executor) => executor,
            Err(why) => return Ok(OwnerWorkReceipt::unassigned(kind, target, why)),
        };
        let request = OwnerWorkRequest {
            carrier: machine,
            act: OwnerAct::by_owner(actor, kind.act(), target, surface, seen),
            executor,
            work,
        };
        let parents = fold.owner_work_request_parents(machine, executor, kind, target);
        if parents.len() > MAX_PARENTS {
            return Err(parent_bound(parents.len()));
        }
        let seq = next_sequence(&fold, &AuthorityKey::Ed25519(public_key))?;
        let now = self.instant_in_txn(txn)?.secs();
        let entry = sign_side_entry(
            &fold,
            &signing,
            seq,
            parents,
            AuthorityOp::OwnerWorkRequest(request),
            now,
        )?;
        let hash = authority_entry_hash(&entry)?;
        let at = TimeRange {
            start: now,
            end: now,
        };
        self.put_authority_log_entries_in_txn(txn, &[(entry, at, now)])?;
        let after = self.authority_view_readonly_in_txn(txn)?;
        OwnerWorkReceipt::of(&after, hash).ok_or_else(invalid_authority)
    }
}
