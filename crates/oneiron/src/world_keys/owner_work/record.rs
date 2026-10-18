//! Recording one owner work request in the act's own transaction, and the
//! one rule that names its executor.

use std::collections::BTreeSet;

use super::OwnerWorkReceipt;
use crate::authority::{
    ActSurface, AuthorityFold, AuthorityKey, AuthorityOp, MAX_PARENTS, OwnerAct, OwnerWorkBody,
    OwnerWorkKind, OwnerWorkRequest, WrapRecipient, authority_entry_hash, invalid_authority,
    next_sequence, owner_act_signer_admits, sign_side_entry,
};
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result};
use crate::world_keys::recipients;
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
/// `None` when none can (CALLS OWNER_WORK_NO_EXECUTOR). One executor, read
/// from `fold` alone: no election, no expiry and no clock takeover; only a
/// new owner act names another. `recorder` is never named: an install that
/// could do the work does it in the act's own commit.
pub(crate) fn owner_work_executor(
    fold: &AuthorityFold,
    kind: OwnerWorkKind,
    target: EntityId,
    recorder: EntityId,
) -> Option<EntityId> {
    match kind {
        OwnerWorkKind::WorldKey => world_key_executor(fold, target, recorder),
    }
}

/// A world's key work goes to the lowest machine id among its eligible
/// readers that hold a counted wrap of its current key; with none, to the
/// lowest eligible reader, which mints the first key when the world has none
/// it can see.
fn world_key_executor(
    fold: &AuthorityFold,
    world: EntityId,
    recorder: EntityId,
) -> Option<EntityId> {
    let readers: BTreeSet<EntityId> = eligible_readers(fold, world)
        .filter(|id| *id != recorder)
        .collect();
    let holder = fold.current_world_key(world).and_then(|current| {
        current
            .wraps
            .iter()
            .filter(|(_, wraps)| !wraps.is_empty())
            .filter_map(|(to, _)| match to {
                WrapRecipient::Machine(id) => Some(*id),
                WrapRecipient::RecoveryRoot(_) => None,
            })
            .filter(|id| readers.contains(id))
            .min()
    });
    holder.or_else(|| readers.first().copied())
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
        let fold = self.authority_view_readonly_in_txn(txn)?;
        // Key possession: this install carries the act with its own install
        // key, under a live profile of any role (mesh contract §3).
        let machine = crate::identity::read_machine_id_in_txn(self, txn)?.ok_or_else(no_carrier)?;
        let signing =
            crate::identity::read_machine_signing_key_in_txn(self, txn)?.ok_or_else(no_carrier)?;
        let public_key = signing.verifying_key().to_bytes();
        if !owner_act_signer_admits(fold.machine(machine), &fold.roster, &public_key) {
            return Err(no_carrier());
        }
        let kind = work.kind();
        let Some(executor) = owner_work_executor(&fold, kind, target, machine) else {
            return Ok(OwnerWorkReceipt::unassigned(kind, target));
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
