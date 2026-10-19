//! Recording one owner work request in the act's own transaction, and the
//! one rule that names its executor; and recording the owner's cancel of a
//! root request (FIX 4739).

use std::collections::BTreeSet;

use ed25519_dalek::SigningKey;

use super::{OWNER_WORK_NO_EXECUTOR, OwnerWorkReceipt, OwnerWorkUnassigned};
use crate::authority::{
    ActSurface, AuthorityEntryHash, AuthorityFold, AuthorityKey, AuthorityOp, MAX_PARENTS,
    OwnerAct, OwnerActKind, OwnerWorkBody, OwnerWorkCancel, OwnerWorkRequest, WorldKeyMode,
    WorldPrivacyWorkBasis, WrapRecipient, authority_entry_hash, invalid_authority, next_sequence,
    owner_act_signer_admits, sign_side_entry, stored_authority_row,
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
         work request or cancel; nothing was written"
            .to_owned(),
    )
}

/// The PERSON key work after a settings edit binds the world's key to is no
/// live owner of the vault. Nothing was written.
const NO_KEY_OWNER: &str = "the person this world's key binds is no live owner of the vault; \
                            nothing was written";

/// The request or cancel would name more rows than one authority entry may:
/// the log's encoding bound, never a possession test. Nothing was written.
fn parent_bound(named: usize) -> Error {
    Error::InvalidConfig(format!(
        "this owner work entry would name {named} parent rows, more than the {MAX_PARENTS} one \
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
        let act = OwnerAct::by_owner(actor, work.kind().act(), target, surface, seen);
        self.sign_owner_work_in_txn(txn, act, work, None)
    }

    /// Records the key work the world settings edit signed as entry `edit`
    /// left a holder, in the edit's own write transaction (FIX 4704): Ensure
    /// work for the world's revision `after`, right after the edit, binding
    /// the key to `key_owner`, a live vault owner. The request carries the
    /// edit's own act exactly as its stored entry signed it, whoever's it is
    /// (a holder who owns no vault, or an agent within its Grant): no proof,
    /// and no act made for someone who did not act. The edit is in its
    /// causal past: the main-log heads it names carry it (FIX 4987). The fold
    /// judges its basis (CALLS "FIX 4704 derived key work authority"); a
    /// request it did not admit refuses the transaction.
    pub(crate) fn record_world_privacy_work_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        edit: AuthorityEntryHash,
        key_owner: EntityId,
        after: [u8; 32],
    ) -> Result<OwnerWorkReceipt> {
        let source = stored_authority_row(&self.store, txn, &edit)?;
        let Some(AuthorityOp::WorldPrivacy(source)) = source.map(|entry| entry.op) else {
            return Err(Error::InvariantViolation(
                "world privacy key work names no stored settings edit",
            ));
        };
        if !crate::policy_model::is_live_vault_owner_in_txn(self, txn, &key_owner)? {
            return Err(Error::InvalidConfig(NO_KEY_OWNER.to_owned()));
        }
        let basis = WorldPrivacyWorkBasis {
            edit,
            after,
            key_owner,
        };
        let work = OwnerWorkBody::WorldKey {
            mode: WorldKeyMode::Ensure,
        };
        self.sign_owner_work_in_txn(txn, source.act, work, Some(basis))
    }

    /// Signs and lands one request for `act`'s work in `txn`, carried by
    /// this install, then reads it back from the fold. `act` is exactly the
    /// act the request carries; its target is the work's.
    fn sign_owner_work_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        act: OwnerAct,
        work: OwnerWorkBody,
        privacy_basis: Option<WorldPrivacyWorkBasis>,
    ) -> Result<OwnerWorkReceipt> {
        let target = act.target;
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
        // The main-log heads alone (FIX 4987): the settings edit key work
        // follows is a main-log row among them or their ancestors, and the
        // fold judges its basis in the request's parent state
        // (`privacy_key_work_basis_admits`).
        let parents = fold.owner_work_parents();
        let request = OwnerWorkRequest {
            carrier: machine,
            act,
            executor,
            work,
            privacy_basis,
        };
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

    /// Signs and lands the owner's cancel of the root request signed as
    /// entry `request`, whose target is `target`, in `txn`, carried by this
    /// install for `actor`, the owner PERSON the caller revalidated in this
    /// same transaction (CALLS ROOT_WORK_CANCEL). Ids only: its act names the
    /// target and, as its `seen`, the request. Its parents are the main-log
    /// heads alone, which carry the request (FIX 4987). The fold is the
    /// judge: a cancel it does not take refuses the transaction.
    pub(crate) fn record_owner_work_cancel_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        actor: EntityId,
        surface: ActSurface,
        target: EntityId,
        request: AuthorityEntryHash,
    ) -> Result<AuthorityEntryHash> {
        let fold = self.authority_view_readonly_in_txn(txn)?;
        // Key possession: this install carries the act with its own install
        // key, under a live profile of any role (mesh contract §3).
        let (machine, signing) = self
            .owner_work_carrier_in_txn(txn, &fold)?
            .ok_or_else(no_carrier)?;
        let public_key = signing.verifying_key().to_bytes();
        let seen = OwnerWorkCancel::seen_for(request);
        let act = OwnerAct::by_owner(actor, OwnerActKind::RootRequest, target, surface, seen);
        let parents = fold.owner_work_parents();
        if parents.len() > MAX_PARENTS {
            return Err(parent_bound(parents.len()));
        }
        let cancel = OwnerWorkCancel {
            carrier: machine,
            act,
            request,
        };
        let seq = next_sequence(&fold, &AuthorityKey::Ed25519(public_key))?;
        let now = self.instant_in_txn(txn)?.secs();
        let entry = sign_side_entry(
            &fold,
            &signing,
            seq,
            parents,
            AuthorityOp::OwnerWorkCancel(cancel),
            now,
        )?;
        let hash = authority_entry_hash(&entry)?;
        let at = TimeRange {
            start: now,
            end: now,
        };
        self.put_authority_log_entries_in_txn(txn, &[(entry, at, now)])?;
        let after = self.authority_view_readonly_in_txn(txn)?;
        if !after
            .owner_work_cancels(&request)
            .any(|cancel| cancel == hash)
        {
            return Err(invalid_authority());
        }
        Ok(hash)
    }
}
