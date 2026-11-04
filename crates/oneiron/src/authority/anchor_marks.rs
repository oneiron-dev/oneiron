//! An owner anchor's writes (world privacy P6b, contract §4 and E2(b)): its
//! root's record, and its `Owned(Yours)` mark of a machine in its own chain.
//! The anchor signs each alone; no roster key and no install key vouches.
//! A frontier wider than one of them names is joined first by the anchor
//! itself (FIX 8498, Engine 09:31), for its own rows alone, and so are its
//! own side heads when they alone fill one (FIX 11868).

use std::collections::BTreeSet;

use ed25519_dalek::SigningKey;

use super::*;
use crate::error::Result;
use crate::{EntityId, TimeRange, Vault};

impl Vault {
    /// Puts one entry an anchor signed, in the caller's write transaction.
    pub(crate) fn put_anchor_entry_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        entry: AuthorityLogEntry,
    ) -> Result<AuthorityEntryHash> {
        let hash = authority_entry_hash(&entry)?;
        let now = self.instant_in_txn(txn)?.secs();
        let at = TimeRange {
            start: now,
            end: now,
        };
        self.put_authority_log_entries_in_txn(txn, &[(entry, at, now)])?;
        Ok(hash)
    }

    /// Joins `fold`'s main-log heads in `txn` when the next row `anchor`
    /// signs ([`anchor_signed_entry`]) would name more of them than one entry
    /// may beside the anchor's own heads, each join signed by `anchor` itself
    /// (FIX 8498, Engine 09:31): the third join signer, for the anchor's own
    /// rows alone, which the fold admits only while it records `anchor` for a
    /// stored root. Its own heads that leave no room for one main head are
    /// joined first, among its own rows (FIX 11868). The fold read back, else
    /// `None`: today's path.
    pub(crate) fn join_anchor_frontier_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        fold: &AuthorityFold,
        anchor: &SigningKey,
    ) -> Result<Option<AuthorityView>> {
        let key = anchor.verifying_key().to_bytes();
        let own_heads = fold.anchor_heads.get(&key).cloned().unwrap_or_default();
        let sided = self.join_scoped_heads_in_txn(
            txn,
            fold,
            (&own_heads, FrontierJoinScope::AnchorSide),
            FrontierSigner::Anchor(anchor),
            MAX_PARENTS - 1,
        )?;
        let fold = sided.as_deref().unwrap_or(fold);
        let own = fold.anchor_heads.get(&key).map_or(0, BTreeSet::len);
        let joined = self.prepare_authority_frontier_in_txn(
            txn,
            fold,
            FrontierSigner::Anchor(anchor),
            MAX_PARENTS.saturating_sub(own),
        )?;
        Ok(joined.or(sided))
    }

    /// The root `record` describes, signed by its own `anchor` on this
    /// vault's main-log heads and put in the caller's write transaction. A
    /// root its anchor already published here joins a wide frontier first; a
    /// first root names the heads that fit ([`anchor_signed_entry`]).
    pub(crate) fn publish_owner_root_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        anchor: &SigningKey,
        record: OwnerRootRecord,
    ) -> Result<AuthorityEntryHash> {
        let fold = self.authority_view_readonly_in_txn(txn)?;
        let fold = self
            .join_anchor_frontier_in_txn(txn, &fold, anchor)?
            .unwrap_or(fold);
        let now = self.instant_in_txn(txn)?.secs();
        let entry = anchor_signed_entry(&fold, anchor, AuthorityOp::OwnerRoot(record), now)?;
        self.put_anchor_entry_in_txn(txn, entry)
    }

    /// `anchor` marks `request`'s machine `Owned(Yours)` with the request's
    /// keys and proof, as the next revision of its own chain of that machine,
    /// in the caller's write transaction. The MACHINE row is created when
    /// absent. Returns the mark's entry; the caller judges the refold.
    pub(crate) fn append_anchor_mark_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        anchor: &SigningKey,
        owner: EntityId,
        request: &MachineEnrolmentRequest,
    ) -> Result<AuthorityEntryHash> {
        let fold = self.authority_view_readonly_in_txn(txn)?;
        if fold.vault_id != Some(request.vault_id) {
            return Err(invalid_authority());
        }
        self.ensure_machine_row_in_txn(txn, request.machine)?;
        let anchor_key = anchor.verifying_key().to_bytes();
        let revision = match fold
            .machine(request.machine)
            .and_then(|folded| folded.anchored.get(&anchor_key))
        {
            Some(head) => head
                .profile
                .revision
                .checked_add(1)
                .ok_or_else(invalid_authority)?,
            None => 1,
        };
        let profile = MachineProfile {
            machine: request.machine,
            owner,
            machine_key: request.machine_key,
            device_class: request.device_class,
            encryption_key: request.encryption_key.clone(),
            role: MachineRole::Owned(MachineOwnership::Yours),
            revision,
            machine_proof: request.machine_proof,
            seen_world_edits: super::act_standing::acknowledged_by_in_txn(
                &self.store,
                txn,
                &fold,
                request.machine,
            )?,
            // An anchor's mark is its own proof arm (C4): no install carries
            // it, and no owner act rides it. A later owner answer that saw
            // it supersedes it, and it supersedes every answer its parents
            // held, each replica reading that from the parents (FIX 4610).
            carrier: None,
            act: None,
        };
        profile.validate()?;
        // FIX 8498: the mark's basis is the one read above; a join moves none.
        let fold = self
            .join_anchor_frontier_in_txn(txn, &fold, anchor)?
            .unwrap_or(fold);
        let now = self.instant_in_txn(txn)?.secs();
        let entry = anchor_signed_entry(&fold, anchor, AuthorityOp::MachineProfile(profile), now)?;
        self.put_anchor_entry_in_txn(txn, entry)
    }
}

/// The postcondition of every anchoring (Wonder R1-F6, R1b-F7): `mark` heads
/// `anchor_key`'s chain of `machine`, and under that anchor that chain is the
/// machine's trusted identity with `request`'s keys. A roster chain that
/// already makes the machine mine does not satisfy it. An owner answer the
/// mark's parents held that says otherwise no longer stands against it: the
/// mark saw it (FIX 4610), so no re-answer follows an anchoring. One it never
/// saw still conflicts, and another key or a removal still refuses.
pub(crate) fn anchor_mark_stands(
    fold: &AuthorityFold,
    anchor_key: [u8; 32],
    mark: AuthorityEntryHash,
    request: &MachineEnrolmentRequest,
) -> bool {
    let Some(folded) = fold.machine(request.machine) else {
        return false;
    };
    let admitter = MachineAdmitter::Anchor(anchor_key);
    folded
        .anchored
        .get(&anchor_key)
        .is_some_and(|head| head.entry == mark)
        && folded.trusted_under(&admitter).is_some_and(|trusted| {
            trusted.chain == admitter
                && trusted.profile.machine_key == request.machine_key
                && trusted.profile.encryption_key == request.encryption_key
        })
}
