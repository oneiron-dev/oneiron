//! The owner's list of owner key changes (the owner's ruling AUTH-5, pass 27
//! section 4.4): every enrolment and every removal of an enrolled owner key
//! that this vault's log holds and its fold counts, newest first.
//!
//! This list is the notice of a key change. It writes no row of its own:
//! each change is its authority entry, every owner device holds the log, and
//! so each device reads the same list and shows what it has not shown yet
//! ("[device] was removed. Not you?"). An install-local notification row
//! would reach only the install that wrote it.
//!
//! One removal ends its key although the fold counts no entry for it: two
//! removals that cross. When key A removes key B on one branch and B removes
//! A on a branch that never saw it, each revocation retires the other's
//! signer, so the fold refuses both entries and both keys end
//! (`retired_signers`). The list shows such an entry as
//! [`OwnerKeyChangeKind::RemovedByEndedKey`], so the owner still reads that
//! the key ended and which key signed its removal.

use std::collections::{BTreeMap, BTreeSet};

use super::*;
use crate::consent::AuthenticatedOwner;
use crate::error::Result;
use crate::{EntityId, Vault};

/// What happened to an enrolled owner key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerKeyChangeKind {
    /// The key was enrolled.
    Enrolled,
    /// The key was removed: a counted `RevokeDevice` of it.
    Removed,
    /// The key ended, and no counted removal names it: this `RevokeDevice`
    /// of it is one the fold refused only because its own signer's key ended
    /// too, on a branch that never saw this entry (two removals that cross
    /// end both keys and count neither entry).
    RemovedByEndedKey,
}

/// One change of an enrolled owner key, as its authority entry says it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerKeyChange {
    /// The change's authority entry.
    pub entry: AuthorityEntryHash,
    /// What happened.
    pub change: OwnerKeyChangeKind,
    /// The key.
    pub public_key: [u8; 32],
    /// The machine the key's enrolment names.
    pub machine: EntityId,
    /// What the key is, as its enrolment says.
    pub kind: EnrolledOwnerKeyKind,
    /// The key that signed the entry: an enrolment's predecessor, a
    /// removal's proof.
    pub signed_by: AuthorityKey,
    /// When it was signed, advisory unix seconds.
    pub at: u64,
}

impl Vault {
    /// Every change of an enrolled owner key, newest first: each counted
    /// enrolment and each counted removal of a key an enrolment names, from
    /// the rows this vault keeps (stored, or carried by an adopted
    /// checkpoint image). A key enrolled on two branches lists its smallest
    /// enrolment entry, as [`Self::enrolled_owner_keys`] does; a key that
    /// two counted entries removed lists both removals. A key that ended
    /// with no counted removal lists each removal of it that the fold
    /// refused for its signer alone
    /// ([`OwnerKeyChangeKind::RemovedByEndedKey`]). Empty before any
    /// enrolment.
    ///
    /// # Errors
    /// A refusal when the proof is no longer the vault's live owner; the
    /// log's read errors.
    pub fn owner_key_changes(&self, owner: &AuthenticatedOwner) -> Result<Vec<OwnerKeyChange>> {
        let txn = self.store.env.read_txn()?;
        owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        let enrolled: BTreeMap<[u8; 32], EnrolledOwnerKey> = self
            .enrolled_owner_keys_in_txn(&txn)?
            .into_iter()
            .map(|key| (key.public_key, key))
            .collect();
        let mut changes = Vec::new();
        let mut stored = BTreeSet::new();
        for (_, body) in super::readonly_fold::authority_log_rows_in_txn(&self.store, &txn)? {
            let entry = decode_authority_log_entry_body(&body)?;
            let hash = authority_entry_hash(&entry)?;
            stored.insert(hash);
            changes.extend(owner_key_change(&fold, &enrolled, hash, &entry));
        }
        if let Some(evidence) = super::adopted_evidence::adopted_evidence_in_txn(&self.store, &txn)?
        {
            for (hash, entry) in evidence.carried_past(&stored) {
                changes.extend(owner_key_change(&fold, &enrolled, *hash, entry));
            }
        }
        // A counted removal of a key is the whole account of its end.
        let removed: BTreeSet<[u8; 32]> = changes
            .iter()
            .filter(|change| change.change == OwnerKeyChangeKind::Removed)
            .map(|change| change.public_key)
            .collect();
        changes.retain(|change| {
            change.change != OwnerKeyChangeKind::RemovedByEndedKey
                || !removed.contains(&change.public_key)
        });
        changes.sort_by(|a, b| b.at.cmp(&a.at).then_with(|| a.entry.cmp(&b.entry)));
        Ok(changes)
    }
}

/// The owner key change `entry`, at `hash`, is on `fold`: a counted
/// enrolment that stands for its key among `enrolled`, a counted
/// `RevokeDevice` of a key an enrolment names, or a `RevokeDevice` of such a
/// key that ended it uncounted ([`ended_by_a_refused_removal`]). None for any
/// other entry.
fn owner_key_change(
    fold: &AuthorityFold,
    enrolled: &BTreeMap<[u8; 32], EnrolledOwnerKey>,
    hash: AuthorityEntryHash,
    entry: &AuthorityLogEntry,
) -> Option<OwnerKeyChange> {
    let counted = fold.valid_entries.contains(&hash);
    let (change, key) = match &entry.op {
        AuthorityOp::OwnerKeyEnroll(enroll) if counted => {
            let key = enrolled.get(enroll.public_key()?)?;
            (key.entry == hash).then_some((OwnerKeyChangeKind::Enrolled, key))?
        }
        AuthorityOp::RevokeDevice {
            revoked_key: AuthorityKey::Ed25519(revoked),
        } => {
            let key = enrolled.get(revoked)?;
            if counted {
                (OwnerKeyChangeKind::Removed, key)
            } else if ended_by_a_refused_removal(fold, hash, key) {
                (OwnerKeyChangeKind::RemovedByEndedKey, key)
            } else {
                return None;
            }
        }
        _ => return None,
    };
    Some(OwnerKeyChange {
        entry: hash,
        change,
        public_key: key.public_key,
        machine: key.machine,
        kind: key.kind,
        signed_by: entry.signer.public_key.clone(),
        at: entry.ts,
    })
}

/// Whether the uncounted `RevokeDevice` of `key` at `hash` is a removal that
/// ended it all the same: the key is retired, and the fold refused the entry
/// for its signer alone (`RetiredSigner`), so the entry counted on its own
/// branch and only a removal of its signer, on a branch that never saw it,
/// refused it. A refused entry of any other kind (a bad signature, a signer
/// the roster never held) is no removal and lists nothing.
fn ended_by_a_refused_removal(
    fold: &AuthorityFold,
    hash: AuthorityEntryHash,
    key: &EnrolledOwnerKey,
) -> bool {
    !key.live
        && fold
            .retired_keys
            .contains(&AuthorityKey::Ed25519(key.public_key))
        && fold
            .issues
            .contains(&AuthorityFoldIssue::RetiredSigner(hash))
}
