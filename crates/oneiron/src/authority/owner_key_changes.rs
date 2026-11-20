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
//! the key ended and which key signed its removal. Only a removal that a key
//! of the owner's signed lists so: a managed host's root may sign a second
//! revoke of a key that had already ended, and that entry is no act of the
//! owner's. And only one that no settled fence from a branch it never saw
//! holds a signer of: a removal whose signer a sibling handoff, appointment
//! or counted revocation ended yields to it and ends nothing, so when its
//! key ended all the same (a sibling `ReRoot` that fenced both keys, say),
//! the removal is not why, and it lists nothing.

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
    /// too, by a removal on a branch that never saw this entry (two removals
    /// that cross end both keys and count neither entry).
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
    /// with no counted removal lists each removal of it that a key of the
    /// owner's signed and the fold refused for its signer alone, where only
    /// removals that cross ended that signer
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
        let hosted = self.is_hosted();
        let enrolled: BTreeMap<[u8; 32], EnrolledOwnerKey> = self
            .enrolled_owner_keys_in_txn(&txn)?
            .into_iter()
            .map(|key| (key.public_key, key))
            .collect();
        let mut rows = Vec::new();
        let mut stored = BTreeSet::new();
        for (_, body) in super::readonly_fold::authority_log_rows_in_txn(&self.store, &txn)? {
            let entry = decode_authority_log_entry_body(&body)?;
            let hash = authority_entry_hash(&entry)?;
            stored.insert(hash);
            rows.push((hash, entry));
        }
        if let Some(evidence) = super::adopted_evidence::adopted_evidence_in_txn(&self.store, &txn)?
        {
            rows.extend(
                evidence
                    .carried_past(&stored)
                    .map(|(hash, entry)| (*hash, entry.clone())),
            );
        }
        let fences = SignerFences::of(&fold, &rows);
        let mut changes: Vec<OwnerKeyChange> = rows
            .iter()
            .filter_map(|(hash, entry)| {
                owner_key_change(&fold, hosted, &enrolled, &fences, *hash, entry)
            })
            .collect();
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

/// The settled fences that can make a refused removal yield, and the
/// authority DAG of the rows this vault keeps, to place them against it.
struct SignerFences<'a> {
    /// Each key's counted `RevokeDevice` rows.
    revocations: BTreeMap<&'a AuthorityKey, Vec<AuthorityEntryHash>>,
    /// The closed handoffs, settled or in conflict, and the counted root
    /// appointments.
    handoffs: Vec<AuthorityEntryHash>,
    /// Each kept row's parents.
    parents: BTreeMap<AuthorityEntryHash, &'a [AuthorityEntryHash]>,
}

impl<'a> SignerFences<'a> {
    /// The fences among `rows` on `fold`.
    fn of(fold: &AuthorityFold, rows: &'a [(AuthorityEntryHash, AuthorityLogEntry)]) -> Self {
        let mut fences = Self {
            revocations: BTreeMap::new(),
            handoffs: fold.closed_handoffs.iter().copied().collect(),
            parents: BTreeMap::new(),
        };
        for (hash, entry) in rows {
            fences.parents.insert(*hash, &entry.parent_hashes);
            if !fold.valid_entries.contains(hash) {
                continue;
            }
            match &entry.op {
                AuthorityOp::RevokeDevice { revoked_key } => {
                    fences
                        .revocations
                        .entry(revoked_key)
                        .or_default()
                        .push(*hash);
                }
                AuthorityOp::RootAppointment(_) => fences.handoffs.push(*hash),
                _ => {}
            }
        }
        fences
    }

    /// Whether a settled fence on a branch that never saw the refused
    /// removal `entry`, at `hash`, holds a signer of it, so the removal
    /// yielded to it and ended nothing: a counted revocation of the signer,
    /// or a closed handoff or a counted appointment while such a fence holds
    /// the signer. The fold keeps no handoff's keys apart, so a signer some
    /// handoff holds counts as held by each handoff on a sibling branch. A
    /// fence below the removal, or one that saw it (a recovery after two
    /// removals that crossed, say), does not fence it.
    fn fence_a_signer_of(
        &self,
        fold: &AuthorityFold,
        hash: AuthorityEntryHash,
        entry: &AuthorityLogEntry,
    ) -> bool {
        super::retired_signers::entry_signer_keys(entry).any(|key| {
            let revoked = self
                .revocations
                .get(key)
                .is_some_and(|rows| rows.iter().any(|row| self.concurrent(*row, hash)));
            let handed_off = fold.handoff_or_appointment_retired_keys.contains(key)
                && self.handoffs.iter().any(|row| self.concurrent(*row, hash));
            revoked || handed_off
        })
    }

    /// Whether `a` and `b` are on branches that never saw each other.
    fn concurrent(&self, a: AuthorityEntryHash, b: AuthorityEntryHash) -> bool {
        a != b && !self.descends(a, b) && !self.descends(b, a)
    }

    /// Whether `ancestor` is in the ancestry of `row`, as the kept rows name
    /// it.
    fn descends(&self, row: AuthorityEntryHash, ancestor: AuthorityEntryHash) -> bool {
        let mut seen = BTreeSet::new();
        let mut next = vec![row];
        while let Some(current) = next.pop() {
            for parent in self.parents.get(&current).copied().unwrap_or_default() {
                if *parent == ancestor {
                    return true;
                }
                if seen.insert(*parent) {
                    next.push(*parent);
                }
            }
        }
        false
    }
}

/// The owner key change `entry`, at `hash`, is on `fold`: a counted
/// enrolment that stands for its key among `enrolled`, a counted
/// `RevokeDevice` of a key an enrolment names, or a `RevokeDevice` of such a
/// key that ended it uncounted ([`ended_by_a_refused_removal`], and no fence
/// of `fences` made it yield; `hosted` is as
/// [`AuthorityFold::proves_owner_acts`] takes it). None for any other entry.
fn owner_key_change(
    fold: &AuthorityFold,
    hosted: bool,
    enrolled: &BTreeMap<[u8; 32], EnrolledOwnerKey>,
    fences: &SignerFences<'_>,
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
            } else if ended_by_a_refused_removal(fold, hash, key)
                && signed_by_a_key_of_the_owners(fold, hosted, entry)
                && !fences.fence_a_signer_of(fold, hash, entry)
            {
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
/// the roster never held) is no removal and lists nothing. The caller also
/// asks who signed it ([`signed_by_a_key_of_the_owners`]) and whether a
/// settled fence made it yield ([`SignerFences::fence_a_signer_of`]).
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

/// Whether a key of the owner's signed `entry`, as its primary signer or as
/// a cosign: a roster key with `ROLE_OWNER`, live or ended, outside the
/// host's custody when the vault is `hosted`
/// ([`AuthorityFold::proves_owner_acts`], without its liveness: the list
/// reads an entry whose signer has ended since). A managed host's custodial
/// root and an admin-only key are no key of the owner's.
fn signed_by_a_key_of_the_owners(
    fold: &AuthorityFold,
    hosted: bool,
    entry: &AuthorityLogEntry,
) -> bool {
    std::iter::once(&entry.signer.public_key)
        .chain(entry.cosigns.iter().map(|cosign| &cosign.public_key))
        .any(|key| {
            fold.roster
                .get(key)
                .is_some_and(|device| device.roles & ROLE_OWNER != 0)
                && !(hosted && fold.in_host_custody(key))
        })
}
