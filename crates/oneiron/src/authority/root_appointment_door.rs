//! The root appointment door's writer half (row OWNER-ANCHOR-ROOT-RECOVERY,
//! PLAN v3 section 7; Engine RULINGs 14 Nov 21:01, 21:47 and 22:32).
//!
//! [`Vault::appoint_owner_root`] checks the owner, the kit and the pin, and
//! makes the successor key; this half runs in its writer transaction. It
//! names the appointment's parents from the recovery evidence: the rows of a
//! closed conflict (the witnesses, which the append frontier never holds),
//! this install's heads, and the root's own record. It judges each candidate
//! appointment over its ancestry, as every install's fold will, before the
//! anchor signs one, so an honest door never signs, let alone writes, a void
//! row: a void row burns the anchor. Then the successor binds the owner as
//! `human`, and the fold runs again. The transaction commits only when the
//! fold counts the appointment, the successor is a live root key, the
//! owner's binding is active, and the roster holds a root key again.

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::{Signer, SigningKey};

use crate::error::Result;
use crate::key_material::refused;
use crate::world_keys::OwnerRootSigner;
use crate::{EntityId, TimeRange, Vault};

use super::root_appointment_judge::{proof_fold, verdict_of_candidate};
use super::*;

/// The roster still holds a live root key: no appointment is needed.
/// Nothing was written.
const NOT_ROOTLESS: &str = "this install's roster still holds a live root key; no appointment \
                            is needed; nothing was written";
/// The pinned root's anchor is burned on this install. Nothing was written.
const ANCHOR_BURNED: &str = "the anchor of this install's pinned root is burned; re-issue the \
                             kit, pin its root with pin_owner_root and appoint with the new \
                             anchor; nothing was written";
/// No candidate ancestry gives a valid appointment (the verdict's reason
/// follows). Nothing was written.
const VOID_ROOTED: &str = "no ancestry this install holds folds to a roster without a live root \
                           key; the appointment would be void; nothing was written";
const VOID_NO_ROOT: &str = "no ancestry this install holds carries the pinned root's record as \
                            its anchor fold takes it; the appointment would be void; nothing \
                            was written";
const VOID_SEQUENCE: &str = "the anchor's sequence does not advance over its own rows; the \
                             appointment would be void; nothing was written";
const VOID_BURNED: &str = "the anchor is burned in the ancestry this install holds; the \
                           appointment would be void; nothing was written";
const NOT_FRESH: &str = "a row this install holds names the new successor key; nothing was \
                         written";
const PENDING: &str = "this install's history is incomplete for the appointment's ancestry, or \
                       its fold passes the memory floor; nothing was written";
/// The fold did not count the signed appointment, or its successor is not
/// a live root key. Nothing was written.
const NOT_COUNTED: &str = "this install's fold does not count the appointment, or its successor \
                           is not a live root key; nothing was written";
/// The fold did not count the successor's binding of the owner, or the
/// roster still holds no root key. Nothing was written.
const BINDING_NOT_COUNTED: &str = "this install's fold does not count the successor's binding of \
                                   the owner, or the roster still holds no root key; nothing \
                                   was written";

/// What a counted appointment answers, once it committed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootAppointmentReceipt {
    /// The appointment's authority entry.
    pub entry: AuthorityEntryHash,
    /// The pinned root whose anchor signed it.
    pub root: RecoveryRootId,
    /// The successor root key: this install's owner signing key from now on.
    pub successor: [u8; 32],
    /// The successor's binding of the owner as `human`.
    pub binding: AuthorityEntryHash,
    /// That binding's epoch.
    pub epoch: u64,
    /// The rows this install held valid before the appointment that no
    /// longer stand: an old roster key signed them, or one below them,
    /// outside the appointment's line, and its fence seals them.
    pub sealed: BTreeSet<AuthorityEntryHash>,
}

/// Whether `fold`'s roster holds a live root key (`ROLE_OWNER`).
fn rooted(fold: &AuthorityFold) -> bool {
    fold.roster
        .values()
        .any(|device| !device.revoked && device.roles & ROLE_OWNER != 0)
}

/// Whether `fold` names `anchor` burned.
fn burned(fold: &AuthorityFold, anchor: [u8; 32]) -> bool {
    fold.issues.iter().any(|issue| {
        matches!(issue, AuthorityFoldIssue::AnchorBurned { anchor: named } if *named == anchor)
    })
}

/// The refusal for a candidate's verdict.
fn void_refusal(verdict: AppointmentVerdict) -> crate::error::Error {
    refused(match verdict {
        AppointmentVerdict::Void(AppointmentVoidReason::RootedAncestry) => VOID_ROOTED,
        AppointmentVerdict::Void(AppointmentVoidReason::NoOwnerRoot) => VOID_NO_ROOT,
        AppointmentVerdict::Void(AppointmentVoidReason::SequenceNotAdvanced) => VOID_SEQUENCE,
        AppointmentVerdict::Void(AppointmentVoidReason::AnchorBurned) => VOID_BURNED,
        AppointmentVerdict::SuccessorNotFresh => NOT_FRESH,
        AppointmentVerdict::Unjudged | AppointmentVerdict::Pending | AppointmentVerdict::Valid => {
            PENDING
        }
    })
}

/// Refuses an appointment `fold` does not need: a roster that holds a live
/// root key, or a burned `anchor`.
pub(crate) fn refuse_unneeded_appointment(fold: &AuthorityFold, anchor: [u8; 32]) -> Result<()> {
    if rooted(fold) {
        return Err(refused(NOT_ROOTLESS));
    }
    if burned(fold, anchor) {
        return Err(refused(ANCHOR_BURNED));
    }
    Ok(())
}

/// The hashes of `hash`'s strict ancestry in `rows`, as far as they reach.
fn ancestry_in(
    rows: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    hash: &AuthorityEntryHash,
) -> BTreeSet<AuthorityEntryHash> {
    let mut ancestry = BTreeSet::new();
    let mut stack: Vec<AuthorityEntryHash> = rows
        .get(hash)
        .map(|row| row.parent_hashes.clone())
        .unwrap_or_default();
    while let Some(parent) = stack.pop() {
        if ancestry.insert(parent)
            && let Some(row) = rows.get(&parent)
        {
            stack.extend(row.parent_hashes.iter().copied());
        }
    }
    ancestry
}

/// `ordered` without the rows in another one's ancestry, the first
/// [`MAX_PARENTS`] of what is left, ascending.
fn parent_set(
    rows: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    ordered: &[AuthorityEntryHash],
) -> Vec<AuthorityEntryHash> {
    let mut unique = Vec::new();
    for hash in ordered {
        if !unique.contains(hash) {
            unique.push(*hash);
        }
    }
    let below: BTreeSet<AuthorityEntryHash> = unique
        .iter()
        .flat_map(|hash| ancestry_in(rows, hash))
        .collect();
    let mut parents: Vec<_> = unique
        .into_iter()
        .filter(|hash| !below.contains(hash))
        .take(MAX_PARENTS)
        .collect();
    parents.sort_unstable();
    parents
}

/// The parent sets the door tries, in order (PLAN v3 section 7): for each
/// closed conflict, smallest first, its two smallest rows, then all of its
/// rows when they fit in [`MAX_PARENTS`], each first with this install's heads
/// and then with the root's record alone; last, the heads alone, for a
/// roster no conflict left rootless (a handoff to a key without
/// `ROLE_OWNER`, a revocation).
fn candidate_parents(
    rows: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    conflicts: &[BTreeSet<AuthorityEntryHash>],
    heads: &[AuthorityEntryHash],
    root_record: Option<AuthorityEntryHash>,
) -> Vec<Vec<AuthorityEntryHash>> {
    let mut conflicts: Vec<&BTreeSet<AuthorityEntryHash>> = conflicts.iter().collect();
    conflicts.sort_by_key(|conflict| conflict.first().copied());
    let mut candidates = Vec::new();
    for conflict in conflicts {
        let pair: Vec<AuthorityEntryHash> = conflict.iter().take(2).copied().collect();
        let mut witnesses = vec![pair];
        if conflict.len() > 2 && conflict.len() <= MAX_PARENTS {
            witnesses.push(conflict.iter().copied().collect());
        }
        for witnesses in witnesses {
            let with_heads: Vec<_> = witnesses.iter().chain(heads).copied().collect();
            candidates.push(parent_set(rows, &with_heads));
            let with_root: Vec<_> = witnesses.iter().chain(&root_record).copied().collect();
            candidates.push(parent_set(rows, &with_root));
        }
    }
    candidates.push(parent_set(rows, heads));
    candidates.dedup();
    candidates
}

/// The appointment of `successor` that `anchor`, the anchor of `pin`'s root,
/// would sign at `seq` on `parents`, with the successor's proof and no
/// anchor signature yet.
fn unsigned_appointment(
    vault_id: AuthorityVaultId,
    pin: &PinnedRoot,
    anchor: &SigningKey,
    successor: &OwnerRootSigner,
    seq: u64,
    parents: Vec<AuthorityEntryHash>,
    now: u64,
) -> Result<AuthorityLogEntry> {
    let proof = successor.sign_appointment_challenge(&vault_id, &pin.id, &parents)?;
    let anchor_key = AuthorityKey::Ed25519(anchor.verifying_key().to_bytes());
    let mut entry = AuthorityLogEntry {
        schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id: Some(vault_id),
        seq,
        parent_hashes: parents,
        op: AuthorityOp::RootAppointment(RootAppointment {
            root: pin.id,
            successor: DeviceAuthority {
                key: AuthorityKey::Ed25519(successor.public_key()),
                transport_key_binding: [0; 32],
                attestation: AuthorityAttestation {
                    kind: ROOT_APPOINTMENT_SUCCESSOR_PROOF_KIND.to_owned(),
                    evidence: proof,
                },
                tier: AuthorityTier::Software,
                roles: ROOT_APPOINTMENT_SUCCESSOR_ROLES,
            },
        }),
        signer: AuthoritySignature {
            suite: AuthoritySignatureSuite::Ed25519,
            public_key: anchor_key,
            signature: vec![0; 64],
        },
        cosigns: Vec::new(),
        ts: now,
    };
    entry.validate_shape().map_err(|_| invalid_authority())?;
    Ok(entry)
}

/// The first candidate appointment whose verdict over its own ancestry in
/// `rows`, this install's stored history, is valid, signed by `anchor`; else
/// the refusal for the last candidate's verdict. Each candidate is judged
/// before the anchor signs it, so the anchor signs no void appointment, not
/// even one the door discards.
fn valid_appointment(
    fold: &AuthorityFold,
    rows: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    pin: &PinnedRoot,
    anchor: &SigningKey,
    successor: &OwnerRootSigner,
    now: u64,
) -> Result<AuthorityLogEntry> {
    let vault_id = fold.vault_id.ok_or_else(invalid_authority)?;
    let anchor_key = AuthorityKey::Ed25519(pin.anchor_key);
    // Strictly above every row the anchor signed here (V2).
    let seq = rows
        .values()
        .filter(|row| *row.signer_key() == anchor_key)
        .map(|row| row.seq)
        .max()
        .map_or(Ok(0), |seq| {
            seq.checked_add(1).ok_or_else(invalid_authority)
        })?;
    // The canonical fold of the whole history names its closed conflicts.
    let history: Vec<AuthorityLogEntry> = rows.values().cloned().collect();
    let conflicts = proof_fold(&history, pin.id, pin.anchor_key)
        .1
        .map(|parts| parts.closed_conflicts)
        .unwrap_or_default();
    let heads: Vec<AuthorityEntryHash> = fold
        .append_heads
        .iter()
        .chain(fold.anchor_heads.get(&pin.anchor_key).into_iter().flatten())
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let root_record = rows.iter().find_map(|(hash, row)| {
        matches!(&row.op, AuthorityOp::OwnerRoot(record)
            if record.root == pin.id && record.anchor_key == pin.anchor_key)
        .then_some(*hash)
    });
    let mut last = AppointmentVerdict::Pending;
    for parents in candidate_parents(rows, &conflicts, &heads, root_record) {
        if parents.is_empty() {
            continue;
        }
        let mut entry = unsigned_appointment(vault_id, pin, anchor, successor, seq, parents, now)?;
        last = verdict_of_candidate(rows, &entry);
        if last == AppointmentVerdict::Valid {
            entry.signer.signature = anchor
                .sign(&authority_transcript(&entry)?)
                .to_bytes()
                .to_vec();
            return Ok(entry);
        }
    }
    Err(void_refusal(last))
}

impl Vault {
    /// [`Vault::appoint_owner_root`]'s writer half, in its transaction, for
    /// `owner`, a vault owner the caller revalidated in it: `anchor` (the
    /// anchor of `pin`, this install's pin) appoints the key `successor`
    /// makes on the recovery evidence, and the successor binds `owner` as
    /// `human` at its own floor, one past any binding its key has had (a
    /// fresh key has none). The caller commits.
    ///
    /// `successor` runs only once the roster reads rootless in this
    /// transaction: a run checked before another run's appointment committed
    /// is refused here, before it makes a key in place of that run's
    /// successor.
    pub(crate) fn appoint_successor_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        owner: EntityId,
        pin: &PinnedRoot,
        anchor: &SigningKey,
        successor: impl FnOnce() -> Result<OwnerRootSigner>,
    ) -> Result<RootAppointmentReceipt> {
        let before = self.authority_view_readonly_in_txn(txn)?;
        refuse_unneeded_appointment(&before, pin.anchor_key)?;
        let successor = successor()?;
        let rows: BTreeMap<AuthorityEntryHash, AuthorityLogEntry> =
            super::history_transfer::history_in_txn(self, txn)?
                .into_iter()
                .map(|(hash, (_, entry))| (hash, entry))
                .collect();
        let now = self.instant_in_txn(txn)?.secs();
        let at = TimeRange {
            start: now,
            end: now,
        };
        let appointment = valid_appointment(&before, &rows, pin, anchor, &successor, now)?;
        let entry = authority_entry_hash(&appointment)?;
        self.put_authority_log_entries_in_txn(txn, &[(appointment, at, now)])?;
        let key = AuthorityKey::Ed25519(successor.public_key());
        let mid = self.authority_view_readonly_in_txn(txn)?;
        if !mid.valid_entries.contains(&entry)
            || !mid.roster.get(&key).is_some_and(|device| !device.revoked)
        {
            return Err(refused(NOT_COUNTED));
        }
        let epoch = mid
            .actor_bindings
            .get(&key)
            .map_or(Some(1), |binding| binding.epoch.checked_add(1))
            .ok_or_else(invalid_authority)?;
        let mut bind = AuthorityLogEntry {
            schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
            vault_id: mid.vault_id,
            seq: next_sequence(&mid, &key)?,
            parent_hashes: vec![entry],
            op: AuthorityOp::BindActor {
                authority_key: key.clone(),
                actor_ref: owner,
                actor_class: ACTOR_CLASS_HUMAN.into(),
                epoch,
            },
            signer: AuthoritySignature {
                suite: AuthoritySignatureSuite::Ed25519,
                public_key: key.clone(),
                signature: vec![0; 64],
            },
            cosigns: Vec::new(),
            ts: now,
        };
        bind.signer.signature = successor.sign_successor_binding(&bind)?;
        let binding = authority_entry_hash(&bind)?;
        self.put_authority_log_entries_in_txn(txn, &[(bind, at, now)])?;
        let after = self.authority_view_readonly_in_txn(txn)?;
        if !after.valid_entries.contains(&binding)
            || !after.valid_entries.contains(&entry)
            || !after.roster.get(&key).is_some_and(|device| !device.revoked)
            || !actor_binding_is_active(&after, &owner, ACTOR_CLASS_HUMAN)
            || !rooted(&after)
        {
            return Err(refused(BINDING_NOT_COUNTED));
        }
        let sealed = before
            .valid_entries
            .iter()
            .filter(|hash| !after.valid_entries.contains(hash))
            .copied()
            .collect();
        Ok(RootAppointmentReceipt {
            entry,
            root: pin.id,
            successor: successor.public_key(),
            binding,
            epoch,
            sealed,
        })
    }
}
