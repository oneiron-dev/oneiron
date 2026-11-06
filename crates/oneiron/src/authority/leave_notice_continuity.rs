//! Leave-notice continuity (FIX 7932, Engine 19:59 = A): the purpose-limited
//! delegations a root signs at each ReRoot it settles, kept here as
//! immutable authority evidence, sent beside a removed person's notices, and
//! judged by that person's env.
//!
//! The ReRoot signer path signs the move and its [`LeaveNoticeDelegation`]
//! while the predecessor key is at hand, and stores the delegation in the
//! transaction that settles the handoff; a move signed elsewhere brings its
//! delegation along, checked against the move before it is stored. Each
//! delegation's canonical bytes are kept under their digest, and the digest
//! under the handoff entry it names. A ReRoot settled with none, or before
//! this code, has none: nothing is inferred or backfilled, so it bridges no
//! root for a leave notice.
//!
//! The delegations follow the vault's home: a home move carries them
//! ([`home_rows`]), so a new home answers a removed person's notices with
//! every delegation the old one held. They name keys and hashes and no
//! actor, so an actor's erase leaves them as the log it binds is left; no
//! signed byte is ever edited. An archive export carries none, as its import
//! restores no authority log row for them to bind.
//!
//! A delegation hands on leave-notice verification only. The env that judges
//! one anchors at a live Owner of its own, unconflicted fold and verifies every
//! link from there to the notice's signer; it writes no authority row and
//! builds no roster. A gap leaves the notice pending, and nothing is purged on
//! it; a link a key this env already knows retired, or a handoff this env
//! holds in conflict, refuses it.

#[cfg(feature = "sync")]
use std::collections::{BTreeMap, BTreeSet};

use super::*;
use crate::Vault;
use crate::error::Result;
use crate::side_table::{self, Raw, SideTable};
use crate::store::Store;

// The adapter a home move carries the delegations through (L01 20:19 (6)).
#[cfg(feature = "sync")]
mod home_rows;

#[cfg(feature = "sync")]
pub(crate) use home_rows::LeaveNoticeDelegationRows;

/// One delegation's canonical bytes. Key: its digest.
const DELEGATIONS: SideTable<[u8; 32], Vec<u8>, Raw> =
    SideTable::new(&side_table::AUTHORITY_LEAVE_NOTICE_DELEGATION);
/// The digest of the delegation a settled ReRoot's root signed. Key: the
/// ReRoot's entry hash.
const DELEGATION_BY_HANDOFF: SideTable<AuthorityEntryHash, [u8; 32], Raw> =
    SideTable::new(&side_table::AUTHORITY_LEAVE_NOTICE_DELEGATION_BY_HANDOFF);

/// What rides beside a removed person's leave notices in place of any
/// authority row (FIX 7932): the authority vault, and the canonical bytes of
/// the delegations on the root chain to the key that signed the notices, in
/// chain order, less those the person's env already folded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaveNoticeContinuity {
    /// The authority vault the notices and delegations name.
    pub authority_vault_id: AuthorityVaultId,
    /// Each delegation's canonical bytes ([`LeaveNoticeDelegation::encode`]).
    pub delegations: Vec<Vec<u8>>,
}

/// How a leave notice's signer stands in this env, on its own fold and the
/// continuity the notice rode with. A notice-verification result only: never
/// a fold, a roster or root-attestation assurance.
#[cfg(feature = "sync")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NoticeSignerStanding {
    /// A live Owner of this env's fold, or the successor every carried link
    /// from one hands leave-notice verification on to.
    Trusted,
    /// No carried link reaches from a live Owner of this env's fold to the
    /// signer: a later delivery may.
    Pending,
    /// The signer or a link stands on what this env knows otherwise, names
    /// another vault, or does not verify.
    Refused,
}

/// The delegation the ReRoot `entry` settles, before its signature (an empty
/// one under the predecessor's key): this vault's authority vault, the
/// move's signer and successor, its entry hash, and the digest of the one
/// stored delegation that made the signer root, when one did.
fn unsigned_delegation_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    entry: &AuthorityLogEntry,
) -> Result<LeaveNoticeDelegation> {
    let AuthorityOp::ReRoot { new_device } = &entry.op else {
        return Err(invalid_authority());
    };
    let authority_vault_id = entry.vault_id.ok_or_else(invalid_authority)?;
    let predecessor = entry.signer_key().clone();
    let predecessor_delegation = delegation_to_in_txn(store, txn, &predecessor)?;
    Ok(LeaveNoticeDelegation {
        schema_version: LEAVE_NOTICE_DELEGATION_SCHEMA_VERSION,
        authority_vault_id,
        predecessor: predecessor.clone(),
        successor: new_device.key.clone(),
        handoff_entry: authority_entry_hash(entry)?,
        predecessor_delegation,
        purpose: LeaveNoticeDelegationPurpose::LeaveNoticesOnly,
        signature: AuthoritySignature {
            suite: predecessor.suite(),
            public_key: predecessor,
            signature: Vec::new(),
        },
    })
}

/// The digest of the one stored delegation that handed the root on to
/// `key`; `None` when none did, or more than one names it.
fn delegation_to_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    key: &AuthorityKey,
) -> Result<Option<[u8; 32]>> {
    let mut found = None;
    for (digest, bytes) in DELEGATIONS.scan(store, txn)? {
        if LeaveNoticeDelegation::decode(&bytes)?.successor != *key {
            continue;
        }
        if found.is_some() {
            return Ok(None);
        }
        found = Some(digest);
    }
    Ok(found)
}

/// Signs, through `sign`, the delegation the ReRoot `entry` settles, while
/// its signer's key is at hand, and stores it in `txn`, the transaction that
/// settles the handoff ([`store_delegation_in_txn`]).
pub(super) fn sign_delegation_in_txn<S>(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    entry: &AuthorityLogEntry,
    sign: &mut S,
) -> Result<()>
where
    S: FnMut(&[u8]) -> Result<Vec<u8>>,
{
    let mut delegation = unsigned_delegation_in_txn(store, txn, entry)?;
    delegation.signature.signature = sign(&delegation.transcript()?)?;
    store_delegation_in_txn(store, txn, entry, &delegation)
}

/// Stores `delegation`, the one the ReRoot `entry` settles, in `txn`: it must
/// be the delegation this vault makes of `entry`
/// ([`unsigned_delegation_in_txn`]: its vault, predecessor, successor,
/// handoff and predecessor delegation), signed by the move's signer. A
/// handoff that already has one keeps it: none is ever rewritten.
///
/// # Errors
///
/// A delegation that differs from `entry`'s or does not verify; storage
/// errors.
pub(super) fn store_delegation_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    entry: &AuthorityLogEntry,
    delegation: &LeaveNoticeDelegation,
) -> Result<()> {
    let expected = LeaveNoticeDelegation {
        signature: delegation.signature.clone(),
        ..unsigned_delegation_in_txn(store, txn, entry)?
    };
    if expected != *delegation || !delegation.verify() {
        return Err(invalid_authority());
    }
    if DELEGATION_BY_HANDOFF.contains(store, txn, &delegation.handoff_entry)? {
        return Ok(());
    }
    let bytes = delegation.encode()?;
    let digest = leave_notice_delegation_digest(&bytes);
    DELEGATIONS.put(store, txn, &digest, &bytes)?;
    DELEGATION_BY_HANDOFF.put(store, txn, &delegation.handoff_entry, &digest)
}

/// The stored delegations that hand the root on to `signer`, as (handoff
/// entry, canonical bytes), in chain order (FIX 7932): walked back from
/// `signer` through each certificate's own predecessor, so a home that
/// adopted a checkpoint image and holds no raw ReRoot row still finds the
/// certificates a home move carried in. The walk ends at a key no stored
/// delegation hands the root to, at a key more than one does (a fork this
/// selection does not choose between), or at a repeated handoff. It only
/// selects what rides: the member's env verifies every link.
pub(super) fn delegation_chain_to_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    signer: &AuthorityKey,
) -> Result<Vec<(AuthorityEntryHash, Vec<u8>)>> {
    let mut stored = Vec::new();
    for (_, bytes) in DELEGATIONS.scan(store, txn)? {
        let delegation = LeaveNoticeDelegation::decode(&bytes)?;
        stored.push((delegation, bytes));
    }
    let mut chain: Vec<(AuthorityEntryHash, Vec<u8>)> = Vec::new();
    let mut key = signer.clone();
    loop {
        let mut to = stored
            .iter()
            .filter(|(delegation, _)| delegation.successor == key);
        let (Some((delegation, bytes)), None) = (to.next(), to.next()) else {
            break;
        };
        if chain
            .iter()
            .any(|(handoff, _)| *handoff == delegation.handoff_entry)
        {
            break;
        }
        chain.push((delegation.handoff_entry, bytes.clone()));
        key = delegation.predecessor.clone();
    }
    chain.reverse();
    Ok(chain)
}

impl Vault {
    /// The leave-notice delegation this vault stores beside the ReRoot
    /// `entry`, signed elsewhere, before its signature (FIX 7932): its
    /// signer signs [`LeaveNoticeDelegation::transcript`] into
    /// `signature.signature`, and the request that carries the move carries
    /// it too ([`VaultRecoveryRequest::delegation`]).
    ///
    /// # Errors
    ///
    /// An entry that is no ReRoot of a vault; storage errors.
    pub fn unsigned_leave_notice_delegation(
        &self,
        entry: &AuthorityLogEntry,
    ) -> Result<LeaveNoticeDelegation> {
        let txn = self.store.env.read_txn()?;
        unsigned_delegation_in_txn(&self.store, &txn, entry)
    }

    /// How `signer`, the key a leave notice naming the authority vault
    /// `authority_vault_id` is signed under, stands in this env, with the
    /// `continuity` it rode with ([`NoticeSignerStanding`], FIX 7932).
    /// Nothing is written.
    ///
    /// # Errors
    ///
    /// Storage errors.
    #[cfg(feature = "sync")]
    pub(crate) fn leave_notice_signer_standing(
        &self,
        authority_vault_id: &AuthorityVaultId,
        signer: &AuthorityKey,
        continuity: &LeaveNoticeContinuity,
    ) -> Result<NoticeSignerStanding> {
        let txn = self.store.env.read_txn()?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        drop(txn);
        Ok(signer_standing(
            &fold,
            authority_vault_id,
            signer,
            continuity,
        ))
    }
}

/// One carried delegation and its digest.
#[cfg(feature = "sync")]
struct Link {
    digest: [u8; 32],
    delegation: LeaveNoticeDelegation,
}

/// `signer`'s standing on `fold` with `continuity`. The fold must hold
/// `authority_vault_id`'s root unconflicted, and the continuity name that
/// vault. A live Owner of `fold` stands as it is. Any other signer stands
/// only at the end of carried links walked back to a live Owner of `fold`
/// ([`walk_to_anchor`]).
#[cfg(feature = "sync")]
fn signer_standing(
    fold: &AuthorityFold,
    authority_vault_id: &AuthorityVaultId,
    signer: &AuthorityKey,
    continuity: &LeaveNoticeContinuity,
) -> NoticeSignerStanding {
    if fold.vault_root_is_conflicted()
        || fold.vault_id != Some(*authority_vault_id)
        || continuity.authority_vault_id != *authority_vault_id
    {
        return NoticeSignerStanding::Refused;
    }
    if roster_has_live_owner(&fold.roster, signer) {
        return NoticeSignerStanding::Trusted;
    }
    match carried_links(authority_vault_id, &continuity.delegations) {
        Some(links) => walk_to_anchor(fold, signer, &links),
        None => NoticeSignerStanding::Refused,
    }
}

/// The carried delegations by successor; `None` when one does not decode,
/// names another vault or does not verify, or two repeat a digest, hand on
/// from one predecessor, or hand on to one successor (competing links).
#[cfg(feature = "sync")]
fn carried_links(
    authority_vault_id: &AuthorityVaultId,
    delegations: &[Vec<u8>],
) -> Option<BTreeMap<AuthorityKey, Link>> {
    let mut by_successor = BTreeMap::new();
    let mut predecessors = BTreeSet::new();
    let mut digests = BTreeSet::new();
    for bytes in delegations {
        let delegation = LeaveNoticeDelegation::decode(bytes).ok()?;
        if delegation.authority_vault_id != *authority_vault_id || !delegation.verify() {
            return None;
        }
        let digest = leave_notice_delegation_digest(bytes);
        if !digests.insert(digest) || !predecessors.insert(delegation.predecessor.clone()) {
            return None;
        }
        let successor = delegation.successor.clone();
        if by_successor
            .insert(successor, Link { digest, delegation })
            .is_some()
        {
            return None;
        }
    }
    Some(by_successor)
}

/// Walks back from `signer` through `links`, each step the link that hands
/// on to the key the walk stands at, to a live Owner of `fold`, the anchor.
/// Each link names the digest of the link before it; the link from the
/// anchor may name the delegation that made the anchor root, which, when it
/// rides, hands on to the anchor. Pending where no link hands on to the key
/// the walk stands at, or a link names no delegation before it. Refused where
/// `fold` already knows a key the walk passes revoked or retired, holds a
/// link's handoff in conflict, or a link names another delegation than the
/// one before it, or the walk passes a key twice.
#[cfg(feature = "sync")]
fn walk_to_anchor(
    fold: &AuthorityFold,
    signer: &AuthorityKey,
    links: &BTreeMap<AuthorityKey, Link>,
) -> NoticeSignerStanding {
    let mut key = signer;
    let mut passed = BTreeSet::from([signer]);
    let mut later: Option<&Link> = None;
    loop {
        if roster_has_live_owner(&fold.roster, key) {
            let named = later.and_then(|link| link.delegation.predecessor_delegation);
            if named.is_some_and(|named| {
                links
                    .values()
                    .any(|prior| prior.digest == named && prior.delegation.successor != *key)
            }) {
                return NoticeSignerStanding::Refused;
            }
            return NoticeSignerStanding::Trusted;
        }
        if fold.retired_keys.contains(key)
            || fold.roster.get(key).is_some_and(|device| device.revoked)
        {
            return NoticeSignerStanding::Refused;
        }
        let Some(link) = links.get(key) else {
            return NoticeSignerStanding::Pending;
        };
        let handoff = &link.delegation.handoff_entry;
        if fold.closed_handoffs.contains(handoff) && !fold.valid_entries.contains(handoff) {
            return NoticeSignerStanding::Refused;
        }
        if let Some(later) = later {
            match later.delegation.predecessor_delegation {
                Some(named) if named == link.digest => {}
                Some(_) => return NoticeSignerStanding::Refused,
                None => return NoticeSignerStanding::Pending,
            }
        }
        if !passed.insert(&link.delegation.predecessor) {
            return NoticeSignerStanding::Refused;
        }
        later = Some(link);
        key = &link.delegation.predecessor;
    }
}
