//! A box recovery's wait (OPUS-WAYBACK): the fold's judgement of the hold
//! rows, the hold view, the wait, the landing and the answers (Engine RULING
//! WAYBACK-RECOVERY-HOLD-WIRE = A).
//!
//! After a box recovery the root's door holds the vouch instead of writing
//! it: one [`RecoveryHold`] signed by R, judged here, read by
//! [`Vault::recovery_holds_in_txn`], landed lazily by
//! [`Vault::land_due_recovery_holds`], and answered by owner devices and the
//! kit. A hold or an answer changes no roster, no grant and no anchor.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron_keystore::{DeviceKeystore, KeystoreError, KeystoreSlot, SlotKind};
use zeroize::Zeroizing;

use super::owner_key_enrollment_door::EntrySigner;
use super::*;
use crate::error::{Error, SecretError};
use crate::side_table::{self, Raw, SideTable};
use crate::store::recovery_kit::{KitPassphrase, KitPiece, KitSecretKind};
use crate::world_keys::{OwnerRootSigner, RecoveryAuthoritySigner, keystore_error};
use crate::{EntityId, Result, TimeRange, Vault};

/// The hold's signer and successor, judged at the parents' state: the
/// signer is the recovery root's authority key R (the generic transition
/// checked its liveness, consent and sequence before this arm), and the
/// successor is fresh there: no roster row names it, live or revoked, as an
/// enrolment of it would need.
pub(super) fn judge_recovery_hold(
    state: &FoldState,
    entry: &AuthorityLogEntry,
    hold: &RecoveryHold,
    hash: AuthorityEntryHash,
) -> std::result::Result<(), AuthorityFoldIssue> {
    if !state.recovery_authority_keys.contains(entry.signer_key()) {
        return Err(AuthorityFoldIssue::MissingAuthorityConsent(hash));
    }
    if state.roster.contains_key(&hold.successor_key()) {
        return Err(AuthorityFoldIssue::InvalidEntry(hash));
    }
    Ok(())
}

/// A roster-signed answer's signer, judged at the parents' state: a live
/// owner device key that is not R, with no cosign. R never answers a hold:
/// the box releases R, so an R-signed answer would end the wait for the
/// attacker. Nor does an admin's key or a host's ([`answers_recovery_holds`]):
/// the generic consent rule admits both, and either answer would end or stop
/// an owner's wait with no owner device (WAYBACK-7: no staff override). (An
/// anchor's Cancel, beside R's cosign, folded through the anchor's branch
/// before the roster rules; an anchor's ItIsMe is refused as not-in-ancestry
/// before this arm.)
pub(super) fn judge_recovery_hold_answer(
    state: &FoldState,
    entry: &AuthorityLogEntry,
    hash: AuthorityEntryHash,
) -> std::result::Result<(), AuthorityFoldIssue> {
    if !entry.cosigns.is_empty() {
        return Err(AuthorityFoldIssue::InvalidEntry(hash));
    }
    if state.recovery_authority_keys.contains(entry.signer_key()) {
        return Err(AuthorityFoldIssue::InvalidEntry(hash));
    }
    if !state
        .roster
        .get(entry.signer_key())
        .is_some_and(answers_recovery_holds)
    {
        return Err(AuthorityFoldIssue::MissingAuthorityConsent(hash));
    }
    Ok(())
}

/// Whether `device` may answer a recovery hold: a live owner key on its own
/// device, the local consent rule's owner half. Never an admin-only key, and
/// never a key stamped as the host's (`ROLE_CLOUD` or `CloudCustodial`), on
/// any posture. The fold and the answer door both ask it.
pub(super) fn answers_recovery_holds(device: &FoldedDevice) -> bool {
    folded_device_can_authority_consent(device) && device.roles & ROLE_OWNER != 0
}

/// One recovery hold as this install reads it: the attempt, its successor
/// and lost keys, its landing second, its state on the reader's clock, and
/// who answered it. Every owner device folds the same rows; only the
/// Due/Waiting line moves with the reader's clock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryHoldView {
    /// The hold's entry hash: the attempt id.
    pub hold: AuthorityEntryHash,
    /// The hold's signer R: the recovery root's authority key whose released
    /// seed the landing signs with. The kit's Cancel counts for this hold
    /// only beside R's cosign; a kit whose live root key is another key's
    /// cancels another root's holds.
    pub root_key: AuthorityKey,
    /// The successor key the landing enrols.
    pub successor_key: AuthorityKey,
    /// The machine that holds the successor key.
    pub successor_machine: EntityId,
    /// The lost keys the landing revokes.
    pub lost: Vec<AuthorityKey>,
    /// Unix seconds the wait ends at, on the door install's clock.
    pub lands_at: u64,
    /// What the attempt is now.
    pub state: RecoveryHoldState,
    /// The signers of the hold's valid answers that count for it,
    /// ascending, each once: a roster key's answers, and the kit's Cancel
    /// only beside this hold's signer R (a foreign anchor's Cancel is
    /// inert, and leaves no name here).
    pub answered_by: Vec<AuthorityKey>,
}

/// What a recovery hold is now, judged from the log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryHoldState {
    /// Live and not due: lands at `lands_at` unless answered first.
    Waiting,
    /// Live and due: an ItIsMe answered it, or the reader's clock reached
    /// `lands_at`. Lands at the seed holder's next call.
    Due,
    /// The successor key is on the roster: the attempt completed.
    Landed,
    /// A Cancel answered it: it never lands, and no later answer revives it.
    Cancelled,
    /// The hold's signer R is no longer a live roster key: it never lands.
    Void,
}

/// The view order: Landed, then Cancelled, then Void, then Due/Waiting.
fn state_rank(state: RecoveryHoldState) -> u8 {
    match state {
        RecoveryHoldState::Landed => 0,
        RecoveryHoldState::Cancelled => 1,
        RecoveryHoldState::Void => 2,
        RecoveryHoldState::Due | RecoveryHoldState::Waiting => 3,
    }
}

impl Vault {
    /// Every recovery hold this install's log holds, with its state: Landed
    /// once the successor key is on the roster (live or since revoked: the
    /// attempt completed), else Cancelled on any valid Cancel that counts
    /// for the hold (a roster key's, or the kit's anchor-signed Cancel
    /// beside this hold's signer R; a foreign anchor's Cancel is inert, and
    /// an ItIsMe never revives one), else Void when the hold's signer R is
    /// no longer live, else Due on a valid ItIsMe or when this reader's
    /// `instant_in_txn` reached `lands_at`, else Waiting. Only rows this
    /// install's fold counts are read: a refused hold or answer is as if
    /// unwritten, and an answer to an unknown hold is inert. On a vault
    /// that adopted a checkpoint image, a hold or an answer the image
    /// carries and the vault does not store counts as a stored one does.
    /// Ordered Landed, Cancelled, Void, then Due/Waiting; within a rank by
    /// `lands_at`, then the attempt id.
    ///
    /// # Errors
    /// The log's and the clock's.
    pub fn recovery_holds_in_txn(&self, txn: &heed::RoTxn<'_>) -> Result<Vec<RecoveryHoldView>> {
        let fold = self.authority_view_readonly_in_txn(txn)?;
        let now = self.instant_in_txn(txn)?.secs();
        let history = super::history_transfer::history_in_txn(self, txn)?;
        let mut holds: Vec<(AuthorityEntryHash, RecoveryHold, AuthorityKey)> = Vec::new();
        let mut answers: BTreeMap<
            AuthorityEntryHash,
            Vec<(RecoveryHoldAnswerKind, AuthorityKey, Option<AuthorityKey>)>,
        > = BTreeMap::new();
        let read = |hash: AuthorityEntryHash,
                    entry: &AuthorityLogEntry,
                    holds: &mut Vec<(AuthorityEntryHash, RecoveryHold, AuthorityKey)>,
                    answers: &mut BTreeMap<
            AuthorityEntryHash,
            Vec<(RecoveryHoldAnswerKind, AuthorityKey, Option<AuthorityKey>)>,
        >| {
            match &entry.op {
                AuthorityOp::RecoveryHold(hold) => {
                    holds.push((hash, hold.clone(), entry.signer_key().clone()));
                }
                AuthorityOp::RecoveryHoldAnswer(answer) => {
                    // A counted answer carries no cosign (the roster arm) or
                    // exactly one (the anchor arm): the fold refused any
                    // other shape.
                    let cosigner = match entry.cosigns.as_slice() {
                        [cosign] => Some(cosign.public_key.clone()),
                        _ => None,
                    };
                    answers.entry(answer.hold).or_default().push((
                        answer.answer,
                        entry.signer_key().clone(),
                        cosigner,
                    ));
                }
                _ => {}
            }
        };
        let mut stored = BTreeSet::new();
        for (hash, (_, entry)) in &history {
            stored.insert(*hash);
            if !fold.valid_entries.contains(hash) {
                continue;
            }
            read(*hash, entry, &mut holds, &mut answers);
        }
        if let Some(evidence) = super::adopted_evidence::adopted_evidence_in_txn(&self.store, txn)?
        {
            for (hash, entry) in evidence.carried_past(&stored) {
                if !fold.valid_entries.contains(hash) {
                    continue;
                }
                read(*hash, entry, &mut holds, &mut answers);
            }
        }
        let mut views: Vec<RecoveryHoldView> = holds
            .into_iter()
            .map(|(hash, hold, signer)| {
                let successor_key = hold.successor_key();
                let named = answers.get(&hash);
                // A Cancel counts for this hold when a roster key signed it
                // (no cosign), or when its single cosign is this hold's
                // signer R (the kit's Cancel). An anchor Cancel whose cosign
                // is another key is inert for this hold.
                let counts = |kind: RecoveryHoldAnswerKind, cosigner: &Option<AuthorityKey>| {
                    kind == RecoveryHoldAnswerKind::ItIsMe
                        || cosigner.as_ref().is_none_or(|key| *key == signer)
                };
                let cancelled = named.is_some_and(|list| {
                    list.iter().any(|(kind, _, cosigner)| {
                        *kind == RecoveryHoldAnswerKind::Cancel && counts(*kind, cosigner)
                    })
                });
                let affirmed = named.is_some_and(|list| {
                    list.iter()
                        .any(|(kind, _, _)| *kind == RecoveryHoldAnswerKind::ItIsMe)
                });
                let state = if fold.roster.contains_key(&successor_key) {
                    RecoveryHoldState::Landed
                } else if cancelled {
                    RecoveryHoldState::Cancelled
                } else if !fold
                    .roster
                    .get(&signer)
                    .is_some_and(|device| !device.revoked)
                {
                    RecoveryHoldState::Void
                } else if affirmed || now >= hold.lands_at {
                    RecoveryHoldState::Due
                } else {
                    RecoveryHoldState::Waiting
                };
                let mut answered_by: Vec<AuthorityKey> = named.map_or(Vec::new(), |list| {
                    list.iter()
                        .filter(|(kind, _, cosigner)| counts(*kind, cosigner))
                        .map(|(_, key, _)| key.clone())
                        .collect()
                });
                answered_by.sort();
                answered_by.dedup();
                RecoveryHoldView {
                    hold: hash,
                    root_key: signer,
                    successor_key,
                    successor_machine: hold.enrolment.machine,
                    lost: hold.lost.clone(),
                    lands_at: hold.lands_at,
                    state,
                    answered_by,
                }
            })
            .collect();
        views.sort_by(|a, b| {
            (state_rank(a.state), a.lands_at, a.hold).cmp(&(
                state_rank(b.state),
                b.lands_at,
                b.hold,
            ))
        });
        Ok(views)
    }

    /// [`Self::recovery_holds_in_txn`] in its own read transaction: the
    /// owner-visible "recovery started, lands at <time>, cancel?" event
    /// list, and what the recovering device's poll reads.
    ///
    /// # Errors
    /// The log's and the clock's.
    pub fn recovery_holds(&self) -> Result<Vec<RecoveryHoldView>> {
        let txn = self.store.env.read_txn()?;
        self.recovery_holds_in_txn(&txn)
    }
}

/// A recovery hold's seed slot this install may hold, by successor key:
/// the pending record the door commits before R's seed enters the slot, so
/// a crash between the keystore put and the hold commit still leaves the
/// slot on a list the landing sweep reaps. Public key only; value-free.
const RECOVERY_HOLD_SLOT_PENDING: SideTable<[u8; 32], (), Raw> =
    SideTable::new(&side_table::AUTHORITY_RECOVERY_HOLD_SLOT_PENDING);

/// The box recovery's wait until the `recovery.wait` Setting key lands: 24 h.
pub const RECOVERY_WAIT_DEFAULT: std::time::Duration = std::time::Duration::from_secs(24 * 60 * 60);

/// The fold did not count the signed recovery hold here: it never reports
/// success. Nothing was written.
const HOLD_NOT_COUNTED: &str =
    "this install's fold does not count the recovery hold; nothing was written";
/// The hold would name more rows than one authority entry may: the log's
/// encoding bound, never a possession test.
const HOLD_TOO_MANY_HEADS: &str = "the authority log has more concurrent heads than one recovery hold may name; nothing was written";
/// An answer names no live hold: it landed, was cancelled, is void, or no
/// such hold is counted here. Nothing was written.
const HOLD_NOT_LIVE: &str = "the recovery hold is not live: it landed, was cancelled, is void, \
                              or no such hold is counted here; nothing was written";
/// The hold's successor key never answers its own hold, live or not: another
/// owner device answers. Nothing was written.
const ANSWER_KEY_IS_SUCCESSOR: &str = "the hold's successor key never answers its own hold; \
                                        another owner device answers; nothing was written";
/// The root's authority key never answers a recovery hold: the box released
/// it, so its answer would end the wait for the attacker. Another owner
/// device answers. Nothing was written.
const ANSWER_KEY_IS_ROOT: &str = "the root's authority key never answers a recovery hold; \
                                   another owner device answers; nothing was written";
/// This install holds no live owner key to answer with: sign-in alone cannot
/// answer. Nothing was written.
const NO_OWNER_KEY: &str = "this install holds no live owner key to answer the recovery hold; \
                             sign-in alone cannot answer; nothing was written";
/// A recovery hold is the owner's to answer or cancel: no Grant action names
/// it. Nothing was written.
const ANSWER_OWNER_ONLY: &str =
    "a recovery hold is the owner's to answer; no Grant action names it; nothing was written";
/// The fold did not count the signed answer here: it never reports success.
/// Nothing was written.
const ANSWER_NOT_COUNTED: &str =
    "this install's fold does not count the recovery hold's answer; nothing was written";
/// The answer would name more rows than one authority entry may: the log's
/// encoding bound, never a possession test.
const ANSWER_TOO_MANY_HEADS: &str = "the authority log has more concurrent heads than one recovery answer may name; nothing was written";
/// The fold did not count the kit's hold cancellation here: it never reports
/// success. Nothing was written.
const KIT_CANCEL_NOT_COUNTED: &str =
    "this install's fold does not count the kit's hold cancellation; nothing was written";
/// The kit's root key did not sign the named hold: a kit cancels only the
/// holds its own live root key signed. Nothing was written.
const KIT_ROOT_NOT_HOLD_SIGNER: &str =
    "this kit's root key did not sign the recovery hold; nothing was written";
/// The kit's pieces do not rebuild this vault's recovery seed. Nothing was
/// written.
const KIT_PIECES_UNREADABLE: &str =
    "the kit's pieces do not rebuild this vault's recovery seed; nothing was written";

impl Vault {
    /// How long a box recovery waits before its enrolment and revocations
    /// land. Answers [`RECOVERY_WAIT_DEFAULT`] until the `recovery.wait`
    /// Setting key lands and this reads it.
    ///
    /// # Errors
    /// The store's.
    pub fn recovery_wait_in_txn(&self, _txn: &heed::RoTxn<'_>) -> Result<std::time::Duration> {
        Ok(RECOVERY_WAIT_DEFAULT)
    }

    /// R's seed slot for a hold of `successor`: this install's
    /// device-keystore slot for this vault, install and successor key.
    pub(crate) fn recovery_hold_slot(
        &self,
        vault_id: &AuthorityVaultId,
        machine: EntityId,
        successor: &[u8; 32],
    ) -> KeystoreSlot {
        KeystoreSlot {
            vault_id: *vault_id,
            install: *machine.as_bytes(),
            kind: SlotKind::RecoveryHold(*successor),
        }
    }

    /// R's seed from `slot`, or `None` when this install holds no seed for
    /// the slot's successor: a hold another install wrote is never this
    /// install's.
    ///
    /// # Errors
    /// `KeystoreUnavailable` while the host installed no keystore; the
    /// keystore's own refusal.
    pub(crate) fn read_recovery_hold_seed(
        &self,
        slot: &KeystoreSlot,
    ) -> Result<Option<Zeroizing<[u8; 32]>>> {
        Ok(self.device_keystore()?.get(slot).map_err(keystore_error)?)
    }

    /// R's `seed` into `slot`, create-only: true when this call created or
    /// replaced it, so the caller removes it again when its transaction
    /// fails. A slot that already holds this R's seed stays (a retried
    /// write); one that holds another R's (a rotation between attempts)
    /// gives way: the old hold is void. An empty slot is not an error at
    /// the delete below.
    ///
    /// # Errors
    /// `KeystoreUnavailable` while the host installed no keystore; the
    /// keystore's own refusal.
    pub(crate) fn put_recovery_hold_seed(
        &self,
        slot: &KeystoreSlot,
        seed: &Zeroizing<[u8; 32]>,
        expected: &[u8; 32],
    ) -> Result<bool> {
        let keystore = self.device_keystore()?;
        if let Some(kept) = keystore.get(slot).map_err(keystore_error)? {
            let kept_key = SigningKey::from_bytes(&kept).verifying_key().to_bytes();
            if kept_key == *expected {
                return Ok(false);
            }
            keystore.delete(slot).map_err(keystore_error)?;
        }
        match keystore.create(slot, seed) {
            Ok(()) | Err(KeystoreError::AlreadyExists) => {}
            Err(other) => return Err(keystore_error(other)),
        }
        Ok(true)
    }

    /// Empties `slot`: the landing, the cancel and the void each call it.
    /// An empty slot is not an error.
    ///
    /// # Errors
    /// `KeystoreUnavailable` while the host installed no keystore; the
    /// keystore's own refusal.
    pub(crate) fn delete_recovery_hold_seed(&self, slot: &KeystoreSlot) -> Result<()> {
        self.device_keystore()?
            .delete(slot)
            .map_err(keystore_error)?;
        Ok(())
    }

    /// Records `successor`'s seed slot as one this install may hold, in the
    /// caller's write transaction: the door commits it before R's seed
    /// enters the slot.
    ///
    /// # Errors
    /// The store's.
    pub(crate) fn put_recovery_hold_slot_pending_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        successor: &[u8; 32],
    ) -> Result<()> {
        RECOVERY_HOLD_SLOT_PENDING.put(&self.store, txn, successor, &())
    }

    /// Drops `successor`'s pending slot record in the caller's write
    /// transaction, once its slot is deleted. A missing record is none.
    ///
    /// # Errors
    /// The store's.
    pub(crate) fn drop_recovery_hold_slot_pending_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        successor: &[u8; 32],
    ) -> Result<()> {
        RECOVERY_HOLD_SLOT_PENDING.delete(&self.store, txn, successor)?;
        Ok(())
    }

    /// Every successor whose seed slot this install may hold, in key order.
    ///
    /// # Errors
    /// The store's.
    pub(crate) fn recovery_hold_slots_pending_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
    ) -> Result<Vec<[u8; 32]>> {
        Ok(RECOVERY_HOLD_SLOT_PENDING
            .scan(&self.store, txn)?
            .into_iter()
            .map(|(successor, ())| successor)
            .collect())
    }

    /// This install's waiting hold for `successor`, if one waits and its
    /// seed slot is here: the attempt id and its landing second. The root
    /// door answers it again instead of writing a second hold.
    ///
    /// # Errors
    /// The log's, the clock's and the keystore's.
    pub(crate) fn waiting_hold_for_successor_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        machine: EntityId,
        successor: &[u8; 32],
    ) -> Result<Option<(AuthorityEntryHash, u64)>> {
        let fold = self.authority_view_readonly_in_txn(txn)?;
        let vault_id = fold.vault_id.ok_or_else(invalid_authority)?;
        let wanted = AuthorityKey::Ed25519(*successor);
        for view in self.recovery_holds_in_txn(txn)? {
            if view.successor_key != wanted || view.state != RecoveryHoldState::Waiting {
                continue;
            }
            let slot = self.recovery_hold_slot(&vault_id, machine, successor);
            if self.read_recovery_hold_seed(&slot)?.is_some() {
                return Ok(Some((view.hold, view.lands_at)));
            }
        }
        Ok(None)
    }

    /// One `RecoveryHold` row in the caller's write transaction, signed by
    /// `root_key` through `sign`: the frontier join when the frontier is
    /// wide, the main-log heads as parents, R's next sequence, the stamped
    /// `now`. Answers the hold's hash once this install's fold counts it.
    /// The caller commits, and removes the seed slot again when anything
    /// here fails.
    ///
    /// # Errors
    /// An all-zero or over-wide write; an entry the fold does not count;
    /// the log's.
    pub(crate) fn append_recovery_hold_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        root_key: &AuthorityKey,
        sign: &dyn Fn(&[u8]) -> Result<Vec<u8>>,
        body: RecoveryHold,
        now: u64,
    ) -> Result<AuthorityEntryHash> {
        let fold = self.authority_view_readonly_in_txn(txn)?;
        let vault_id = fold.vault_id.ok_or_else(invalid_authority)?;
        let joiner = FrontierSigner::Callback(root_key, sign);
        let fold = self
            .prepare_authority_frontier_in_txn(txn, &fold, joiner, MAX_PARENTS)?
            .unwrap_or(fold);
        let parents = fold.append_heads.clone();
        if parents.is_empty() {
            return Err(invalid_authority());
        }
        if parents.len() > MAX_PARENTS {
            return Err(authority_refused(HOLD_TOO_MANY_HEADS));
        }
        let mut entry = AuthorityLogEntry {
            schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
            vault_id: Some(vault_id),
            seq: next_sequence(&fold, root_key)?,
            parent_hashes: parents.into_iter().collect(),
            op: AuthorityOp::RecoveryHold(body),
            signer: AuthoritySignature {
                suite: root_key.suite(),
                public_key: root_key.clone(),
                signature: vec![0; 64],
            },
            cosigns: Vec::new(),
            ts: now,
        };
        entry.validate_shape().map_err(|_| invalid_authority())?;
        entry.signer.signature = sign(&authority_transcript(&entry)?)?;
        let hash = authority_entry_hash(&entry)?;
        let at = TimeRange {
            start: now,
            end: now,
        };
        self.put_authority_log_entries_in_txn(txn, &[(entry, at, now)])?;
        let after = self.authority_view_readonly_in_txn(txn)?;
        if !after.valid_entries.contains(&hash) || after.install.held_back.contains(&hash) {
            return Err(authority_refused(HOLD_NOT_COUNTED));
        }
        Ok(hash)
    }

    /// One `RecoveryHoldAnswer` row in the caller's write transaction,
    /// signed by `key` through `sign`: the frontier join when the frontier
    /// is wide, the main-log heads as parents, the signer's next sequence,
    /// the stamped `now`. Answers the answer's hash once this install's
    /// fold counts it. The caller commits.
    ///
    /// # Errors
    /// An all-zero or over-wide write; an entry the fold does not count;
    /// the log's.
    pub(crate) fn append_recovery_hold_answer_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        key: &AuthorityKey,
        sign: &dyn Fn(&[u8]) -> Result<Vec<u8>>,
        body: RecoveryHoldAnswer,
        now: u64,
    ) -> Result<AuthorityEntryHash> {
        let fold = self.authority_view_readonly_in_txn(txn)?;
        let vault_id = fold.vault_id.ok_or_else(invalid_authority)?;
        let joiner = FrontierSigner::Callback(key, sign);
        let fold = self
            .prepare_authority_frontier_in_txn(txn, &fold, joiner, MAX_PARENTS)?
            .unwrap_or(fold);
        let parents = fold.append_heads.clone();
        if parents.is_empty() {
            return Err(invalid_authority());
        }
        if parents.len() > MAX_PARENTS {
            return Err(authority_refused(ANSWER_TOO_MANY_HEADS));
        }
        let mut entry = AuthorityLogEntry {
            schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
            vault_id: Some(vault_id),
            seq: next_sequence(&fold, key)?,
            parent_hashes: parents.into_iter().collect(),
            op: AuthorityOp::RecoveryHoldAnswer(body),
            signer: AuthoritySignature {
                suite: key.suite(),
                public_key: key.clone(),
                signature: vec![0; 64],
            },
            cosigns: Vec::new(),
            ts: now,
        };
        entry.validate_shape().map_err(|_| invalid_authority())?;
        entry.signer.signature = sign(&authority_transcript(&entry)?)?;
        let hash = authority_entry_hash(&entry)?;
        let at = TimeRange {
            start: now,
            end: now,
        };
        self.put_authority_log_entries_in_txn(txn, &[(entry, at, now)])?;
        let after = self.authority_view_readonly_in_txn(txn)?;
        if !after.valid_entries.contains(&hash) || after.install.held_back.contains(&hash) {
            return Err(authority_refused(ANSWER_NOT_COUNTED));
        }
        Ok(hash)
    }

    /// An anchor-signed `Cancel` for each of `holds`, in the caller's write
    /// transaction, before its rows: the kit's cancel (W3). Each answer
    /// names the main-log heads and the anchor's own, takes the anchor's
    /// next sequence, carries R's cosign beside the anchor (`r`, the kit's
    /// live root key: the hold view counts the Cancel only for a hold R
    /// signed), and must count, or nothing commits. Answers the
    /// answers' hashes in `holds`' order.
    ///
    /// # Errors
    /// An entry the fold does not count; the log's.
    pub(crate) fn append_anchor_cancels_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        anchor: &SigningKey,
        r: &RecoveryAuthoritySigner,
        holds: &[AuthorityEntryHash],
    ) -> Result<Vec<AuthorityEntryHash>> {
        let mut answers = Vec::with_capacity(holds.len());
        for hold in holds {
            let fold = self.authority_view_readonly_in_txn(txn)?;
            let fold = self
                .join_anchor_frontier_in_txn(txn, &fold, anchor)?
                .unwrap_or(fold);
            let now = self.instant_in_txn(txn)?.secs();
            let mut entry = anchor_signed_entry(
                &fold,
                anchor,
                AuthorityOp::RecoveryHoldAnswer(RecoveryHoldAnswer {
                    hold: *hold,
                    answer: RecoveryHoldAnswerKind::Cancel,
                }),
                now,
            )?;
            // R's cosign beside the anchor's, over the one transcript both
            // sign (row CARRIER-OWNER-PROOF's shape): the key goes in before
            // either signature, so the anchor signs again over it.
            let r_key = r.authority_key();
            entry.cosigns.push(AuthoritySignature {
                suite: r_key.suite(),
                public_key: r_key,
                signature: vec![0; 64],
            });
            let transcript = authority_transcript(&entry)?;
            entry.cosigns[0].signature = r.sign_authority_transcript(&transcript)?;
            entry.signer.signature = anchor.sign(&transcript).to_bytes().to_vec();
            let hash = self.put_anchor_entry_in_txn(txn, entry)?;
            let after = self.authority_view_readonly_in_txn(txn)?;
            if !after.valid_entries.contains(&hash) || after.install.held_back.contains(&hash) {
                return Err(authority_refused(KIT_CANCEL_NOT_COUNTED));
            }
            answers.push(hash);
        }
        Ok(answers)
    }
}

/// What one landing run did with one hold of this install.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryHoldLanding {
    /// The hold's entry hash: the attempt id.
    pub hold: AuthorityEntryHash,
    /// What the hold is after this run: `Landed` for a write and for a
    /// successor already on the roster, `Cancelled` and `Void` for a slot
    /// cleaned without a write (`Void` also when the held owner is gone:
    /// it never lands).
    pub state: RecoveryHoldState,
    /// The landing's enrolment, for a write.
    pub enrollment: Option<OwnerKeyEnrollmentReceipt>,
    /// The landing's revocations, in the order written, for a write.
    pub revoked: Vec<AuthorityEntryHash>,
}

/// One owner key this install holds: a signer on the handle, or the key in
/// this install's owner signing slot.
enum AnswerKey {
    /// A signer this handle holds.
    Held(Arc<dyn CheckpointRootSigner>),
    /// This install's owner signing key, read without creating it.
    Slot(OwnerRootSigner),
}

impl AnswerKey {
    /// The key's owner proof over an answer's transcript.
    fn sign(&self, transcript: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::Held(signer) => signer.sign_owner_proof(transcript),
            Self::Slot(signer) => signer.sign_owner_proof(transcript),
        }
    }
}

impl Vault {
    /// Lands this install's due recovery holds, one writer transaction per
    /// hold: a hold whose seed slot is here. In the transaction the hold is
    /// folded again on this install's clock: Due (by this install's own
    /// `instant_in_txn`, or an `ItIsMe`) with R and the held owner live
    /// revokes each lost key still live and then enrols the held input
    /// (predecessor R, kind `Device`), all signed by R from the slot, as
    /// the root door's vouch orders them (a self-hosted owner whose lost
    /// key held their binding is bound again by the enrolment), marks the
    /// rows for the live mirror, commits, announces them, then deletes the
    /// slot. `Cancelled`, `Void` and a successor already on the roster
    /// delete the slot and its pending record, while this run's writer is
    /// held, and report the state; they write no authority row. `Waiting`
    /// is nothing. A terminal hold whose successor a waiting or due retry
    /// names leaves the slot to that retry and is not reported. A hold with
    /// no row here keeps its slot: its write may still be committing. With
    /// no keystore installed no slot is here, so the run lands nothing;
    /// with no hold and no pending slot record it writes nothing at all.
    /// Before any of that, one sweep reaps the seed slots a crash orphaned:
    /// for each pending slot record, a slot that holds no seed loses its
    /// record, and a seed no hold names is deleted with its record (the
    /// door puts its seed again when a run reaped it before the door's
    /// hold committed). The root door's box arm calls it first; the
    /// host's poll of a waiting recovery calls it too (the keystore is
    /// installed after each open, so an open never lands).
    ///
    /// # Errors
    /// A hold's write that the fold does not count; the store's, the
    /// clock's and the keystore's.
    pub fn land_due_recovery_holds(&self) -> Result<Vec<RecoveryHoldLanding>> {
        match self.device_keystore() {
            Ok(_) => {}
            Err(Error::Secret(SecretError::KeystoreUnavailable(_))) => return Ok(Vec::new()),
            Err(other) => return Err(other),
        }
        let (vault_id, views, pending) = {
            let txn = self.store.env.read_txn()?;
            let fold = self.authority_view_readonly_in_txn(&txn)?;
            let vault_id = fold.vault_id.ok_or_else(invalid_authority)?;
            (
                vault_id,
                self.recovery_holds_in_txn(&txn)?,
                self.recovery_hold_slots_pending_in_txn(&txn)?,
            )
        };
        if views.is_empty() && pending.is_empty() {
            return Ok(Vec::new());
        }
        let machine = self.prepare_install_signing()?;
        // The orphan sweep: a seed the door put before a crash left a
        // pending record and no hold. Under one write transaction, a record
        // whose slot holds no seed is dropped; one whose seed no hold
        // (stored or carried, any state) names is deleted with its record;
        // a hold's own slot is left for the landing loop below. It commits
        // only when it reaped something.
        if !pending.is_empty() {
            let mut sweep = self.store.env.write_txn()?;
            let fold = self.authority_view_readonly_in_txn(&sweep)?;
            let vault_id = fold.vault_id.ok_or_else(invalid_authority)?;
            let named: BTreeSet<[u8; 32]> = self
                .recovery_holds_in_txn(&sweep)?
                .into_iter()
                .filter_map(|view| match view.successor_key {
                    AuthorityKey::Ed25519(successor) => Some(successor),
                    _ => None,
                })
                .collect();
            let mut reaped = false;
            for successor in &pending {
                let slot = self.recovery_hold_slot(&vault_id, machine, successor);
                if self.read_recovery_hold_seed(&slot)?.is_none() {
                    self.drop_recovery_hold_slot_pending_in_txn(&mut sweep, successor)?;
                    reaped = true;
                } else if !named.contains(successor) {
                    self.delete_recovery_hold_seed(&slot)?;
                    self.drop_recovery_hold_slot_pending_in_txn(&mut sweep, successor)?;
                    reaped = true;
                }
            }
            if reaped {
                sweep.commit()?;
            }
        }
        let mut landings = Vec::new();
        for view in views {
            let AuthorityKey::Ed25519(successor) = view.successor_key else {
                continue;
            };
            let slot = self.recovery_hold_slot(&vault_id, machine, &successor);
            let Some(seed) = self.read_recovery_hold_seed(&slot)? else {
                continue;
            };
            let mut txn = self.store.env.write_txn()?;
            let in_txn = self.recovery_holds_in_txn(&txn)?;
            let Some(state) = in_txn
                .iter()
                .find(|found| found.hold == view.hold)
                .map(|found| found.state)
            else {
                continue;
            };
            // A retry for the same successor owns the seed slot now: only a
            // terminal hold with no live attempt for its successor cleans
            // it.
            let retry_owns = in_txn.iter().any(|found| {
                found.hold != view.hold
                    && matches!(
                        found.state,
                        RecoveryHoldState::Waiting | RecoveryHoldState::Due
                    )
                    && found.successor_key == view.successor_key
            });
            match state {
                RecoveryHoldState::Waiting => {}
                RecoveryHoldState::Landed
                | RecoveryHoldState::Cancelled
                | RecoveryHoldState::Void => {
                    // The retry owns the slot: nothing here is this hold's
                    // to clean, and the retry reports for itself.
                    if retry_owns {
                        continue;
                    }
                    // The slot goes while this writer is held, so no hold
                    // naming it commits between the read above and the
                    // delete; the record goes after its slot.
                    self.delete_recovery_hold_seed(&slot)?;
                    self.drop_recovery_hold_slot_pending_in_txn(&mut txn, &successor)?;
                    txn.commit()?;
                    landings.push(RecoveryHoldLanding {
                        hold: view.hold,
                        state,
                        enrollment: None,
                        revoked: Vec::new(),
                    });
                    continue;
                }
                RecoveryHoldState::Due => {
                    let history = super::history_transfer::history_in_txn(self, &txn)?;
                    let evidence =
                        super::adopted_evidence::adopted_evidence_in_txn(&self.store, &txn)?;
                    let row = match history.get(&view.hold) {
                        Some((_, row)) => row,
                        None => match evidence.as_deref().and_then(|held| held.body(&view.hold)) {
                            Some(row) => row,
                            None => continue,
                        },
                    };
                    let AuthorityOp::RecoveryHold(hold) = &row.op else {
                        continue;
                    };
                    let root_key = row.signer_key().clone();
                    let fold = self.authority_view_readonly_in_txn(&txn)?;
                    let root_live = fold
                        .roster
                        .get(&root_key)
                        .is_some_and(|device| !device.revoked);
                    let owner_live =
                        crate::consent::person_is_live_in_txn(self, &txn, &hold.owner)?
                            && crate::policy_model::is_live_vault_owner_in_txn(
                                self,
                                &txn,
                                &hold.owner,
                            )?;
                    if !root_live || !owner_live {
                        // As in the terminal arms above.
                        if retry_owns {
                            continue;
                        }
                        self.delete_recovery_hold_seed(&slot)?;
                        self.drop_recovery_hold_slot_pending_in_txn(&mut txn, &successor)?;
                        txn.commit()?;
                        landings.push(RecoveryHoldLanding {
                            hold: view.hold,
                            state: RecoveryHoldState::Void,
                            enrollment: None,
                            revoked: Vec::new(),
                        });
                        continue;
                    }
                    let mut sign_enrolment = |transcript: &[u8]| {
                        RecoveryAuthoritySigner::sign_transcript_with_seed(&seed, transcript)
                    };
                    let sign_revoke = |transcript: &[u8]| {
                        RecoveryAuthoritySigner::sign_transcript_with_seed(&seed, transcript)
                    };
                    // The lost keys go first, as at the root door's vouch: the
                    // enrolment binds a self-hosted owner whose lost key held
                    // their binding.
                    let mut revoked = Vec::with_capacity(hold.lost.len());
                    for key in &hold.lost {
                        let live = fold.roster.get(key).is_some_and(|device| !device.revoked);
                        if !live {
                            continue;
                        }
                        let signer = EntrySigner::Key(&root_key, &sign_revoke);
                        revoked.push(self.append_revoke_device_in_txn(
                            &mut txn,
                            signer,
                            key.clone(),
                        )?);
                    }
                    let enrollment = self.enrol_owner_signing_key_for_actor_in_txn(
                        &mut txn,
                        hold.owner,
                        ActSurface::ThisInstall,
                        OwnerKeyEnrollment {
                            machine: hold.enrolment.machine,
                            public_key: hold.enrolment.public_key,
                            proof: hold.enrolment.proof.clone(),
                        },
                        EnrolledOwnerKeyKind::Device,
                        root_key.clone(),
                        &mut sign_enrolment,
                    )?;
                    let rows = self.mark_authority_rows_counted_since_in_txn(&mut txn, &fold)?;
                    txn.commit()?;
                    self.note_committed_authority_rows(rows);
                    self.delete_recovery_hold_seed(&slot)?;
                    let mut cleanup = self.store.env.write_txn()?;
                    self.drop_recovery_hold_slot_pending_in_txn(&mut cleanup, &successor)?;
                    cleanup.commit()?;
                    landings.push(RecoveryHoldLanding {
                        hold: view.hold,
                        state: RecoveryHoldState::Landed,
                        enrollment: Some(enrollment),
                        revoked,
                    });
                    continue;
                }
            }
            drop(txn);
        }
        Ok(landings)
    }

    /// Answers the live recovery hold `hold` with `answer`, signed by this
    /// install's held live owner key: the device unlock is the confirm
    /// sheet, and the surface stays audit-only. The key is any key this
    /// install holds that may answer ([`answers_recovery_holds`]: a live
    /// owner device key, never an admin's or a host's), is not the hold's
    /// successor and is not the root's authority kind; R's held seed
    /// answers nothing. The answer is marked for the live mirror and
    /// announced, so the door install sees it at the next mirror pass. An
    /// unknown hold is [`HOLD_NOT_LIVE`]; a terminal one too, once no held
    /// key speaks for it first.
    ///
    /// # Errors
    /// [`crate::error::RecordError::AuthorityRefused`] for an agent's act, a
    /// hold that is not live, a held key that is the successor or the root's
    /// key, and this install holding no live owner key; an answer the fold
    /// does not count; the store's, the clock's and the keystore's.
    pub fn answer_recovery_hold_as(
        &self,
        authority: &ActAuthority,
        hold: AuthorityEntryHash,
        answer: RecoveryHoldAnswerKind,
    ) -> Result<()> {
        let owner = match authority {
            ActAuthority::Owner(owner, _) => owner,
            ActAuthority::Agent(_) => return Err(authority_refused(ANSWER_OWNER_ONLY)),
        };
        let machine = self.prepare_install_signing()?;
        let mut candidates: Vec<(AuthorityKey, AnswerKey)> = self
            .checkpoint_root_signers()
            .into_iter()
            .map(|signer| (signer.root(), AnswerKey::Held(signer)))
            .collect();
        if let Some(slot) = self.existing_device_owner_signing_key()? {
            let key = AuthorityKey::Ed25519(slot.public_key());
            if !candidates.iter().any(|(held, _)| *held == key) {
                candidates.push((key, AnswerKey::Slot(slot)));
            }
        }
        let mut txn = self.store.env.write_txn()?;
        owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
        let view = self
            .recovery_holds_in_txn(&txn)?
            .into_iter()
            .find(|found| found.hold == hold)
            .ok_or_else(|| authority_refused(HOLD_NOT_LIVE))?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        let vault_id = fold.vault_id.ok_or_else(invalid_authority)?;
        let enrolled = self.enrolled_owner_keys_in_txn(&txn)?;
        let live_owner =
            |key: &AuthorityKey| fold.roster.get(key).is_some_and(answers_recovery_holds);
        let is_root_kind = |key: &AuthorityKey| {
            enrolled.iter().any(|listed| {
                AuthorityKey::Ed25519(listed.public_key) == *key
                    && listed.kind == EnrolledOwnerKeyKind::RecoveryAuthority
            })
        };
        let answered = candidates
            .iter()
            .find(|(key, _)| *key != view.successor_key && !is_root_kind(key) && live_owner(key));
        let Some((key, answered)) = answered else {
            if candidates.iter().any(|(key, _)| *key == view.successor_key) {
                return Err(authority_refused(ANSWER_KEY_IS_SUCCESSOR));
            }
            let AuthorityKey::Ed25519(successor) = view.successor_key else {
                return Err(invalid_authority());
            };
            let slot = self.recovery_hold_slot(&vault_id, machine, &successor);
            let holds_root = candidates.iter().any(|(key, _)| is_root_kind(key))
                || self.read_recovery_hold_seed(&slot)?.is_some();
            if holds_root {
                return Err(authority_refused(ANSWER_KEY_IS_ROOT));
            }
            return Err(authority_refused(NO_OWNER_KEY));
        };
        if !matches!(
            view.state,
            RecoveryHoldState::Waiting | RecoveryHoldState::Due
        ) {
            return Err(authority_refused(HOLD_NOT_LIVE));
        }
        let now = self.instant_in_txn(&txn)?.secs();
        let sign = |transcript: &[u8]| answered.sign(transcript);
        self.append_recovery_hold_answer_in_txn(
            &mut txn,
            key,
            &sign,
            RecoveryHoldAnswer { hold, answer },
            now,
        )?;
        let rows = self.mark_authority_rows_counted_since_in_txn(&mut txn, &fold)?;
        txn.commit()?;
        self.note_committed_authority_rows(rows);
        Ok(())
    }

    /// Cancels the live recovery hold `hold`, or every live hold when none
    /// is named, with the vault's anchor from the kit `pieces` rebuild
    /// (with `passphrase` when the kit takes one): the kit stops the
    /// attempt. A kit cancels only the live holds its live root key R
    /// signed: cancelling every hold skips another root's holds, and a
    /// named hold another key signed is refused. With no live R from the
    /// kit, cancelling every hold cancels nothing. One write transaction;
    /// cancelling nothing is no refusal.
    ///
    /// # Errors
    /// [`crate::error::RecordError::AuthorityRefused`] for an agent's act,
    /// unreadable kit pieces, a named hold that is not live, and a named
    /// hold this kit's root key did not sign; a cancellation the fold does
    /// not count; the store's and the clock's.
    pub fn cancel_recovery_holds_with_kit_as(
        &self,
        authority: &ActAuthority,
        pieces: &[&KitPiece],
        passphrase: Option<&KitPassphrase>,
        hold: Option<AuthorityEntryHash>,
    ) -> Result<()> {
        let owner = match authority {
            ActAuthority::Owner(owner, _) => owner,
            ActAuthority::Agent(_) => return Err(authority_refused(ANSWER_OWNER_ONLY)),
        };
        let vault_id = {
            let txn = self.store.env.read_txn()?;
            self.authority_view_readonly_in_txn(&txn)?
                .vault_id
                .ok_or_else(invalid_authority)?
        };
        let secret =
            crate::recovery::restore_kit(vault_id, KitSecretKind::RecoveryRoot, pieces, passphrase)
                .map_err(|_| authority_refused(KIT_PIECES_UNREADABLE))?;
        let seed = crate::world_keys::RecoveryRootSeed::from_restored_kit(secret)?;
        let anchor = seed.anchor();
        let mut txn = self.store.env.write_txn()?;
        owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
        let views = self.recovery_holds_in_txn(&txn)?;
        let live = |state: RecoveryHoldState| {
            matches!(state, RecoveryHoldState::Waiting | RecoveryHoldState::Due)
        };
        let live_r = self
            .recovery_authority_generations_in_txn(&txn, &seed, &vault_id)?
            .live
            .map(|(_, signer)| signer);
        let targets: Vec<AuthorityEntryHash> = match hold {
            Some(named) => {
                let view = views
                    .into_iter()
                    .find(|found| found.hold == named)
                    .ok_or_else(|| authority_refused(HOLD_NOT_LIVE))?;
                if !live(view.state) {
                    return Err(authority_refused(HOLD_NOT_LIVE));
                }
                let Some(r) = &live_r else {
                    return Err(authority_refused(KIT_ROOT_NOT_HOLD_SIGNER));
                };
                if view.root_key != r.authority_key() {
                    return Err(authority_refused(KIT_ROOT_NOT_HOLD_SIGNER));
                }
                vec![named]
            }
            None => match &live_r {
                Some(r) => {
                    let r_key = r.authority_key();
                    views
                        .into_iter()
                        .filter(|found| live(found.state) && found.root_key == r_key)
                        .map(|found| found.hold)
                        .collect()
                }
                None => Vec::new(),
            },
        };
        let before = self.authority_view_readonly_in_txn(&txn)?;
        if !targets.is_empty() {
            let Some(r) = &live_r else {
                return Err(authority_refused(KIT_ROOT_NOT_HOLD_SIGNER));
            };
            self.append_anchor_cancels_in_txn(&mut txn, &anchor, r, &targets)?;
        }
        let rows = self.mark_authority_rows_counted_since_in_txn(&mut txn, &before)?;
        txn.commit()?;
        self.note_committed_authority_rows(rows);
        Ok(())
    }
}
