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

use ed25519_dalek::SigningKey;
use oneiron_keystore::{DeviceKeystore, KeystoreError, KeystoreSlot, SlotKind};
use zeroize::Zeroizing;

use super::owner_key_enrollment_door::EntrySigner;
use super::*;
use crate::error::{Error, SecretError};
use crate::side_table::{self, Raw, SideTable};
use crate::store::recovery_kit::{KitPassphrase, KitPiece, KitSecretKind};
use crate::world_keys::{OwnerRootSigner, RecoveryAuthoritySigner, keystore_error};
use crate::{EntityId, Result, TimeRange, Vault};

mod answers;
mod landing;

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

/// An answer's signer, judged at the parents' state, with no cosign: a live
/// owner device key that is not R, or, for a `Cancel` only, a live R (the
/// kit's). The kit acts through R like any owner key, and an anchor is no
/// voice in a shared judge (lead ANCHORS-3 = A; Fable pass 29, ANCHORS-E6):
/// the hold view counts R's Cancel only for a hold that R signed. R never
/// says `ItIsMe`: the box releases R, so that answer would end the wait for
/// the attacker. R's Cancel gives the box's release nothing it lacks: R
/// alone already voids its holds by revoking itself, and a direct R holder
/// is outside the wait (WAYBACK-WAIT-PLACEMENT = A). Nor does an admin's key
/// or a host's answer ([`answers_recovery_holds`]): the generic consent rule
/// admits both, and either answer would end or stop an owner's wait with no
/// owner device (WAYBACK-7: no staff override).
pub(super) fn judge_recovery_hold_answer(
    state: &FoldState,
    entry: &AuthorityLogEntry,
    hash: AuthorityEntryHash,
) -> std::result::Result<(), AuthorityFoldIssue> {
    if !entry.cosigns.is_empty() {
        return Err(AuthorityFoldIssue::InvalidEntry(hash));
    }
    if state.recovery_authority_keys.contains(entry.signer_key()) {
        let cancel = matches!(
            &entry.op,
            AuthorityOp::RecoveryHoldAnswer(answer)
                if answer.answer == RecoveryHoldAnswerKind::Cancel
        );
        let live = state
            .roster
            .get(entry.signer_key())
            .is_some_and(|device| !device.revoked);
        return match (cancel, live) {
            (true, true) => Ok(()),
            (true, false) => Err(AuthorityFoldIssue::MissingAuthorityConsent(hash)),
            (false, _) => Err(AuthorityFoldIssue::InvalidEntry(hash)),
        };
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

/// The rows the hold view reads off the counted log: each hold with its
/// signer R, each answer with its kind and signer, and every key a valid
/// enrolment made a recovery root's authority key (the fold's own memory of
/// the R keys), which tells the kit's Cancel from an owner device's.
#[derive(Default)]
struct HoldRows {
    holds: Vec<(AuthorityEntryHash, RecoveryHold, AuthorityKey)>,
    answers: BTreeMap<AuthorityEntryHash, Vec<(RecoveryHoldAnswerKind, AuthorityKey)>>,
    root_keys: BTreeSet<AuthorityKey>,
}

impl HoldRows {
    fn read(&mut self, hash: AuthorityEntryHash, entry: &AuthorityLogEntry) {
        match &entry.op {
            AuthorityOp::RecoveryHold(hold) => {
                self.holds
                    .push((hash, hold.clone(), entry.signer_key().clone()));
            }
            AuthorityOp::RecoveryHoldAnswer(answer) => {
                self.answers
                    .entry(answer.hold)
                    .or_default()
                    .push((answer.answer, entry.signer_key().clone()));
            }
            AuthorityOp::OwnerKeyEnroll(enroll) if enroll.is_recovery_authority() => {
                self.root_keys.insert(enroll.device.key.clone());
            }
            _ => {}
        }
    }
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
    /// seed the landing signs with. An R-signed Cancel (the kit's) counts for
    /// this hold only when this R signed it; another root's R is inert here.
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
    /// ascending, each once: an owner device key's answers, and this hold's
    /// signer R for the kit's Cancel (another root's R is inert, and leaves
    /// no name here).
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
    /// for the hold (an owner device key's, or the kit's, which this hold's
    /// signer R signs; another root's R is inert, and an ItIsMe never
    /// revives one), else Void when the hold's signer R is no longer live,
    /// else Due on a valid ItIsMe or when this reader's
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
        let mut rows = HoldRows::default();
        let mut stored = BTreeSet::new();
        for (hash, (_, entry)) in &history {
            stored.insert(*hash);
            if !fold.valid_entries.contains(hash) {
                continue;
            }
            rows.read(*hash, entry);
        }
        if let Some(evidence) = super::adopted_evidence::adopted_evidence_in_txn(&self.store, txn)?
        {
            for (hash, entry) in evidence.carried_past(&stored) {
                if !fold.valid_entries.contains(hash) {
                    continue;
                }
                rows.read(*hash, entry);
            }
        }
        let HoldRows {
            holds,
            answers,
            root_keys,
        } = rows;
        let mut views: Vec<RecoveryHoldView> = holds
            .into_iter()
            .map(|(hash, hold, signer)| {
                let successor_key = hold.successor_key();
                let named = answers.get(&hash);
                // A Cancel counts for this hold when an owner device key
                // signed it, or when this hold's signer R did (the kit's
                // Cancel). Another root's R is inert for this hold. The fold
                // refused an ItIsMe that any R signs.
                let counts = |kind: RecoveryHoldAnswerKind, answerer: &AuthorityKey| {
                    kind == RecoveryHoldAnswerKind::ItIsMe
                        || !root_keys.contains(answerer)
                        || *answerer == signer
                };
                let cancelled = named.is_some_and(|list| {
                    list.iter().any(|(kind, answerer)| {
                        *kind == RecoveryHoldAnswerKind::Cancel && counts(*kind, answerer)
                    })
                });
                let affirmed = named.is_some_and(|list| {
                    list.iter()
                        .any(|(kind, _)| *kind == RecoveryHoldAnswerKind::ItIsMe)
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
                        .filter(|(kind, answerer)| counts(*kind, answerer))
                        .map(|(_, answerer)| answerer.clone())
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
/// The root's authority key never answers at this door: the box released
/// it, so its ItIsMe would end the wait for the attacker, and the kit
/// cancels through R at its own door. Another owner device answers. Nothing
/// was written.
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

    /// R's own `Cancel` for each of `holds`, in the caller's write
    /// transaction, before its rows: the kit's cancel (W3). The kit acts
    /// through R like any owner key (lead ANCHORS-3 = A): each answer is a
    /// roster row `r`, the kit's live root key, signs alone
    /// ([`Self::append_recovery_hold_answer_in_txn`]); the hold view counts
    /// it only for a hold R signed. Each must count, or nothing commits.
    /// Answers the answers' hashes in `holds`' order.
    ///
    /// # Errors
    /// An entry the fold does not count; the log's and the clock's.
    pub(crate) fn append_root_key_cancels_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        r: &RecoveryAuthoritySigner,
        holds: &[AuthorityEntryHash],
    ) -> Result<Vec<AuthorityEntryHash>> {
        let r_key = r.authority_key();
        let sign = |transcript: &[u8]| r.sign_authority_transcript(transcript);
        let mut answers = Vec::with_capacity(holds.len());
        for hold in holds {
            let now = self.instant_in_txn(txn)?.secs();
            answers.push(self.append_recovery_hold_answer_in_txn(
                txn,
                &r_key,
                &sign,
                RecoveryHoldAnswer {
                    hold: *hold,
                    answer: RecoveryHoldAnswerKind::Cancel,
                },
                now,
            )?);
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
