//! A box recovery's wait (OPUS-WAYBACK): the fold's judgement of the hold
//! rows, the hold view, the wait, the landing and the answers (Engine RULING
//! WAYBACK-RECOVERY-HOLD-WIRE = A).
//!
//! After a box recovery the root's door holds the vouch instead of writing
//! it: one [`RecoveryHold`] signed by R, judged here, read by
//! [`Vault::recovery_holds_in_txn`], landed lazily by
//! [`Vault::land_due_recovery_holds`], and answered by owner devices, an
//! owner's passkey (a Cancel alone, in two steps: `passkey_cancel`) and the
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
mod box_cancel;
mod hold_view;
mod landing;
mod passkey_cancel;

pub use box_cancel::RecoveryBoxCancelProof;
pub use hold_view::{RecoveryHoldState, RecoveryHoldView};
pub use passkey_cancel::PreparedRecoveryHoldCancel;

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
/// owner device (WAYBACK-7: no staff override). Whose `ItIsMe` ends a wait
/// is the hold view's rule, not this judge's: the fold counts a co-owner's
/// `ItIsMe` row, and the view gives it no weight (`hold_view::key_is_the_owners`).
/// An owner's passkey answers here as any owner key does, with a `Cancel`
/// alone (the shape check refuses its `ItIsMe`; row
/// RECOVERY-HOLD-PASSKEY-ANSWER), its assertion made where its enrollment
/// pinned it (the generic passkey context rule).
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

/// The `RecoveryHoldAnswer` entry `key` signs for `body` on vault
/// `vault_id`: `fold`'s main-log heads as parents, `key`'s next sequence,
/// the stamp `now`, no cosign, and a zero signature until the signer's goes
/// in. The one shape both answer doors write.
///
/// # Errors
/// No heads, or more than one entry may name.
fn unsigned_recovery_hold_answer(
    vault_id: AuthorityVaultId,
    fold: &AuthorityFold,
    key: &AuthorityKey,
    body: RecoveryHoldAnswer,
    now: u64,
) -> Result<AuthorityLogEntry> {
    let parents = fold.append_heads.clone();
    if parents.is_empty() {
        return Err(invalid_authority());
    }
    if parents.len() > MAX_PARENTS {
        return Err(authority_refused(ANSWER_TOO_MANY_HEADS));
    }
    Ok(AuthorityLogEntry {
        schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id: Some(vault_id),
        seq: next_sequence(fold, key)?,
        parent_hashes: parents.into_iter().collect(),
        op: AuthorityOp::RecoveryHoldAnswer(body),
        signer: AuthoritySignature {
            suite: key.suite(),
            public_key: key.clone(),
            signature: vec![0; 64],
        },
        cosigns: Vec::new(),
        ts: now,
        overlay_seed: None,
    })
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
/// Another owner's recovery hold for the same successor key is live: a
/// successor key is held for one owner at a time, and that hold keeps its
/// seed. Nothing was written.
const ANOTHER_OWNERS_HOLD: &str = "another owner's recovery waits for this successor key; \
                                   nothing was written";
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
/// Only the owner whose recovery it is says it is them: a co-owner's
/// "it is me" never ends another owner's wait, though a co-owner may cancel
/// it (WAYBACK-COOWNER-CANCEL-OTHER-OWNERS-RECOVERY = B). Nothing was
/// written.
const ANSWER_NOT_HOLD_OWNER: &str = "only the owner whose recovery this is says it is them; \
                                      another owner may cancel it; nothing was written";
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
    /// write); one that holds another R's gives way. The root door calls it
    /// under the vault's recovery-hold lock, once
    /// [`Self::live_hold_for_successor_in_txn`] found no live hold whose R
    /// the kept seed is, so the seed it replaces is no live hold's. An empty
    /// slot is not an error at the delete below.
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

    /// Whether `owner` may still land a recovery hold of theirs: a live
    /// person who is a live owner of this vault. The landing voids a due
    /// hold of anyone else, and [`Self::live_hold_for_successor_in_txn`]
    /// counts no such hold as live.
    ///
    /// # Errors
    /// The store's.
    fn recovery_hold_owner_is_live_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        owner: &EntityId,
    ) -> Result<bool> {
        Ok(crate::consent::person_is_live_in_txn(self, txn, owner)?
            && crate::policy_model::is_live_vault_owner_in_txn(self, txn, owner)?)
    }

    /// This install's live hold for `successor`, Waiting or Due, of
    /// `owner`, the owner who acts: the attempt id, its landing second, and
    /// whether the seed slot keeps that hold's own R. A successor key is
    /// held for one owner at a time: while another owner's hold for it is
    /// live, the call is refused and that hold keeps its seed (row
    /// RECOVERY-HOLD-BOX-PATH-WRITES-BEFORE-CHECKS). A hold whose owner is
    /// no live owner of this vault now is not live here, as the landing
    /// voids it (`recovery_hold_owner_is_live_in_txn`; REVIEW-10327 round 2
    /// P1 2), so it never stands in a live owner's way. The landing signs
    /// only with a hold's own R, so a hold whose slot keeps another seed
    /// never lands from here. A hold whose R the kept seed is comes first; else,
    /// while the slot keeps another seed, one that `root` (the caller's R)
    /// signed, whose seed a racing attempt replaced before the door held
    /// the recovery-hold lock: the door puts R's seed back and answers it.
    /// With neither, the kept seed is no live hold's, and a new attempt may
    /// replace it; an empty slot answers no hold, as before.
    ///
    /// # Errors
    /// [`crate::error::RecordError::AuthorityRefused`] while another
    /// owner's hold for `successor` is live; the log's, the clock's and the
    /// keystore's.
    pub(crate) fn live_hold_for_successor_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        machine: EntityId,
        successor: &[u8; 32],
        root: &AuthorityKey,
        owner: EntityId,
    ) -> Result<Option<(AuthorityEntryHash, u64, bool)>> {
        let fold = self.authority_view_readonly_in_txn(txn)?;
        let vault_id = fold.vault_id.ok_or_else(invalid_authority)?;
        let wanted = AuthorityKey::Ed25519(*successor);
        let mut live: Vec<RecoveryHoldView> = Vec::new();
        for view in self.recovery_holds_in_txn(txn)? {
            if view.successor_key == wanted
                && matches!(
                    view.state,
                    RecoveryHoldState::Waiting | RecoveryHoldState::Due
                )
                && self.recovery_hold_owner_is_live_in_txn(txn, &view.owner)?
            {
                live.push(view);
            }
        }
        if live.is_empty() {
            return Ok(None);
        }
        if live.iter().any(|view| view.owner != owner) {
            return Err(authority_refused(ANOTHER_OWNERS_HOLD));
        }
        let slot = self.recovery_hold_slot(&vault_id, machine, successor);
        let kept = self.read_recovery_hold_seed(&slot)?.map(|seed| {
            AuthorityKey::Ed25519(SigningKey::from_bytes(&seed).verifying_key().to_bytes())
        });
        if let Some(view) = live
            .iter()
            .find(|view| kept.as_ref() == Some(&view.root_key))
        {
            return Ok(Some((view.hold, view.lands_at, true)));
        }
        if kept.is_none() {
            return Ok(None);
        }
        Ok(live
            .iter()
            .find(|view| view.root_key == *root)
            .map(|view| (view.hold, view.lands_at, false)))
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
            overlay_seed: None,
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
    /// the stamped `now`. `sign` takes the fold each entry is signed on, as
    /// an owner key's proof needs it: a join carries no op, so each join is
    /// signed on the fold before it, and the answer on the joined fold.
    /// Answers the answer's hash once this install's fold counts it. The
    /// caller commits.
    ///
    /// # Errors
    /// An all-zero or over-wide write; an entry the fold does not count;
    /// the log's.
    pub(crate) fn append_recovery_hold_answer_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        key: &AuthorityKey,
        sign: &dyn Fn(&AuthorityFold, &[u8]) -> Result<Vec<u8>>,
        body: RecoveryHoldAnswer,
        now: u64,
    ) -> Result<AuthorityEntryHash> {
        let fold = self.authority_view_readonly_in_txn(txn)?;
        let vault_id = fold.vault_id.ok_or_else(invalid_authority)?;
        let join_sign = |transcript: &[u8]| sign(&fold, transcript);
        let joiner = FrontierSigner::Callback(key, &join_sign);
        let joined = self.prepare_authority_frontier_in_txn(txn, &fold, joiner, MAX_PARENTS)?;
        let fold = joined.unwrap_or(fold);
        let mut entry = unsigned_recovery_hold_answer(vault_id, &fold, key, body, now)?;
        entry.validate_shape().map_err(|_| invalid_authority())?;
        entry.signer.signature = sign(&fold, &authority_transcript(&entry)?)?;
        self.put_recovery_hold_answer_in_txn(txn, entry)
    }

    /// Stores the signed answer `entry` in the caller's write transaction,
    /// at its own stamp, and answers its hash once this install's fold
    /// counts it. The caller commits.
    ///
    /// # Errors
    /// An entry the fold does not count; the log's.
    fn put_recovery_hold_answer_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        entry: AuthorityLogEntry,
    ) -> Result<AuthorityEntryHash> {
        let hash = authority_entry_hash(&entry)?;
        let now = entry.ts;
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
        let sign = |_: &AuthorityFold, transcript: &[u8]| r.sign_authority_transcript(transcript);
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
    /// The key's owner proof over an answer's transcript on `vault`, with
    /// the roster read from `fold`, the fold the entry is signed on, on
    /// `ground`, the person's confirm the answer door asked for: the key
    /// refuses where its owner proof refuses (a key off the live roster; a
    /// slot key under a device PIN or out of its slot).
    fn sign(
        &self,
        vault: &Vault,
        fold: &AuthorityFold,
        ground: &OwnerProofGround,
        transcript: &[u8],
    ) -> Result<Vec<u8>> {
        match self {
            Self::Held(signer) => signer.sign_owner_proof(vault, fold, ground, transcript),
            Self::Slot(signer) => signer.sign_owner_proof(vault, fold, ground, transcript),
        }
    }
}

impl Vault {
    /// Marks the rows `txn` counted since `before` for the live mirror, as
    /// the vouch writer does: the caller commits, then announces them with
    /// [`Self::note_committed_authority_rows`], so other owner devices see
    /// a hold, an answer or a landing at the next mirror pass.
    ///
    /// # Errors
    /// The log's and the mirror marks'.
    pub(super) fn mark_authority_rows_counted_since_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        before: &AuthorityFold,
    ) -> Result<BTreeSet<EntityId>> {
        let after = self.authority_view_readonly_in_txn(txn)?;
        let rows = super::root_recovery_door::authority_rows_counted_since(before, &after)?;
        self.mark_authority_rows_in_txn(txn, &rows)?;
        Ok(rows)
    }

    /// The kit's live root key R cancels every live hold R signed, in the
    /// caller's write transaction, before its rows (W3): a kit recovery lands
    /// over any hold, so an attacker's hold never lands after the owner's
    /// kit. Another root's holds are skipped (the kit holds no other root's
    /// key; such a hold voids when its key is revoked), and with no live R
    /// from the kit it cancels nothing. The anchor arm of this door needs
    /// none: with no live root key no hold is live, since a live hold's
    /// signer R is one.
    pub(super) fn cancel_live_holds_for_kit_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        seed: &crate::world_keys::RecoveryRootSeed,
    ) -> Result<()> {
        let vault_id = self
            .authority_view_readonly_in_txn(txn)?
            .vault_id
            .ok_or_else(invalid_authority)?;
        let Some((_, r)) = self
            .recovery_authority_generations_in_txn(txn, seed, &vault_id)?
            .live
        else {
            return Ok(());
        };
        let r_key = r.authority_key();
        let live: Vec<AuthorityEntryHash> = self
            .recovery_holds_in_txn(txn)?
            .into_iter()
            .filter(|view| {
                view.root_key == r_key
                    && matches!(
                        view.state,
                        RecoveryHoldState::Waiting | RecoveryHoldState::Due
                    )
            })
            .map(|view| view.hold)
            .collect();
        self.append_root_key_cancels_in_txn(txn, &r, &live)?;
        Ok(())
    }
}
