//! An owner's passkey cancels a recovery hold (row
//! RECOVERY-HOLD-PASSKEY-ANSWER): an owner whose only live owner key is a
//! browser passkey stops a box recovery's attempt, as an owner device does
//! with [`Vault::answer_recovery_hold_as`].
//!
//! The passkey signs in the owner's browser, so its Cancel is two steps, as
//! its vouch for a device key is ([`Vault::prepare_owner_key_enrollment_as`],
//! [`Vault::land_owner_key_enrollment_as`]): the engine builds the answer
//! entry with no signature and hands out the challenge its assertion names,
//! then lands the entry with the assertion as its one signature. A frontier
//! wider than one entry names is joined at prepare, signed by this install's
//! key, and the join is kept: the passkey signs the Cancel alone.
//!
//! A Cancel alone: an `ItIsMe` lands the hold's revocations of the owner's
//! other keys at once, and a passkey revokes no other owner key (Engine
//! ruling WEBPASSKEY-PASSKEY-OWN-REVOKE = B), so the shape check refuses a
//! passkey's `ItIsMe` and this door builds none. The fold judges the Cancel
//! as any answer (a live owner key, never an admin's or a host's), and the
//! generic passkey rule the context its assertion was made in.

use super::*;
use crate::authority::owner_key_enrollment_door::{decode_unsigned_entry, not_valid};

/// A passkey's Cancel of a recovery hold, built and waiting for the
/// passkey's assertion: the entry's canonical encoding with a zero
/// signature, which the client hands back unchanged, and the challenge the
/// assertion names, [`webauthn_challenge`] of the entry's authority
/// transcript.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedRecoveryHoldCancel {
    /// The unsigned entry, canonical MessagePack.
    pub entry: Vec<u8>,
    /// The challenge the passkey's assertion names.
    pub challenge: [u8; 32],
}

/// The key is not a live owner passkey that a valid enrollment names the
/// acting owner for. Nothing was written.
const PASSKEY_NOT_ACTORS: &str = "the key is not a live passkey of the acting owner's; \
                                  nothing was written";
/// Integrity: the entry handed back is not a passkey's Cancel of a recovery
/// hold for this vault in its one encoding. Nothing was written.
const CANCEL_NOT_PREPARED: &str = "the entry is not a passkey's Cancel of a recovery hold \
                                   for this vault; prepare it again";
/// Integrity: since the Cancel was prepared, its passkey signed a later
/// entry. Nothing was written.
const CANCEL_STALE: &str = "since this Cancel was prepared, its passkey signed a later entry; \
                            prepare it again";
/// The frontier is wider than one entry names, and this install has no live
/// machine profile whose key would join it. Nothing was written.
const NO_CARRIER: &str = "this install has no live machine profile in the vault's roster to join \
                          the authority log's heads for the Cancel; nothing was written";

/// The hold `entry` cancels, when `entry` is a passkey's Cancel in the
/// shape the wire takes: a `Cancel` answer signed by one P-256 key, with no
/// cosign. The signature checks wait for the assertion.
fn passkey_cancel_hold(entry: &AuthorityLogEntry) -> Result<AuthorityEntryHash> {
    let AuthorityOp::RecoveryHoldAnswer(answer) = &entry.op else {
        return Err(not_valid(CANCEL_NOT_PREPARED));
    };
    if answer.answer != RecoveryHoldAnswerKind::Cancel
        || !matches!(entry.signer.public_key, AuthorityKey::P256(_))
    {
        return Err(not_valid(CANCEL_NOT_PREPARED));
    }
    answer
        .validate()
        .and_then(|()| answer.validate_entry(entry))
        .map_err(|_| not_valid(CANCEL_NOT_PREPARED))?;
    Ok(answer.hold)
}

impl Vault {
    /// The first step of a passkey's Cancel of the live recovery hold `hold`
    /// (row RECOVERY-HOLD-PASSKEY-ANSWER): the answer entry `passkey` signs,
    /// built now with no signature, and the challenge its assertion names.
    /// `passkey` is a live owner passkey a valid enrollment names the owner
    /// `authority` proves for; any owner of this vault may cancel
    /// (WAYBACK-COOWNER-CANCEL-OTHER-OWNERS-RECOVERY = B). A frontier join
    /// the entry needs is written, signed by this install's key, and kept;
    /// nothing else is.
    ///
    /// # Errors
    /// [`crate::error::RecordError::AuthorityRefused`] for an agent's act, a
    /// hold that is not live, a key that is not a live passkey of the
    /// actor's, and a wide frontier on an install with no live machine
    /// profile; the store's and the clock's.
    pub fn prepare_recovery_hold_cancel_as(
        &self,
        authority: &ActAuthority,
        hold: AuthorityEntryHash,
        passkey: &AuthorityKey,
    ) -> Result<PreparedRecoveryHoldCancel> {
        let owner = match authority {
            ActAuthority::Owner(owner, _) => owner,
            ActAuthority::Agent(_) => return Err(authority_refused(ANSWER_OWNER_ONLY)),
        };
        let mut txn = self.store.env.write_txn()?;
        let actor = owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        self.refuse_passkey_cancel_in_txn(&txn, &fold, actor, hold, passkey)?;
        let vault_id = fold.vault_id.ok_or_else(invalid_authority)?;
        // FIX 7908: one entry names at most MAX_PARENTS heads. The passkey
        // signs the Cancel alone, so this install's key joins a wider
        // frontier first.
        let fold = if fold.append_heads.len() > MAX_PARENTS {
            let (carrier, carrier_key) = self
                .carrier_in_txn(&txn, &fold)
                .map_err(authority_refusal_as(NO_CARRIER))?;
            let joiner = FrontierSigner::Install(carrier, &carrier_key);
            self.prepare_authority_frontier_in_txn(&mut txn, &fold, joiner, MAX_PARENTS)?
                .unwrap_or(fold)
        } else {
            fold
        };
        let now = self.instant_in_txn(&txn)?.secs();
        let body = RecoveryHoldAnswer {
            hold,
            answer: RecoveryHoldAnswerKind::Cancel,
        };
        let entry = unsigned_recovery_hold_answer(vault_id, &fold, passkey, body, now)?;
        let challenge = webauthn_challenge(&authority_transcript(&entry)?);
        let bytes = encode_value(&entry_value(&entry, true))?;
        // A frontier join the entry names must stand for it to land.
        txn.commit()?;
        Ok(PreparedRecoveryHoldCancel {
            entry: bytes,
            challenge,
        })
    }

    /// The second step: the owner lands `entry`, as
    /// [`Self::prepare_recovery_hold_cancel_as`] answered it, with
    /// `assertion` (the passkey's assertion envelope over its challenge) as
    /// its one signature. The entry must be a passkey's Cancel for this
    /// vault in its one encoding; its passkey must still be a live passkey
    /// of the owner `authority` proves now, past its last sequence, and its
    /// hold still live. It lands only when the fold counts it, and is marked
    /// for the live mirror and announced as the device door's answer is.
    /// Answers the Cancel's entry hash.
    ///
    /// # Errors
    /// [`crate::error::RecordError::InvalidAuthorityLogBody`] for an entry
    /// that is not such a Cancel, and for a passkey that signed a later
    /// entry since prepare; [`crate::error::RecordError::AuthorityRefused`]
    /// for an agent's act, a hold that is no longer live, a key that is not
    /// a live passkey of the actor's, and a Cancel the fold does not count;
    /// the store's refusal of an assertion that does not verify (over
    /// another challenge, or without the person verified); the clock's.
    pub fn land_recovery_hold_cancel_as(
        &self,
        authority: &ActAuthority,
        entry: &[u8],
        assertion: Vec<u8>,
    ) -> Result<AuthorityEntryHash> {
        let owner = match authority {
            ActAuthority::Owner(owner, _) => owner,
            ActAuthority::Agent(_) => return Err(authority_refused(ANSWER_OWNER_ONLY)),
        };
        let mut entry =
            decode_unsigned_entry(entry).ok_or_else(|| not_valid(CANCEL_NOT_PREPARED))?;
        let hold = passkey_cancel_hold(&entry)?;
        let mut txn = self.store.env.write_txn()?;
        let actor = owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        if entry.vault_id != fold.vault_id {
            return Err(not_valid(CANCEL_NOT_PREPARED));
        }
        let passkey = entry.signer_key().clone();
        self.refuse_passkey_cancel_in_txn(&txn, &fold, actor, hold, &passkey)?;
        if entry.seq < next_sequence(&fold, &passkey)? {
            return Err(not_valid(CANCEL_STALE));
        }
        entry.signer.signature = assertion;
        let hash = self.put_recovery_hold_answer_in_txn(&mut txn, entry)?;
        let rows = self.mark_authority_rows_counted_since_in_txn(&mut txn, &fold)?;
        txn.commit()?;
        self.note_committed_authority_rows(rows);
        Ok(hash)
    }

    /// Refuses a Cancel of `hold` by `passkey` for `actor` at `fold` in
    /// `txn` unless the hold is live (Waiting or Due) and `passkey` is a
    /// live owner passkey a valid enrollment names `actor` for, which may
    /// answer a hold ([`answers_recovery_holds`]).
    fn refuse_passkey_cancel_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        fold: &AuthorityFold,
        actor: EntityId,
        hold: AuthorityEntryHash,
        passkey: &AuthorityKey,
    ) -> Result<()> {
        let live = self.recovery_holds_in_txn(txn)?.into_iter().any(|view| {
            view.hold == hold
                && matches!(
                    view.state,
                    RecoveryHoldState::Waiting | RecoveryHoldState::Due
                )
        });
        if !live {
            return Err(authority_refused(HOLD_NOT_LIVE));
        }
        let actors_passkey = self
            .enrolled_owner_passkeys_in_txn(txn)?
            .into_iter()
            .any(|listed| {
                listed.owner == actor && AuthorityKey::P256(listed.public_key) == *passkey
            });
        if !actors_passkey || !fold.roster.get(passkey).is_some_and(answers_recovery_holds) {
            return Err(authority_refused(PASSKEY_NOT_ACTORS));
        }
        Ok(())
    }
}
