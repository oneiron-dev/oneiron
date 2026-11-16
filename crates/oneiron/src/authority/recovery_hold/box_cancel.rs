//! An owner device's Cancel of the release pending at the recovery box
//! (OPUS-WAYBACK; WAYBACK-BOX-WAIT-ENGINE-HOLD-ONE-WAIT = A). On a hosted
//! vault the box's wait is the recovery wait, and while it runs no recovery
//! hold exists: R is still sealed at the box. So this Cancel is no
//! authority row. The owner's device signs a short proof with its live
//! owner key ([`Vault::sign_recovery_box_cancel_as`]), and the managed node
//! checks it on its own fold before it asks the box to cancel
//! ([`Vault::cancel_box_recovery_as`]). Neither side stores anything; the
//! box's receipt and the owner's notice name who cancelled.

use super::*;
use crate::world_keys::{RecoveryBoxCanceller, RecoveryBoxHold};

/// The domain of a box Cancel's proof. No other signature of an owner key
/// starts with these bytes.
const RECOVERY_BOX_CANCEL_DOMAIN: &[u8] = b"oneiron/recovery-box-cancel/v1";

/// The length of a box Cancel's transcript: the domain, the vault id, the
/// person, the key, `issued_at`, the receipt's tag and the receipt.
const CANCEL_TRANSCRIPT_LEN: usize = RECOVERY_BOX_CANCEL_DOMAIN.len() + 32 + 16 + 32 + 8 + 1 + 8;

/// How far a Cancel's `issued_at` may be from the node's clock, either way,
/// in seconds.
const CANCEL_PROOF_FRESH_SECS: u64 = 300;

/// A box Cancel is the owner's act: no Grant action names it. Nothing was
/// sent to the box.
const CANCEL_OWNER_ONLY: &str = "a recovery box cancel is the owner's act; no Grant action names it; nothing was sent to the box";
/// This install holds no live owner key of the actor's to sign the Cancel
/// with: sign-in alone cannot cancel. Nothing was sent to the box.
const NO_OWNER_KEY_TO_CANCEL: &str = "this install holds no live owner key of yours to cancel the box's recovery; \
                                      sign-in alone cannot cancel; nothing was sent to the box";
/// The proof names a person other than the act's actor: each owner signs
/// their own Cancel. Nothing was sent to the box.
const CANCEL_PROOF_NOT_ACTORS: &str = "the cancel's proof names another person; each owner signs their own cancel; \
                                       nothing was sent to the box";
/// The proof's key is no live owner key of the actor's on this node's fold.
/// Nothing was sent to the box.
const CANCEL_KEY_NOT_OWNERS: &str = "the cancel is not signed by a live owner key of yours on this vault; \
                                     sign-in alone cannot cancel; nothing was sent to the box";
/// The root's authority key never cancels at this door: the box holds its
/// seed, and the kit cancels a recovery hold through R at its own door.
/// Nothing was sent to the box.
const CANCEL_KEY_IS_ROOT: &str = "the root's authority key never cancels the box's recovery; \
                                  another owner device cancels; nothing was sent to the box";
/// The proof's signature does not verify over its transcript for this
/// vault. Nothing was sent to the box.
const CANCEL_PROOF_NOT_VALID: &str =
    "the cancel's signature does not verify for this vault; nothing was sent to the box";
/// The proof was signed more than [`CANCEL_PROOF_FRESH_SECS`] from the
/// node's clock. Nothing was sent to the box.
const CANCEL_PROOF_STALE: &str = "the cancel was signed more than five minutes from this node's clock; \
                                  sign it again; nothing was sent to the box";

/// An owner device's signed Cancel of the release pending at the recovery
/// box, made by [`Vault::sign_recovery_box_cancel_as`] and checked by
/// [`Vault::cancel_box_recovery_as`]. The route between them carries its
/// fields as they are.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryBoxCancelProof {
    /// The owner who cancels: the act's actor on the node as well.
    pub person: EntityId,
    /// The Ed25519 public half of the owner key that signs.
    pub key: [u8; 32],
    /// When the device signed, in unix seconds on its clock.
    pub issued_at: u64,
    /// The recovery-started act's receipt this Cancel stops, when the
    /// device read it: the box then cancels only that release, so a replay
    /// never stops a later recovery.
    pub release_receipt: Option<u64>,
    /// The key's Ed25519 signature over [`Self::transcript`].
    pub signature: Vec<u8>,
}

impl RecoveryBoxCancelProof {
    /// The bytes the key signs for the vault `vault_id`: the domain, the
    /// vault id, the person, the key, `issued_at` (big-endian), then the
    /// receipt as a one-byte tag (0 none, 1 some) and eight big-endian bytes
    /// (zero when none). Every field has a fixed length.
    #[must_use]
    pub fn transcript(&self, vault_id: &AuthorityVaultId) -> Vec<u8> {
        let (tag, receipt) = match self.release_receipt {
            Some(receipt) => (1_u8, receipt),
            None => (0_u8, 0),
        };
        let mut transcript = Vec::with_capacity(CANCEL_TRANSCRIPT_LEN);
        transcript.extend_from_slice(RECOVERY_BOX_CANCEL_DOMAIN);
        transcript.extend_from_slice(vault_id);
        transcript.extend_from_slice(self.person.as_bytes());
        transcript.extend_from_slice(&self.key);
        transcript.extend_from_slice(&self.issued_at.to_be_bytes());
        transcript.push(tag);
        transcript.extend_from_slice(&receipt.to_be_bytes());
        transcript
    }
}

/// Why `key` may not sign `actor`'s box Cancel on `fold`, if it may not:
/// the root's authority kind never cancels here; any other key must be a
/// live owner key ([`answers_recovery_holds`]: never an admin's or a host's)
/// that is `actor`'s own (`key_is_the_owners`), as the answer door reads a
/// Cancel's key. Any owner of the vault may cancel
/// (WAYBACK-COOWNER-CANCEL-OTHER-OWNERS-RECOVERY = B), each with their own
/// key.
fn cancel_key_refusal(
    fold: &AuthorityFold,
    enrolled: &[EnrolledOwnerKey],
    key: &AuthorityKey,
    actor: EntityId,
) -> Option<&'static str> {
    let names_key = |found: &&EnrolledOwnerKey| AuthorityKey::Ed25519(found.public_key) == *key;
    if enrolled
        .iter()
        .filter(names_key)
        .any(|found| found.kind == EnrolledOwnerKeyKind::RecoveryAuthority)
    {
        return Some(CANCEL_KEY_IS_ROOT);
    }
    let enrolled_owner = enrolled.iter().find(names_key).map(|found| found.owner);
    let live_owner = fold.roster.get(key).is_some_and(answers_recovery_holds);
    if !live_owner || !super::hold_view::key_is_the_owners(fold, enrolled_owner, key, actor) {
        return Some(CANCEL_KEY_NOT_OWNERS);
    }
    None
}

impl Vault {
    /// Signs this owner's Cancel of the release pending at the recovery box,
    /// with this install's owner signing key: the device unlock is the
    /// confirm sheet. The key must be a live owner key of the acting
    /// owner's on this install's fold, never the root's authority kind.
    /// `release_receipt` is the recovery-started act's receipt when the
    /// device read it (the box then cancels only that release). The proof
    /// goes to the managed node, which checks it
    /// ([`Self::cancel_box_recovery_as`]). Nothing is written.
    ///
    /// # Errors
    /// [`crate::error::RecordError::AuthorityRefused`] for an agent's act
    /// and for an install that holds no live owner key of the actor's (sign-in
    /// alone); the key's own refusal to sign an owner's proof now (a device
    /// PIN, a slot that no longer holds its seed); the store's, the clock's
    /// and the keystore's.
    pub fn sign_recovery_box_cancel_as(
        &self,
        authority: &ActAuthority,
        release_receipt: Option<u64>,
    ) -> Result<RecoveryBoxCancelProof> {
        let owner = match authority {
            ActAuthority::Owner(owner, _) => owner,
            ActAuthority::Agent(_) => return Err(authority_refused(CANCEL_OWNER_ONLY)),
        };
        let signer = self
            .existing_device_owner_signing_key()?
            .ok_or_else(|| authority_refused(NO_OWNER_KEY_TO_CANCEL))?;
        let txn = self.store.env.read_txn()?;
        let actor = owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        let vault_id = fold.vault_id.ok_or_else(invalid_authority)?;
        let enrolled = self.enrolled_owner_keys_in_txn(&txn)?;
        let key = signer.public_key();
        match cancel_key_refusal(&fold, &enrolled, &AuthorityKey::Ed25519(key), actor) {
            None => {}
            Some(CANCEL_KEY_IS_ROOT) => return Err(authority_refused(CANCEL_KEY_IS_ROOT)),
            Some(_) => return Err(authority_refused(NO_OWNER_KEY_TO_CANCEL)),
        }
        let issued_at = self.instant_in_txn(&txn)?.secs();
        let mut proof = RecoveryBoxCancelProof {
            person: actor,
            key,
            issued_at,
            release_receipt,
            signature: Vec::new(),
        };
        proof.signature = signer.sign_recovery_box_cancel(self, &fold, &proof, &vault_id)?;
        Ok(proof)
    }

    /// The managed node's half of an owner device's Cancel during the box
    /// wait: checks `proof` on this node's fold, then asks `box_hold` to
    /// cancel the release pending there, naming who cancelled. The proof's
    /// person must be the acting owner, revalidated as an owner of this
    /// vault (any owner may cancel: WAYBACK-COOWNER-CANCEL-OTHER-OWNERS-RECOVERY
    /// = B); its key must be that owner's own live owner key here, never the
    /// root's authority kind; its signature must verify strictly over
    /// [`RecoveryBoxCancelProof::transcript`] for this vault; and its
    /// `issued_at` must be within five minutes of this node's clock. A
    /// refused proof never reaches the box. `true` when the box cancelled a
    /// pending release, `false` when none was pending. Nothing is written
    /// here.
    ///
    /// # Errors
    /// [`crate::error::RecordError::AuthorityRefused`] for an agent's act and
    /// a proof that fails any check above; the store's and the clock's; the
    /// box's error when the Cancel did not reach it (whether it cancelled is
    /// then unknown).
    pub fn cancel_box_recovery_as(
        &self,
        authority: &ActAuthority,
        proof: &RecoveryBoxCancelProof,
        box_hold: &dyn RecoveryBoxHold,
    ) -> Result<bool> {
        let owner = match authority {
            ActAuthority::Owner(owner, _) => owner,
            ActAuthority::Agent(_) => return Err(authority_refused(CANCEL_OWNER_ONLY)),
        };
        // RED MUTATION: the node sends every Cancel to the box unchecked.
        return box_hold.cancel_pending_box_release(
            &RecoveryBoxCanceller {
                owner: proof.person,
                key: proof.key,
            },
            proof.release_receipt,
        );
        #[allow(unreachable_code)]
        let cancelled_by = {
            let txn = self.store.env.read_txn()?;
            let actor = owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
            if proof.person != actor {
                return Err(authority_refused(CANCEL_PROOF_NOT_ACTORS));
            }
            let fold = self.authority_view_readonly_in_txn(&txn)?;
            let vault_id = fold.vault_id.ok_or_else(invalid_authority)?;
            let enrolled = self.enrolled_owner_keys_in_txn(&txn)?;
            let key = AuthorityKey::Ed25519(proof.key);
            if let Some(words) = cancel_key_refusal(&fold, &enrolled, &key, actor) {
                return Err(authority_refused(words));
            }
            let signature = ed25519_dalek::Signature::from_slice(&proof.signature)
                .map_err(|_| authority_refused(CANCEL_PROOF_NOT_VALID))?;
            strong_ed25519_key(&proof.key)
                .map_err(|_| authority_refused(CANCEL_PROOF_NOT_VALID))?
                .verify_strict(&proof.transcript(&vault_id), &signature)
                .map_err(|_| authority_refused(CANCEL_PROOF_NOT_VALID))?;
            let now = self.instant_in_txn(&txn)?.secs();
            if now.abs_diff(proof.issued_at) > CANCEL_PROOF_FRESH_SECS {
                return Err(authority_refused(CANCEL_PROOF_STALE));
            }
            RecoveryBoxCanceller {
                owner: actor,
                key: proof.key,
            }
        };
        box_hold.cancel_pending_box_release(&cancelled_by, proof.release_receipt)
    }
}
