//! Checks whether the PIN-bound owner key can sign now and opens the seed
//! for one signature at a time.

use super::{PinBoundOwnerSigner, open_owner_seed};
use crate::authority::{AuthorityFold, AuthorityKey, CheckpointRootSigner, authority_refused};
use crate::error::{Error, Result};
use crate::vault::Vault;
use crate::world_keys::owner_signing::{KEY_NOT_LIVE, OTHER_VAULT_KEY, OwnerRootSigner};
use crate::world_keys::refused;

const NO_SEALED_KEY: &str = "no owner signing key rests under the device PIN";
const SEALED_KEY_UNOPENED: &str = "the owner signing key does not open under this device's PIN \
                                   key";
const SEALED_KEY_MISNAMED: &str = "the sealed owner signing key is not the key its envelope names";
const KEY_NO_LONGER_NAMED: &str = "this handle no longer names this owner signing key as the one \
                                    it opened under the device PIN";

impl PinBoundOwnerSigner {
    /// Why the key does not sign on `vault` now, from what needs no key:
    /// `vault` is another vault's handle, the device PIN key was set or
    /// forgotten since the seed was opened, `vault` no longer names this
    /// key as the one it opened under the PIN, or the roster no longer
    /// lists the key live. `held` is the fold of a caller that signs inside
    /// its own transaction ([`Vault::owner_key_on_live_roster`]).
    ///
    /// The handle stops naming a key when the seed that rests was replaced,
    /// also by a write the keystore answered a failure for, and when a
    /// later window found another seed or none. A signer of that key may
    /// still be held; it is refused here, so a pass and a door pass it over
    /// in place of failing at its signature.
    fn refusal(&self, vault: &Vault, held: Option<&AuthorityFold>) -> Option<Error> {
        if self.slot.vault_id != *vault.vault_id().as_bytes() {
            return Some(authority_refused(OTHER_VAULT_KEY));
        }
        if self.pin.key_generation() != self.key_generation {
            return Some(refused(SEALED_KEY_UNOPENED));
        }
        if vault.opened_pin_bound_owner_key() != Some(self.public_key) {
            return Some(refused(KEY_NO_LONGER_NAMED));
        }
        if !vault.owner_key_on_live_roster(&self.public_key, held) {
            return Some(authority_refused(KEY_NOT_LIVE));
        }
        None
    }

    /// One signature of the key, which `sign` makes with it: a checkpoint
    /// statement's, an owner act's proof, or an ask word's proof. Each is
    /// made here, under the same checks, and the key is dropped inside the
    /// call.
    ///
    /// # Errors
    /// [`crate::error::DevicePinRefusal::Required`] outside a window; the refusals of
    /// [`Self::refusal`]; a refusal for a seed that does not open, or opens
    /// to another key than its envelope names; what `sign` refuses.
    fn sign(
        &self,
        vault: &Vault,
        held: Option<&AuthorityFold>,
        sign: impl FnOnce(&OwnerRootSigner) -> Result<Vec<u8>>,
    ) -> Result<Vec<u8>> {
        if let Some(refusal) = self.refusal(vault, held) {
            return Err(refusal);
        }
        // Read before the key's lock is taken: a home may be slow.
        let sealed = self
            .pin
            .sealed_slot(&self.slot)?
            .ok_or_else(|| refused(NO_SEALED_KEY))?;
        // The seed is opened, used and wiped under the lock the window's end
        // takes.
        self.pin.with_pin_key(|pin_key| {
            let opened = open_owner_seed(pin_key, &self.slot, &sealed)
                .ok_or_else(|| refused(SEALED_KEY_UNOPENED))?;
            if opened.public_key != self.public_key {
                return Err(refused(SEALED_KEY_MISNAMED));
            }
            sign(&OwnerRootSigner::from_seed(&opened.seed))
        })?
    }
}

impl CheckpointRootSigner for PinBoundOwnerSigner {
    fn root(&self) -> AuthorityKey {
        AuthorityKey::Ed25519(self.public_key)
    }

    fn sign_checkpoint_statement(&self, vault: &Vault, statement: &[u8]) -> Result<Vec<u8>> {
        self.sign(vault, None, |key| key.sign_statement(statement))
    }

    fn signs_now(&self, vault: &Vault) -> bool {
        self.pin.window_is_open() && self.refusal(vault, None).is_none()
    }

    /// Only inside the window a right PIN opened, as a checkpoint statement.
    fn sign_owner_proof(
        &self,
        vault: &Vault,
        fold: &AuthorityFold,
        transcript: &[u8],
    ) -> Result<Vec<u8>> {
        self.sign(vault, Some(fold), |key| key.sign_proof(transcript))
    }

    fn proves_now(&self, vault: &Vault, fold: &AuthorityFold) -> bool {
        self.pin.window_is_open() && self.refusal(vault, Some(fold)).is_none()
    }

    /// Only inside the window a right PIN opened, as an owner act's proof.
    fn sign_ask_word_proof(
        &self,
        vault: &Vault,
        fold: &AuthorityFold,
        transcript: &[u8],
    ) -> Result<Vec<u8>> {
        self.sign(vault, Some(fold), |key| key.sign_ask_word(transcript))
    }
}
