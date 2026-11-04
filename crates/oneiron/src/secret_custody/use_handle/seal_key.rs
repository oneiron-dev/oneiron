//! A host's e-sign seal key held in secret custody (FIX 1297): the key is a
//! custody record's value, named by its handle, and each seal signature is
//! one use of it. The use is the one `Vault::use_secret_with` makes for
//! every handle: the record live and active, its binding for
//! [`SECRET_USE_SEAL_EFFECTOR`] granting `read` under the door policy, its
//! intent record committed before the lend and its outcome after. The value
//! is lent to the host's signer inside the T0 door and comes back to nobody;
//! a failure the signer reports is cleared of it inside that door. A host's
//! own use names no caller: it runs as the host's actor (the vault's
//! embedded owner, as every host call that names none does), class System.

use super::output::{clear_text, handle_text};
use super::{SecretUseConsumed, SecretUseOutcome, SecretUseSend, SecretUser, SentPresentation};
use crate::edge::EdgeActorClass;
use crate::error::Result;
use crate::vault::Vault;

/// The effector a seal key's custody record is bound to: the owner binds the
/// record to it, granting `read`, before the host signs seals with it.
pub const SECRET_USE_SEAL_EFFECTOR: &str = "esign:seal";

/// The operation a seal signature's use records name.
pub const SECRET_USE_SEAL_SIGN: &str = "seal.sign";

impl Vault {
    /// Lends the value of the secret `handle` names, the host's seal key, to
    /// `lend` inside the custody door for [`SECRET_USE_SEAL_EFFECTOR`], and
    /// records the use (FIX 1297). `lend` signs with the bytes and keeps
    /// nothing of them; what it signed it keeps itself. A failure it returns
    /// comes back as the outcome's `failure`, cleared of the value.
    ///
    /// # Errors
    /// [`crate::error::GateError::InvalidConsentBound`] for text that is not
    /// a handle; [`crate::error::SecretError::SecretRefNotFound`] for a
    /// handle that names no secret. Then, each with its refused Gate record:
    /// a record not active, a record with no binding for the seal effector
    /// that grants `read`, and the floor's and the door policy's own
    /// refusals, at the check or at the lend.
    pub fn use_seal_secret_with(
        &self,
        handle: &str,
        lend: &mut dyn FnMut(&[u8]) -> std::result::Result<(), String>,
    ) -> Result<SecretUseOutcome> {
        let user = SecretUser::new(
            crate::vault::embedded_owner_actor_id()?,
            EdgeActorClass::System,
        );
        self.use_secret_with(
            &user,
            handle,
            SECRET_USE_SEAL_SIGN,
            SECRET_USE_SEAL_EFFECTOR,
            &mut |target| {
                let text = handle_text(target.handle);
                let mut failure = None;
                let door = self.inject_secret_record_at_door(
                    &target.custody,
                    SECRET_USE_SEAL_EFFECTOR,
                    &mut |value: &[u8]| {
                        if let Err(mut refused) = lend(value) {
                            clear_text(&mut refused, value, &text);
                            failure = Some(refused);
                        }
                        Ok(())
                    },
                );
                match door {
                    Ok(receipt) => {
                        let generation = receipt.value_generation;
                        target
                            .note_sent(Some(SentPresentation::cleared(target.custody, generation)));
                        match failure {
                            Some(failure) => SecretUseConsumed::failed(failure),
                            None => SecretUseConsumed {
                                result: None,
                                failure: None,
                                send: SecretUseSend::Answered,
                            },
                        }
                    }
                    // The door refused at the lend: nothing was lent, and the
                    // use answers with its refusal.
                    Err(refusal) => {
                        target.refuse(refusal);
                        SecretUseConsumed {
                            result: None,
                            failure: None,
                            send: SecretUseSend::NotSent,
                        }
                    }
                }
            },
        )
    }
}
