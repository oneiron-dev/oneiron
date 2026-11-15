//! The recovery box deposit a kit confirm answers (WAYBACK-BOX-DEPOSIT-PATH
//! = A, Engine 16 Nov 02:00): R's authority seed for the control plane's
//! recovery box enrol, once, without the PIN. The seed is the one the kit's
//! activation hands out (WAYBACK-BOX-AUTHORITY-SEED = A). The deposit rides
//! the owner confirm doors, so it takes no new grant, and nothing is stored.
//!
//! Under "Nobody but me" the box holds no deposit: the answer carries none
//! and the CLI writes no file. The deposit is never logged: its serializer
//! wipes the hex after writing it, and its `Debug` prints no seed bytes. The
//! seed's hex is made here, not by `owner::vault_key::hex`, which no secret
//! passes through.

use oneiron::world_keys::{RecoveryAuthoritySeed, RecoveryRootId};
use serde::Serialize;
use zeroize::Zeroizing;

use crate::owner::vault_key::hex;

/// The box's label for R's seed.
pub(crate) const RECOVERY_AUTHORITY_LABEL: &str = "recovery-authority";

/// R's authority seed for the recovery box, once: one `seeds` element of the
/// control plane's recovery box enrol, without the PIN.
#[derive(Serialize, schemars::JsonSchema)]
pub(crate) struct BoxDeposit {
    /// The box's label for this seed: `recovery-authority`.
    label: &'static str,
    /// R's authority seed, 64 lowercase hex, for the box only.
    #[serde(serialize_with = "seed_hex")]
    #[schemars(with = "String")]
    seed_hex: RecoveryAuthoritySeed,
    /// The root's fingerprint, 64 lowercase hex, which the box binds to the
    /// sealed seed.
    source_root: String,
}

impl std::fmt::Debug for BoxDeposit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BoxDeposit")
            .field("label", &self.label)
            .field("seed_hex", &"<redacted>")
            .field("source_root", &self.source_root)
            .finish()
    }
}

/// The seed as 64 lowercase hex, wiped after it is written.
fn seed_hex<S: serde::Serializer>(
    seed: &RecoveryAuthoritySeed,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&secret_hex(seed.bytes()))
}

/// `bytes` as lowercase hex in one buffer sized up front and wiped when
/// dropped, so no part of the secret is left in a temporary or a buffer the
/// string outgrew.
fn secret_hex(bytes: &[u8]) -> Zeroizing<String> {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut text = Zeroizing::new(String::with_capacity(bytes.len() * 2));
    for &byte in bytes {
        text.push(char::from(DIGITS[usize::from(byte >> 4)]));
        text.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    text
}

/// The box deposit for a kit confirm that activated `root`: `None` under
/// "Nobody but me", where the box holds no deposit, and when the preset
/// cannot be read, which is warned without the seed or the root.
pub(crate) fn box_deposit(
    vault: &oneiron::Vault,
    seed: RecoveryAuthoritySeed,
    root: &RecoveryRootId,
) -> Option<BoxDeposit> {
    match vault.recovery_preset() {
        Ok(preset) if preset.is_nobody_but_me() => None,
        Ok(_) => Some(BoxDeposit {
            label: RECOVERY_AUTHORITY_LABEL,
            seed_hex: seed,
            source_root: hex(&root.0),
        }),
        Err(error) => {
            tracing::warn!(
                %error,
                "recovery preset unread after a kit confirm: no box deposit in the answer"
            );
            None
        }
    }
}
