//! The recovery box deposit a kit confirm answers (WAYBACK-BOX-DEPOSIT-PATH
//! = A, Engine 16 Nov 02:00): R's authority seed for the control plane's
//! recovery box enrol, once, without the PIN. The seed is the one the kit's
//! activation hands out (WAYBACK-BOX-AUTHORITY-SEED = A). The deposit rides
//! the owner confirm doors, so it takes no new grant, and nothing is stored.
//!
//! Only a vault with a recovery box gets one: a managed vault, whose host
//! root carries the host's stamp in the log (REVIEW2 #8597 P2-1; pass 27
//! DESIGN: under relay mode or self-host "No box exists there"). Under
//! "Nobody but me" the box holds no deposit either. Where none is due the
//! answer carries none, the seed is dropped (zeroized) and the CLI writes no
//! file. The deposit is never logged: its serializer
//! wipes the hex after writing it, and its `Debug` prints no seed bytes. The
//! seed's hex is made here, not by `owner::vault_key::hex`, which no secret
//! passes through.

use oneiron::authority::{AuthorityTier, ROLE_CLOUD, ROLE_OWNER};
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

/// Whether `vault` has a recovery box: its fold holds a live owner key with
/// the host's stamp (`ROLE_CLOUD` or `CloudCustodial`), which a managed
/// vault's host root carries (`HostSlipIssuer::root_device`) and a relay or
/// self-hosted vault's root never does. The stamp is a fact in the log, so
/// the owner's own device, where a hosted vault's kit confirm runs (the
/// hosted install refuses kit calls, `kit_requires_owner_device`), reads it
/// as the hosted node does; this install's own posture is not asked. The
/// same reading as `refuse_re_root_of_a_serving_host` and the kit
/// activation's predecessor.
pub(crate) fn vault_has_recovery_box(vault: &oneiron::Vault) -> oneiron::Result<bool> {
    Ok(vault.authority_fold()?.roster.values().any(|device| {
        !device.revoked
            && device.roles & ROLE_OWNER != 0
            && (device.roles & ROLE_CLOUD != 0 || device.tier == AuthorityTier::CloudCustodial)
    }))
}

/// The box deposit for a kit confirm that activated `root`: `None` on a
/// vault with no recovery box ([`vault_has_recovery_box`]) and under "Nobody
/// but me", where the box holds no deposit, and when either cannot be read,
/// which is warned without the seed or the root. `None` drops the seed,
/// zeroized.
pub(crate) fn box_deposit(
    vault: &oneiron::Vault,
    seed: RecoveryAuthoritySeed,
    root: &RecoveryRootId,
) -> Option<BoxDeposit> {
    match vault_has_recovery_box(vault) {
        Ok(true) => {}
        Ok(false) => return None,
        Err(error) => {
            tracing::warn!(
                %error,
                "authority fold unread after a kit confirm: no box deposit in the answer"
            );
            return None;
        }
    }
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
