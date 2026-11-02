//! The owner's kit grant of pad access on the home itself (FIX 4954): where
//! this install keeps the generations, the grant needs no connection to a
//! home. Each kept generation's current pad object is read here whole, the
//! grant is sealed with the kit as
//! [`crate::sync::SyncClient::grant_sealed_bundle_pad_access_with_kit`] seals
//! it, and the home's own custody takes the offer by the checks every offer
//! meets (`offer_sealed_pad_access`). No peer proof is made up: the offer's
//! own signature and the recipient's standing here are what count. An install
//! that keeps no generation is no home for this call and grants nothing.

use super::{held_pad_object, retire_aged};
use crate::Vault;
use crate::authority::PeerMachine;
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result, SecretError};
use crate::sync::client::PadAdmissionReport;
use crate::sync::residence::{PadAccessRequest, ensure_sealed_pad_access, offer_sealed_pad_access};
use crate::world_keys::{PadAdmissionTarget, RecoveryRootSeed};

/// Grants `recipient` access to every pad object this install keeps, with
/// `seed`, the owner's kit for this call alone, as the connected grant does
/// over a home connection: `owner` is revalidated first and again for each
/// grant, the kit's root must be one of the vault's, and `recipient` must
/// stand as the owner's here under the key it names. A generation whose pad
/// object is not kept whole here, that the kit does not open, or whose offer
/// the custody refuses stays pending for an old reader, and its pending row is
/// kept. `None` when this install keeps no generation: it is not the home
/// this call needs, and nothing is written. Nothing keeps the kit.
///
/// # Errors
///
/// A stale owner, a kit root that is not the vault's, a recipient that does
/// not stand here; storage errors.
pub fn grant_local_sealed_pad_access_with_kit(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    seed: &RecoveryRootSeed,
    recipient: PadAdmissionTarget,
) -> Result<Option<PadAdmissionReport>> {
    owner.revalidate(vault)?;
    let mut kept = retire_aged(vault)?;
    if kept.is_empty() {
        return Ok(None);
    }
    kept.reverse();
    let me = vault.pad_admission_self_target().ok();
    let mut report = PadAdmissionReport::default();
    for entry in &kept {
        let generation = entry.generation;
        let pads = match held_pad_object(vault, generation, &entry.pads_digest)? {
            Some(pads) if pads.generation() == generation => pads,
            _ => {
                report.pending.push(generation);
                continue;
            }
        };
        let grant = match vault.seal_pad_admission_grant_with_kit(owner, &pads, seed, recipient) {
            Ok(grant) => grant,
            Err(Error::Secret(SecretError::SealedBundleNoCapsule)) => {
                report.pending.push(generation);
                continue;
            }
            Err(error) => return Err(error),
        };
        match offer_sealed_pad_access(vault, &grant) {
            Ok(()) => {}
            Err(Error::Sync(_)) => {
                report.pending.push(generation);
                continue;
            }
            Err(error) => return Err(error),
        }
        report.offered.push(generation);
        if me == Some(recipient) && vault.open_key_pads_with_grant(&pads, &grant).is_ok() {
            report.usable.push(generation);
        }
    }
    if !report.pending.is_empty() {
        ensure_sealed_pad_access(
            vault,
            PeerMachine::Unknown,
            &[PadAccessRequest {
                target: recipient,
                generations: Some(report.pending.clone()),
                invalid: Vec::new(),
            }],
        )?;
    }
    Ok(Some(report))
}
