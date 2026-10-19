//! The checkpoint image a sealed bundle's base section carries, and the kit
//! restore that adopts it (FIX 3583).
//!
//! A vault that adopted a checkpoint image (OF-469) and has not hydrated the
//! rows it covers holds no row below the image's frontier, so the authority
//! tail its base carries names parents no fresh install holds. The base
//! therefore carries the adopted image whole, as the vault keeps it, with the
//! pin and attestations it verified against. A kit restore adopts it before
//! that tail only once the owner fixed its pin ([`RECOVERY_CHECKPOINT_TRUST`]):
//! a pin riding beside its image proves nothing, and a kit's confirmation
//! ([`KitConfirmation`]) confirms a root, not a pin.

use std::sync::Arc;

use super::{Reader, SealedKitRestore, decode_base, malformed, put_u32};
use crate::Vault;
use crate::authority::{AuthorityCheckpointAttestation, AuthorityCheckpointPin, PinnedRoot};
use crate::consent::AuthenticatedOwner;
use crate::error::Result;
use crate::sync::WindowManager;
use crate::world_keys::{
    KitConfirmation, RecoveryRootSeed, SealedKeyPads, SealedVaultBundle, refused,
};

/// How the owner fixed the pin of the checkpoint image a sealed bundle's base
/// carries, for a kit restore to adopt it: by its digest
/// ([`AuthorityCheckpointPin::digest`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryCheckpointTrust {
    /// The digest the owner carried from one of their machines that adopted
    /// the image, typed or scanned.
    IndependentPin([u8; 32]),
    /// The owner's explicit go-ahead for the digest the client showed
    /// ([`WindowManager::sealed_bundle_checkpoint_pin`]).
    OwnerConfirmation([u8; 32]),
}

/// What fixes a carried image's pin for a kit restore.
enum RecoveryTrust {
    /// The pin's digest is one the owner carried or confirmed; the bundle
    /// never fixes its own pin.
    IndependentPinOrExplicitOwnerConfirmation,
}

/// Which trust a kit restore adopts a carried checkpoint image under (CALLS:
/// RECOVERY_CHECKPOINT_TRUST; canon names owner-authorized recovery and no
/// form for it).
const RECOVERY_CHECKPOINT_TRUST: RecoveryTrust =
    RecoveryTrust::IndependentPinOrExplicitOwnerConfirmation;

/// The adopted image a base section carries: its pin, its bytes as the vault
/// keeps them and the attestations kept with it.
pub(super) struct CarriedCheckpoint {
    pin: AuthorityCheckpointPin,
    image: Vec<u8>,
    attestations: Vec<AuthorityCheckpointAttestation>,
}

/// The image `vault` adopted, verified again, as a base section carries it;
/// `None` when it adopted none.
pub(super) fn carried(vault: &Vault) -> Result<Option<CarriedCheckpoint>> {
    let Some(adopted) = vault.adopted_authority_checkpoint()? else {
        return Ok(None);
    };
    Ok(Some(CarriedCheckpoint {
        pin: adopted.pin().clone(),
        image: adopted.image().encode()?,
        attestations: adopted.attestations().to_vec(),
    }))
}

/// 0 when none rides; else 1 ‖ the pin's canonical bytes `u32`-length-
/// prefixed ‖ the image `u64`-length-prefixed ‖ the attestations as named
/// MessagePack, `u32`-length-prefixed.
pub(super) fn encode(out: &mut Vec<u8>, carried: Option<&CarriedCheckpoint>) -> Result<()> {
    let Some(carried) = carried else {
        out.push(0);
        return Ok(());
    };
    out.push(1);
    let pin = carried.pin.canonical_bytes()?;
    put_u32(out, pin.len())?;
    out.extend_from_slice(&pin);
    out.extend_from_slice(&(carried.image.len() as u64).to_be_bytes());
    out.extend_from_slice(&carried.image);
    let attestations = rmp_serde::to_vec_named(&carried.attestations).map_err(|_| malformed())?;
    put_u32(out, attestations.len())?;
    out.extend_from_slice(&attestations);
    Ok(())
}

/// [`encode`] back. Nothing it reads is trusted yet.
pub(super) fn decode(reader: &mut Reader<'_>) -> Result<Option<CarriedCheckpoint>> {
    match reader.u8()? {
        0 => return Ok(None),
        1 => {}
        _ => return Err(malformed()),
    }
    let len = reader.u32()? as usize;
    let pin = rmp_serde::from_slice(reader.take(len)?).map_err(|_| malformed())?;
    let len = usize::try_from(reader.u64()?).map_err(|_| malformed())?;
    let image = reader.take(len)?.to_vec();
    let len = reader.u32()? as usize;
    let attestations = rmp_serde::from_slice(reader.take(len)?).map_err(|_| malformed())?;
    Ok(Some(CarriedCheckpoint {
        pin,
        image,
        attestations,
    }))
}

/// Adopts `carried`, the image the base section carries, before a kit
/// restore imports the authority tail that stands on it, once `trust` fixes
/// its pin ([`RECOVERY_CHECKPOINT_TRUST`]). The kit's root may become this
/// install's pin first ([`Vault::adopt_recovered_authority_checkpoint`]), so
/// the kit must be one the restore's root door takes: verified, or confirmed
/// by the owner, a fingerprint naming its own root. With no `trust` nothing is
/// adopted and the tail imports alone, as a hydrated publisher's does.
pub(super) fn adopt(
    vault: &Vault,
    vault_id: &[u8; 32],
    carried: Option<&CarriedCheckpoint>,
    trust: Option<RecoveryCheckpointTrust>,
    seed: &RecoveryRootSeed,
    confirm: Option<KitConfirmation>,
) -> Result<()> {
    let (Some(carried), Some(trust)) = (carried, trust) else {
        return Ok(());
    };
    let fixed = match RECOVERY_CHECKPOINT_TRUST {
        RecoveryTrust::IndependentPinOrExplicitOwnerConfirmation => match trust {
            RecoveryCheckpointTrust::IndependentPin(digest)
            | RecoveryCheckpointTrust::OwnerConfirmation(digest) => digest,
        },
    };
    let root = seed.public(vault_id)?;
    if matches!(confirm, Some(KitConfirmation::Fingerprint(id)) if id != root.id) {
        return Err(refused("the fingerprint is not this seed's root"));
    }
    if !seed.authenticated() && confirm.is_none() {
        return Err(refused(
            "a kit that is not verified adopts no checkpoint image: confirm the kit",
        ));
    }
    let kit_root = PinnedRoot {
        id: root.id,
        anchor_key: root.anchor_key,
    };
    vault.adopt_recovered_authority_checkpoint(
        &carried.pin,
        &carried.image,
        &carried.attestations,
        fixed,
        kit_root,
    )?;
    Ok(())
}

impl WindowManager {
    /// [`Self::restore_sealed_bundle_with_kit`] for a bundle cut on a vault
    /// that adopted a checkpoint image: the image the base section carries is
    /// adopted first, once `checkpoint` names its pin, so the authority tail
    /// imports on it however little of the covered history the publisher
    /// held (FIX 3583).
    #[expect(clippy::too_many_arguments)]
    pub fn restore_sealed_bundle_with_kit_checkpoint(
        self: &Arc<Self>,
        owner: &AuthenticatedOwner,
        vault_id: &[u8; 32],
        bundle: &SealedVaultBundle,
        pads: &SealedKeyPads,
        seed: &RecoveryRootSeed,
        confirm: Option<KitConfirmation>,
        checkpoint: RecoveryCheckpointTrust,
    ) -> Result<SealedKitRestore> {
        self.restore_with_kit(
            owner,
            vault_id,
            bundle,
            pads,
            seed,
            confirm,
            Some(checkpoint),
        )
    }

    /// The pin of the checkpoint image `bundle`'s base section carries,
    /// opened with the kit's `seed` for the vault `vault_id`: what the client
    /// shows the owner, as its digest, before a restore adopts the image
    /// ([`RecoveryCheckpointTrust::OwnerConfirmation`]). Nothing in it is
    /// trusted. `None` when the base carries no image.
    pub fn sealed_bundle_checkpoint_pin(
        &self,
        vault_id: &[u8; 32],
        bundle: &SealedVaultBundle,
        seed: &RecoveryRootSeed,
    ) -> Result<Option<AuthorityCheckpointPin>> {
        let opened = bundle.open_with_kit(vault_id, seed)?;
        Ok(decode_base(opened.base())?
            .checkpoint
            .map(|carried| carried.pin))
    }
}
