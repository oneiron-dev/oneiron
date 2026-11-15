//! A sealed world-pad capsule for the home machine, for the member-lane socket test.
//!
//! A capsule needs only its recipient's public key to seal, and the home
//! machine's id is public: the door reads this vault's own machine and seals
//! one fresh pad of `world` to it, through the same seal a hydration's export
//! uses. The position is the sender's own, as a member's capsule carries its
//! own: the install door opens the capsule against the sidecar's position,
//! never against this custody's.

use std::collections::{BTreeMap, BTreeSet};

use zeroize::Zeroizing;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::store::custody_protocol::{
    CustodyEpoch, CustodyNamespace, CustodyPosition, CustodyVaultId,
};
use crate::store::{PadRecipients, seal_world_pad_compartment};
use crate::world_keys::{FIRST_GENERATION, WorldKeyId, WrapRecipient};

/// One fresh pad of a world, sealed for this vault's own machine: the sidecar
/// a Sealed residence-update envelope carries beside its payload, with the
/// pad's full id for the envelope's reference list.
pub struct SealedPadProbe {
    /// The key the pad was sealed under: the world's, at first generation,
    /// with a random mint no pad row names.
    pub key: WorldKeyId,
    /// The pad's full id: world (16) ‖ generation (8) ‖ mint (16).
    pub item: [u8; 40],
    /// The home machine's id: the envelope's recipient.
    pub recipient: [u8; 16],
    /// The sender's custody position the capsule is bound to.
    pub source_position: [u8; 96],
    /// BLAKE3 of [`Self::capsule`].
    pub digest: [u8; 32],
    pub capsule: Vec<u8>,
}

/// Seals one fresh pad of `world` for this vault's own machine. The pad is
/// random bytes under a random mint: no row names it and no custody holds it,
/// so it installs wherever a sealed capsule's pads install.
///
/// # Errors
///
/// No machine identity on this vault; the probe mint already held (retry);
/// sealing and storage faults.
pub fn seal_pad_for_home_machine(vault: &Vault, world: EntityId) -> Result<SealedPadProbe> {
    let secret = vault.machine_secret_outside_txn()?;
    let key = WorldKeyId {
        world,
        generation: FIRST_GENERATION,
        mint: *EntityId::now().as_bytes(),
    };
    let item = key.envelope_key_id();
    if vault.store.world_pad_in_custody(&item)?.is_some() {
        return Err(Error::InvalidConfig(
            "the probe mint is already in custody".to_owned(),
        ));
    }
    let mut pad = Zeroizing::new([0u8; 32]);
    crate::key_material::os_fill(&mut pad[..])?;
    let position = CustodyPosition {
        vault: CustodyVaultId::from_bytes([0xA1; 32]),
        namespace: CustodyNamespace::from_bytes([0xA2; 16]),
        epoch: CustodyEpoch(0),
        seq: 0,
        tip: [0xA3; 32],
    };
    let mut recipients = PadRecipients::new();
    recipients.insert(
        WrapRecipient::Machine(secret.machine),
        secret.secret.public_key().clone(),
    );
    let sealed = seal_world_pad_compartment(
        &position,
        world,
        &BTreeMap::from([(item, pad)]),
        &BTreeSet::new(),
        &recipients,
    )?;
    Ok(SealedPadProbe {
        key,
        item,
        recipient: *secret.machine.as_bytes(),
        source_position: sealed.position.to_bytes(),
        digest: sealed.digest,
        capsule: sealed.bytes,
    })
}

/// Whether current custody on `vault` holds `item`'s pad.
pub fn world_pad_held(vault: &Vault, item: &[u8; 40]) -> Result<bool> {
    Ok(vault.store.world_pad_in_custody(item)?.is_some())
}
