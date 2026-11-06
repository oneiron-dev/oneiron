//! World pad compartments (KS-5, FIX 6706, L04 half): one world's pads,
//! live and retired, sealed apart from every other world's and wrapped only
//! to that world's admitted machines and recovery roots, never to the vault
//! data key, the generic root wrap or every linked machine.
//!
//! Two forms share one codec. A head's world compartment, once
//! [`WORLD_PAD_COMPARTMENTS`] is on, sits among the head's others under the
//! control compartment's root. A capsule ([`SealedWorldPads`]) stands
//! alone: what a machine's pad hydration carries to another of the owner's
//! machines, bound to its custody position, its world, the exact set of pads
//! it holds and the set of recipients it is wrapped to. Its BLAKE3 is what
//! the carrier's authenticated admission names; the capsule's own fields are
//! claims until [`open_world_pad_compartment`] checks them against that.

use std::collections::{BTreeMap, BTreeSet};

use getrandom::SysRng;
use oneiron_crypto::{
    Envelope, HybridSecretKey, Kek, OpenKey, Purpose, SealKey, SealParams, WrapType, seal,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use oneiron_authority::authority::RecoveryRootId;
use oneiron_authority::authority::{WorldKeyId, WrapRecipient};
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;

use crate::key_custody::head::wire::serde_bytes_vec;
use oneiron_crypto::HybridPublicKey;

use crate::key_custody::head::wire::EntryWire;
use crate::key_custody::head::wire::FactWire;
use crate::key_custody::head::wire::WrapWire;
use crate::key_custody::identity::CustodyKind;
use crate::key_custody::identity::CustodySubject;

/// Whether a head seals its worlds' pads in world compartments: on (FIX
/// 9178; DEC-0005 #world-privacy-bundle-erase, ARCH-0038 #key-store). A
/// world's pads open only with the key of a machine admitted to it or a kit
/// root it admits, never the vault data key alone; a restore opened with the
/// data key alone lands its worlds' pad rows locked, named, for the kit or
/// an admitted machine. The scoped capsule API works either way.
pub const WORLD_PAD_COMPARTMENTS: bool = true;

/// A world compartment key's wrap to an admitted machine; a root's is
/// [`TO_ROOT`] under the tagged recipient, apart from the generic root wrap.
pub const TO_MACHINE: u8 = 3;
pub const CAPSULE_MAGIC: &[u8; 4] = b"OCWP";
pub const CAPSULE_VERSION: u16 = 1;
pub const CAPSULE_RECIPIENT: &[u8] = b"oneiron/custody-pads/capsule/v1";
/// The derive-key context of a capsule's envelope key id.
pub const CAPSULE_KEY_ID_CONTEXT: &str = "oneiron/custody-pads/capsule-key-id/v1";
/// A pad's full id: world (16) ‖ key generation (8, big-endian) ‖ mint (16).
pub const FULL: usize = 40;

pub fn pads_corrupt() -> Error {
    Error::CorruptedIndex("world pad compartment")
}

/// A world's admitted machines and recovery roots, by their hybrid public
/// keys: ordered and deduplicated, so its wraps and the publication policy's
/// digest are canonical.
pub type PadRecipients = BTreeMap<WrapRecipient, HybridPublicKey>;

/// One world's compartment scope: every pad of the world, live and retired.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct WorldPadScope(pub EntityId);

impl WorldPadScope {
    pub fn new(world: EntityId) -> Self {
        Self(world)
    }

    /// The scope of the world pad `subject`.
    ///
    /// # Errors
    ///
    /// A subject that is no world pad, or whose item names no world.
    pub fn of(subject: &CustodySubject) -> Result<Self> {
        if subject.kind() != CustodyKind::WorldPad {
            return Err(pads_corrupt());
        }
        world_of(subject.item()).map(Self)
    }

    pub fn world(self) -> EntityId {
        self.0
    }
}

/// The world a pad's full id names.
pub fn world_of(item: &[u8]) -> Result<EntityId> {
    if item.len() != FULL {
        return Err(pads_corrupt());
    }
    let world = <[u8; 16]>::try_from(&item[..16]).map_err(|_| pads_corrupt())?;
    EntityId::from_bytes(world).map_err(|_| pads_corrupt())
}

/// The world key a pad's full id names.
pub fn key_of(full: &[u8; FULL]) -> Result<WorldKeyId> {
    let mut generation = [0u8; 8];
    let mut mint = [0u8; 16];
    generation.copy_from_slice(&full[16..24]);
    mint.copy_from_slice(&full[24..]);
    Ok(WorldKeyId {
        world: world_of(full)?,
        generation: u64::from_be_bytes(generation),
        mint,
    })
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapsuleWire {
    pub version: u16,
    #[serde(with = "serde_bytes_vec")]
    pub position: Vec<u8>,
    pub world: [u8; 16],
    /// Every pad's full id, ascending, end to end.
    #[serde(with = "serde_bytes_vec")]
    pub keys: Vec<u8>,
    #[serde(with = "serde_bytes_vec")]
    pub sealed: Vec<u8>,
    pub wraps: Vec<WrapWire>,
}

/// Every pad of `world` among `live` and `retired`, ascending and end to
/// end, checked: each of the world, none both live and retired.
pub fn pad_ids(
    world: EntityId,
    live: impl IntoIterator<Item = [u8; FULL]>,
    retired: impl IntoIterator<Item = [u8; FULL]>,
) -> Result<Vec<u8>> {
    let live: BTreeSet<[u8; FULL]> = live.into_iter().collect();
    let mut all = live.clone();
    for full in retired {
        if live.contains(&full) || !all.insert(full) {
            return Err(pads_corrupt());
        }
    }
    let mut out = Vec::with_capacity(all.len() * FULL);
    for full in &all {
        if world_of(full)? != world {
            return Err(pads_corrupt());
        }
        out.extend_from_slice(full);
    }
    Ok(out)
}
