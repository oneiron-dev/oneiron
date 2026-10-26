//! World pad compartments (KS-5, FIX 6706, L04 half): one world's pads,
//! live and retired, sealed apart from every other world's and wrapped only
//! to that world's admitted machines and recovery roots, never to the vault
//! data key, the generic root wrap or every linked machine.
//!
//! Two forms share one codec. A head's world compartment, once
//! [`WORLD_PAD_COMPARTMENTS`] is on, sits among the head's others under the
//! control compartment's digests. A capsule ([`SealedWorldPads`]) stands
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

use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::world_keys::{HybridPublicKey, RecoveryRootId, WorldKeyId, WrapRecipient};

use super::super::identity::{CustodyKind, CustodySubject};
use super::super::log::{AEAD, CRYPTO_EPOCH, CustodyPosition, open_sym, seal_refused, seal_sym};
use super::{BodyWire, EntryWire, FactWire, KEM, TO_ROOT, WrapWire, serde_bytes_vec, wrap_policy};

/// Whether a head seals its worlds' pads in world compartments: on (FIX
/// 9178; DEC-0005 #world-privacy-bundle-erase, ARCH-0038 #key-store). A
/// world's pads open only with the key of a machine admitted to it or a kit
/// root it admits, never the vault data key alone; a restore opened with the
/// data key alone lands its worlds' pad rows locked, named, for the kit or
/// an admitted machine. The scoped capsule API works either way.
pub(crate) const WORLD_PAD_COMPARTMENTS: bool = true;

/// A world compartment key's wrap to an admitted machine; a root's is
/// [`TO_ROOT`] under the tagged recipient, apart from the generic root wrap.
const TO_MACHINE: u8 = 3;
const CAPSULE_MAGIC: &[u8; 4] = b"OCWP";
const CAPSULE_VERSION: u16 = 1;
const CAPSULE_RECIPIENT: &[u8] = b"oneiron/custody-pads/capsule/v1";
/// The derive-key context of a capsule's envelope key id.
const CAPSULE_KEY_ID_CONTEXT: &str = "oneiron/custody-pads/capsule-key-id/v1";
/// A pad's full id: world (16) ‖ key generation (8, big-endian) ‖ mint (16).
const FULL: usize = 40;

fn pads_corrupt() -> Error {
    Error::CorruptedIndex("world pad compartment")
}

/// A world's admitted machines and recovery roots, by their hybrid public
/// keys: ordered and deduplicated, so its wraps and the publication policy's
/// digest are canonical.
pub(crate) type PadRecipients = BTreeMap<WrapRecipient, HybridPublicKey>;

/// One world's compartment scope: every pad of the world, live and retired.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct WorldPadScope(EntityId);

impl WorldPadScope {
    pub(super) fn new(world: EntityId) -> Self {
        Self(world)
    }

    /// The scope of the world pad `subject`.
    ///
    /// # Errors
    ///
    /// A subject that is no world pad, or whose item names no world.
    pub(crate) fn of(subject: &CustodySubject) -> Result<Self> {
        if subject.kind() != CustodyKind::WorldPad {
            return Err(pads_corrupt());
        }
        world_of(subject.item()).map(Self)
    }

    pub(crate) fn world(self) -> EntityId {
        self.0
    }
}

/// The world a pad's full id names.
pub(super) fn world_of(item: &[u8]) -> Result<EntityId> {
    if item.len() != FULL {
        return Err(pads_corrupt());
    }
    let world = <[u8; 16]>::try_from(&item[..16]).map_err(|_| pads_corrupt())?;
    EntityId::from_bytes(world).map_err(|_| pads_corrupt())
}

/// The world key a pad's full id names.
fn key_of(full: &[u8; FULL]) -> Result<WorldKeyId> {
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

/// Wraps a compartment `key` bound to `key_id` to each of `admitted`, by its
/// tagged envelope recipient.
///
/// # Errors
///
/// No admitted recipient (`None` or empty): the world's pads stay where they
/// are, never wrapped wider. Sealing faults.
pub(super) fn wrap_to_world(
    position: &CustodyPosition,
    key_id: &[u8; 32],
    key: &Zeroizing<[u8; 32]>,
    admitted: Option<&PadRecipients>,
) -> Result<Vec<WrapWire>> {
    let mut wraps = Vec::new();
    for (recipient, public) in admitted.into_iter().flatten() {
        let tagged = recipient.envelope_recipient();
        let params = SealParams {
            suite: AEAD,
            purpose: Purpose::CustodyCompartmentKey,
            epoch: CRYPTO_EPOCH,
            key_id,
            recipient: &tagged,
            vault_id: position.vault.as_bytes(),
        };
        let envelope = seal(
            &params,
            SealKey::Hybrid {
                recipient: public,
                kem_suite: KEM,
            },
            &key[..],
            &mut SysRng,
        )
        .map_err(|error| seal_refused(&error))?;
        let (to, root, machine) = match recipient {
            WrapRecipient::Machine(machine) => (TO_MACHINE, None, Some(*machine.as_bytes())),
            WrapRecipient::RecoveryRoot(root) => (TO_ROOT, Some(root.0), None),
        };
        wraps.push(WrapWire {
            to,
            root,
            machine,
            envelope: envelope.to_bytes(),
        });
    }
    if wraps.is_empty() {
        return Err(Error::InvalidConfig(
            "a world's pads need an admitted machine or recovery root to seal to".into(),
        ));
    }
    Ok(wraps)
}

/// Who a world compartment's wrap names.
fn wrap_recipient(wrap: &WrapWire) -> Option<WrapRecipient> {
    match (wrap.to, wrap.root, wrap.machine) {
        (TO_MACHINE, None, Some(machine)) => EntityId::from_bytes(machine)
            .ok()
            .map(WrapRecipient::Machine),
        (TO_ROOT, Some(root), None) => Some(WrapRecipient::RecoveryRoot(RecoveryRootId(root))),
        _ => None,
    }
}

/// The compartment key the wrap to `recipient` gives `secret`, if one names
/// it.
fn unwrap_for(
    position: &CustodyPosition,
    key_id: &[u8],
    wraps: &[WrapWire],
    recipient: WrapRecipient,
    secret: &HybridSecretKey,
) -> Option<Zeroizing<[u8; 32]>> {
    let wrap = wraps
        .iter()
        .find(|wrap| wrap_recipient(wrap) == Some(recipient))?;
    let tagged = recipient.envelope_recipient();
    let policy = wrap_policy(
        Purpose::CustodyCompartmentKey,
        position.vault.as_bytes(),
        &tagged,
        key_id,
        &[WrapType::HybridCapsule],
        &[KEM],
    );
    let opened = Envelope::parse(&wrap.envelope)
        .ok()?
        .open(OpenKey::Hybrid(secret), &policy)
        .ok()?;
    super::guarded_key(&opened)
}

/// A head's world compartment key for `machine`'s secret or `root`'s: the
/// machine's own wrap, else any root wrap the kit's secret opens.
pub(super) fn unwrap_world(
    position: &CustodyPosition,
    key_id: &[u8],
    wraps: &[WrapWire],
    machine: Option<(EntityId, &HybridSecretKey)>,
    root: Option<&HybridSecretKey>,
) -> Option<Zeroizing<[u8; 32]>> {
    machine
        .and_then(|(machine, secret)| {
            unwrap_for(
                position,
                key_id,
                wraps,
                WrapRecipient::Machine(machine),
                secret,
            )
        })
        .or_else(|| {
            let secret = root?;
            wraps
                .iter()
                .filter_map(wrap_recipient)
                .filter(|recipient| matches!(recipient, WrapRecipient::RecoveryRoot(_)))
                .find_map(|recipient| unwrap_for(position, key_id, wraps, recipient, secret))
        })
}

/// One world's pads, sealed alone at a custody position for its admitted
/// machines and roots: what pad hydration carries. Only ciphertext and
/// public ids; never a log's, error's or receipt's.
#[derive(Clone)]
#[allow(
    dead_code,
    reason = "L03 02A's pad hydration (FIX 6706) exports and opens these"
)]
pub(crate) struct SealedWorldPads {
    pub(crate) position: CustodyPosition,
    pub(crate) world: EntityId,
    /// What the capsule is wrapped to, ascending.
    pub(crate) recipients: Vec<WrapRecipient>,
    /// Every pad it holds, live or retired, ascending.
    pub(crate) required_keys: Vec<WorldKeyId>,
    /// BLAKE3 of [`Self::bytes`].
    pub(crate) digest: [u8; 32],
    pub(crate) bytes: Vec<u8>,
}

/// A capsule opened by one admitted recipient: its pads' secrets in guarded
/// storage by full id, and its retirement facts. No lineage control
/// secret; no `Debug`.
#[allow(dead_code, reason = "L03 02A's custody install (FIX 6706) reads these")]
pub(crate) struct OpenedWorldPads {
    pub(in crate::store) position: CustodyPosition,
    pub(in crate::store) world: EntityId,
    pub(in crate::store) recipient: WrapRecipient,
    pub(in crate::store) required_keys: Vec<WorldKeyId>,
    pub(in crate::store) live: BTreeMap<[u8; 40], Zeroizing<[u8; 32]>>,
    pub(in crate::store) retired: BTreeSet<[u8; 40]>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CapsuleWire {
    version: u16,
    #[serde(with = "serde_bytes_vec")]
    position: Vec<u8>,
    world: [u8; 16],
    /// Every pad's full id, ascending, end to end.
    #[serde(with = "serde_bytes_vec")]
    keys: Vec<u8>,
    #[serde(with = "serde_bytes_vec")]
    sealed: Vec<u8>,
    wraps: Vec<WrapWire>,
}

/// What a capsule's envelopes are bound to: its position, world, pads and
/// recipients, each counted, so none moves, joins or leaves unseen.
fn capsule_key_id(
    position: &CustodyPosition,
    world: &EntityId,
    keys: &[u8],
    recipients: &[WrapRecipient],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(CAPSULE_KEY_ID_CONTEXT);
    hasher.update(&position.to_bytes());
    hasher.update(world.as_bytes());
    hasher.update(&(keys.len() as u64).to_be_bytes());
    hasher.update(keys);
    hasher.update(&(recipients.len() as u64).to_be_bytes());
    for recipient in recipients {
        let tagged = recipient.envelope_recipient();
        hasher.update(&(tagged.len() as u64).to_be_bytes());
        hasher.update(&tagged);
    }
    *hasher.finalize().as_bytes()
}

/// Every pad of `world` among `live` and `retired`, ascending and end to
/// end, checked: each of the world, none both live and retired.
fn pad_ids(
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

/// A capsule's wire and the claims its unauthenticated fields make: its
/// position, world, recipients and pads.
type Claims = (
    CapsuleWire,
    CustodyPosition,
    EntityId,
    Vec<WrapRecipient>,
    Vec<WorldKeyId>,
);

fn claims(bytes: &[u8]) -> Result<Claims> {
    let body = bytes.strip_prefix(CAPSULE_MAGIC).ok_or_else(pads_corrupt)?;
    let wire: CapsuleWire = rmp_serde::from_slice(body).map_err(|_| pads_corrupt())?;
    if wire.version != CAPSULE_VERSION || wire.keys.len() % FULL != 0 {
        return Err(pads_corrupt());
    }
    let position = CustodyPosition::from_bytes(&wire.position).ok_or_else(pads_corrupt)?;
    let world = EntityId::from_bytes(wire.world).map_err(|_| pads_corrupt())?;
    let recipients = wire
        .wraps
        .iter()
        .map(wrap_recipient)
        .collect::<Option<Vec<_>>>()
        .ok_or_else(pads_corrupt)?;
    let mut keys = Vec::with_capacity(wire.keys.len() / FULL);
    let mut last: Option<&[u8]> = None;
    for full in wire.keys.chunks_exact(FULL) {
        let full: &[u8; FULL] = full.try_into().map_err(|_| pads_corrupt())?;
        if last.is_some_and(|last| last >= full.as_slice()) || world_of(full)? != world {
            return Err(pads_corrupt());
        }
        last = Some(full);
        keys.push(key_of(full)?);
    }
    if recipients.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(pads_corrupt());
    }
    Ok((wire, position, world, recipients, keys))
}

impl SealedWorldPads {
    /// The capsule `bytes` a carrier delivered, with the claims its fields
    /// make; [`open_world_pad_compartment`] authenticates them.
    ///
    /// # Errors
    ///
    /// Bytes that are no capsule of this engine's.
    #[allow(
        dead_code,
        reason = "L03 02A's pad hydration (FIX 6706) receives capsules"
    )]
    pub(crate) fn parse(bytes: Vec<u8>) -> Result<Self> {
        let (_, position, world, recipients, required_keys) = claims(&bytes)?;
        Ok(Self {
            position,
            world,
            recipients,
            required_keys,
            digest: *blake3::hash(&bytes).as_bytes(),
            bytes,
        })
    }
}

/// Seals `world`'s pads at `position`: `live` (each with its secret) and
/// the retirement facts `retired`, wrapped to each of `recipients` alone.
///
/// # Errors
///
/// A pad not of `world`, one both live and retired, no recipient, sealing
/// faults.
#[allow(dead_code, reason = "L03 02A's export (FIX 6706) seals capsules")]
pub(crate) fn seal_world_pad_compartment(
    position: &CustodyPosition,
    world: EntityId,
    live: &BTreeMap<[u8; 40], Zeroizing<[u8; 32]>>,
    retired: &BTreeSet<[u8; 40]>,
    recipients: &PadRecipients,
) -> Result<SealedWorldPads> {
    let keys = pad_ids(world, live.keys().copied(), retired.iter().copied())?;
    let ids: Vec<WrapRecipient> = recipients.keys().copied().collect();
    let key_id = capsule_key_id(position, &world, &keys, &ids);
    let body = BodyWire {
        control: None,
        digests: Vec::new(),
        live: live
            .iter()
            .map(|(full, secret)| EntryWire {
                kind: CustodyKind::WorldPad.tag(),
                item: full.to_vec(),
                generation: 0,
                secret: secret.to_vec(),
            })
            .collect(),
        retired: retired
            .iter()
            .map(|full| FactWire {
                kind: CustodyKind::WorldPad.tag(),
                item: full.to_vec(),
                generation: 0,
            })
            .collect(),
        recipients: Vec::new(),
        history: Vec::new(),
        // A world's pad capsule carries no erase evidence (FIX 10584 item
        // 3): that rides the head's host-readable compartments.
        evidence: Vec::new(),
    };
    let mut key = Zeroizing::new([0u8; 32]);
    crate::world_keys::os_fill(&mut key[..])?;
    let plain = Zeroizing::new(rmp_serde::to_vec_named(&body).map_err(|_| pads_corrupt())?);
    let sealed = seal_sym(
        Purpose::CustodyCompartment,
        position.vault,
        &key_id,
        CAPSULE_RECIPIENT,
        &Kek::from_bytes_ref(&key),
        &plain,
    )?;
    let wraps = wrap_to_world(position, &key_id, &key, Some(recipients))?;
    let wire = CapsuleWire {
        version: CAPSULE_VERSION,
        position: position.to_bytes().to_vec(),
        world: *world.as_bytes(),
        keys,
        sealed,
        wraps,
    };
    let mut bytes = CAPSULE_MAGIC.to_vec();
    bytes.extend_from_slice(&rmp_serde::to_vec_named(&wire).map_err(|_| pads_corrupt())?);
    let (_, _, _, _, required_keys) = claims(&bytes)?;
    Ok(SealedWorldPads {
        position: *position,
        world,
        recipients: ids,
        required_keys,
        digest: *blake3::hash(&bytes).as_bytes(),
        bytes,
    })
}

/// Opens `sealed` as `recipient`, with its `secret`. The capsule must be the
/// one the carrier's authenticated admission names (`expected_digest`), at
/// the position it names (`expected_position`); every field it claims must
/// match what its envelopes are bound to; and each pad it holds must be of
/// its world, custody generation 0, named once.
///
/// # Errors
///
/// A capsule that is not the expected one or does not hold together
/// ([`Error::CorruptedIndex`]); one with no wrap `secret` opens (refused).
#[allow(
    dead_code,
    reason = "L03 02A's pad hydration (FIX 6706) opens capsules"
)]
pub(crate) fn open_world_pad_compartment(
    sealed: &SealedWorldPads,
    expected_position: &CustodyPosition,
    expected_digest: &[u8; 32],
    recipient: WrapRecipient,
    secret: &HybridSecretKey,
) -> Result<OpenedWorldPads> {
    if blake3::hash(&sealed.bytes).as_bytes() != expected_digest
        || sealed.digest != *expected_digest
    {
        return Err(pads_corrupt());
    }
    let (wire, position, world, recipients, required_keys) = claims(&sealed.bytes)?;
    if position != *expected_position
        || sealed.position != position
        || sealed.world != world
        || sealed.recipients != recipients
        || sealed.required_keys != required_keys
    {
        return Err(pads_corrupt());
    }
    let key_id = capsule_key_id(&position, &world, &wire.keys, &recipients);
    let key = unwrap_for(&position, &key_id, &wire.wraps, recipient, secret).ok_or_else(|| {
        crate::world_keys::refused("the world's pads do not open with this machine or root")
    })?;
    let plain = open_sym(
        Purpose::CustodyCompartment,
        position.vault,
        &key_id,
        CAPSULE_RECIPIENT,
        &Kek::from_bytes_ref(&key),
        &wire.sealed,
    )?;
    let mut body: BodyWire = rmp_serde::from_slice(&plain).map_err(|_| pads_corrupt())?;
    if body.control.is_some()
        || !body.digests.is_empty()
        || !body.recipients.is_empty()
        || !body.history.is_empty()
        || !body.evidence.is_empty()
    {
        return Err(pads_corrupt());
    }
    let full = |kind: u8, item: &[u8], generation: u64| -> Result<[u8; FULL]> {
        if kind != CustodyKind::WorldPad.tag() || generation != 0 {
            return Err(pads_corrupt());
        }
        item.try_into().map_err(|_| pads_corrupt())
    };
    let mut live = BTreeMap::new();
    // Each secret goes straight into guarded storage; the wire's copy is
    // zeroized as it drops.
    for entry in std::mem::take(&mut body.live) {
        let id = full(entry.kind, &entry.item, entry.generation)?;
        let pad = super::guarded_key(&entry.secret).ok_or_else(pads_corrupt)?;
        if live.insert(id, pad).is_some() {
            return Err(pads_corrupt());
        }
    }
    let mut retired = BTreeSet::new();
    for fact in &body.retired {
        if !retired.insert(full(fact.kind, &fact.item, fact.generation)?) {
            return Err(pads_corrupt());
        }
    }
    if pad_ids(world, live.keys().copied(), retired.iter().copied())? != wire.keys {
        return Err(pads_corrupt());
    }
    Ok(OpenedWorldPads {
        position,
        world,
        recipient,
        required_keys,
        live,
        retired,
    })
}
