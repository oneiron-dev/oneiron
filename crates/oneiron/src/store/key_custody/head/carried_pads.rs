//! World pad compartments a restore left unopened, carried forward (PAD-3,
//! FIX 11133).
//!
//! A head's world compartment holds one pad: its live entry or its
//! retirement fact, named by its [`PadCompartmentIdentity`], which the
//! control compartment authenticates with the rest of the compartment's
//! wire. A restore whose opener does not open one keeps it as it came
//! ([`CarriedWorldPad`]): its sealed body and its key's wraps verbatim, at
//! the position and index of the head it came from, with that head's and
//! its control compartment's BLAKE3 as provenance. The restored vault keeps
//! it beside its custody, and each later head carries it, its wraps to
//! recipients no longer admitted dropped, never wrapped again, until the pad
//! opens here or is erased. No new seal: it opens under its origin key id,
//! as it would have in its own head, and the carrying head's control
//! compartment commits to its whole wire.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::entity_id::EntityId;
use crate::error::Result;

use super::super::identity::{CustodyId, CustodyKind, CustodySecret};
use super::super::log::CustodyPosition;
use super::pad_scope::{WorldPadScope, retain_admitted};
use super::{
    BodyWire, CompartmentScope, CompartmentWire, CustodyOpener, CustodyRecipients, DigestRoot,
    OpenedHead, WrapWire, head_corrupt, key_id, open_body, serde_bytes_vec, typed, unwrap_key,
};

/// The derive-key context of a compartment's commitment in its head's
/// control compartment: the canonical encoding of its whole wire.
const COMPARTMENT_DIGEST_CONTEXT: &str = "oneiron/custody-head/compartment-digest/v2";
/// The derive-key context of a carried compartment's commitment.
const CARRIED_DIGEST_CONTEXT: &str = "oneiron/custody-head/carried-digest/v2";
/// The derive-key context of a control compartment's root over them all.
const DIGEST_ROOT_CONTEXT: &str = "oneiron/custody-head/digest-root/v3";
/// The derive-key context of the publication policy's carried-set digest.
const CARRIED_SET_CONTEXT: &str = "oneiron/custody-head/carried-set/v1";
const CARRIED_MAGIC: &[u8; 4] = b"OCCW";
/// The name a carried compartment's file takes beside its pad's entries.
pub(in crate::store::key_custody) const CARRIED_PREFIX: &str = ".carried-";

/// What one world compartment holds (PAD-3): the full id of its one pad,
/// world (16) | key generation (8, big-endian) | mint (16), and whether it is
/// the pad's retirement fact rather than its live entry. Public ids only.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PadCompartmentIdentity {
    #[serde(with = "pad_item")]
    item: [u8; 40],
    retired: bool,
}

/// A pad's full id as msgpack bin.
mod pad_item {
    use serde::{Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(item: &[u8; 40], out: S) -> Result<S::Ok, S::Error> {
        out.serialize_bytes(item)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(input: D) -> Result<[u8; 40], D::Error> {
        let bytes = super::serde_bytes_vec::deserialize(input)?;
        <[u8; 40]>::try_from(bytes.as_slice()).map_err(|_| {
            <D::Error as serde::de::Error>::invalid_length(bytes.len(), &"a 40-byte pad id")
        })
    }
}

impl PadCompartmentIdentity {
    /// The one pad `body`, a world compartment's, holds.
    pub(super) fn of(body: &BodyWire) -> Result<Self> {
        let (item, retired) = match (body.live.as_slice(), body.retired.as_slice()) {
            ([entry], []) => (&entry.item, false),
            ([], [fact]) => (&fact.item, true),
            _ => return Err(head_corrupt()),
        };
        Ok(Self {
            item: item.as_slice().try_into().map_err(|_| head_corrupt())?,
            retired,
        })
    }

    /// The pad's id in `position`'s vault, checked of `scope`'s world.
    fn id(&self, position: &CustodyPosition, scope: CompartmentScope) -> Result<CustodyId> {
        typed(
            position,
            CustodyKind::WorldPad.tag(),
            &self.item,
            0,
            scope,
            self.retired,
        )
    }
}

/// Refuses an opened world compartment whose body is not the one pad its
/// wire names.
pub(super) fn check_pad(pad: Option<&PadCompartmentIdentity>, body: &BodyWire) -> Result<()> {
    match pad {
        Some(pad) if PadCompartmentIdentity::of(body)? != *pad => Err(head_corrupt()),
        _ => Ok(()),
    }
}

/// What a head's control compartment commits to for one compartment.
pub(super) fn wire_digest(compartment: &CompartmentWire) -> Result<[u8; 32]> {
    digest(COMPARTMENT_DIGEST_CONTEXT, compartment)
}

fn digest(context: &str, wire: &impl Serialize) -> Result<[u8; 32]> {
    let bytes = rmp_serde::to_vec_named(wire).map_err(|_| head_corrupt())?;
    Ok(*blake3::Hasher::new_derive_key(context)
        .update(&bytes)
        .finalize()
        .as_bytes())
}

/// The root a control compartment commits to (FIX 5800): both counts, then
/// every compartment's digest and every carried one's, in order, under one
/// hash, so the control stays one size however many there are.
pub(super) fn digest_root(
    digests: &[[u8; 32]],
    carried_digests: &[[u8; 32]],
) -> Result<DigestRoot> {
    let compartments = u32::try_from(digests.len()).map_err(|_| head_corrupt())?;
    let carried = u32::try_from(carried_digests.len()).map_err(|_| head_corrupt())?;
    let mut hasher = blake3::Hasher::new_derive_key(DIGEST_ROOT_CONTEXT);
    hasher.update(&compartments.to_be_bytes());
    hasher.update(&carried.to_be_bytes());
    for each in digests.iter().chain(carried_digests) {
        hasher.update(each);
    }
    Ok(DigestRoot {
        compartments,
        carried,
        root: *hasher.finalize().as_bytes(),
    })
}

/// Whether `root`, a control compartment's, names exactly `compartments`
/// and `carried`, each whole and in order.
pub(super) fn committed(
    compartments: &[CompartmentWire],
    carried: &[CarriedWire],
    root: &DigestRoot,
) -> Result<bool> {
    if usize::try_from(root.compartments).ok() != Some(compartments.len())
        || usize::try_from(root.carried).ok() != Some(carried.len())
    {
        return Ok(false);
    }
    let digests = compartments
        .iter()
        .map(wire_digest)
        .collect::<Result<Vec<_>>>()?;
    let carried_digests = carried
        .iter()
        .map(|wire| digest(CARRIED_DIGEST_CONTEXT, wire))
        .collect::<Result<Vec<_>>>()?;
    Ok(digest_root(&digests, &carried_digests)? == *root)
}

/// One carried compartment as a head holds it.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CarriedWire {
    /// The origin head's position and the compartment's index there: what
    /// its key's wraps and its body are bound to.
    #[serde(with = "serde_bytes_vec")]
    position: Vec<u8>,
    index: u32,
    world: [u8; 16],
    pad: PadCompartmentIdentity,
    /// BLAKE3 of the origin head and of its sealed control compartment:
    /// provenance, never a key id input.
    origin_head: [u8; 32],
    origin_control: [u8; 32],
    #[serde(with = "serde_bytes_vec")]
    sealed: Vec<u8>,
    wraps: Vec<WrapWire>,
}

/// One world pad compartment a restore left unopened, at its origin
/// coordinates: ciphertext and public ids, never `Debug`.
#[derive(Clone)]
pub(in crate::store::key_custody) struct CarriedWorldPad {
    wire: CarriedWire,
    position: CustodyPosition,
    scope: CompartmentScope,
    id: CustodyId,
}

impl CarriedWorldPad {
    fn checked(wire: CarriedWire) -> Result<Self> {
        let position = CustodyPosition::from_bytes(&wire.position).ok_or_else(head_corrupt)?;
        let world = EntityId::from_bytes(wire.world).map_err(|_| head_corrupt())?;
        let scope = CompartmentScope::WorldPad(WorldPadScope::new(world));
        if wire.index == 0 {
            return Err(head_corrupt());
        }
        let id = wire.pad.id(&position, scope)?;
        Ok(Self {
            wire,
            position,
            scope,
            id,
        })
    }

    /// The pad it holds.
    pub(in crate::store::key_custody) fn id(&self) -> &CustodyId {
        &self.id
    }

    /// Its file's name beside the pad: its origin key id, one per origin
    /// compartment.
    pub(in crate::store::key_custody) fn file_name(&self) -> String {
        let id = key_id(&self.position.to_bytes(), self.wire.index, Some(self.scope));
        format!(
            "{CARRIED_PREFIX}{}",
            crate::entity_id::bytes_to_hex_lower(&id)
        )
    }

    /// Its file's bytes: ciphertext and public ids only.
    pub(in crate::store::key_custody) fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut out = CARRIED_MAGIC.to_vec();
        out.extend_from_slice(&rmp_serde::to_vec_named(&self.wire).map_err(|_| head_corrupt())?);
        Ok(out)
    }

    /// A carried compartment its file's `bytes` hold.
    pub(in crate::store::key_custody) fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let body = bytes.strip_prefix(CARRIED_MAGIC).ok_or_else(head_corrupt)?;
        Self::checked(rmp_serde::from_slice(body).map_err(|_| head_corrupt())?)
    }
}

/// What a compartment carried from `head`, whose sealed control compartment
/// is `control`, keeps of where it came from: the BLAKE3 of each.
pub(super) fn provenance(head: &[u8], control: &[u8]) -> ([u8; 32], [u8; 32]) {
    (
        *blake3::hash(head).as_bytes(),
        *blake3::hash(control).as_bytes(),
    )
}

/// A world compartment of the head `opened` names, at `index`, that its
/// opener did not open: a retirement fact stands all the same (its wire
/// names it, and the control compartment authenticates that); a live pad is
/// carried as it is, with its head's [`provenance`].
pub(super) fn left_unopened(
    opened: &mut OpenedHead,
    index: u32,
    scope: CompartmentScope,
    compartment: &CompartmentWire,
    provenance: ([u8; 32], [u8; 32]),
) -> Result<()> {
    let (Some(pad), Some(world)) = (compartment.pad, scope.world()) else {
        return Ok(());
    };
    let id = pad.id(&opened.position, scope)?;
    if pad.retired {
        if opened.live.contains_key(&id) || !opened.retired.insert(id) {
            return Err(head_corrupt());
        }
        return Ok(());
    }
    let wire = CarriedWire {
        position: opened.position.to_bytes().to_vec(),
        index,
        world: *world.as_bytes(),
        pad,
        origin_head: provenance.0,
        origin_control: provenance.1,
        sealed: compartment.sealed.clone(),
        wraps: compartment.wraps.clone(),
    };
    opened.carried.push(CarriedWorldPad {
        wire,
        position: opened.position,
        scope,
        id,
    });
    Ok(())
}

/// Opens each of `carried`, the head `opened` names', with `opener` under
/// its origin key id: a pad that opens joins `opened`'s live pads, and must
/// match one of the same id there; a retirement fact, the head's own or a
/// carried one, stands over a live pad. One that does not open stays
/// carried as it came. No carried compartment stays for a pad `opened` holds
/// live or retired.
pub(super) fn open_carried(
    opened: &mut OpenedHead,
    carried: Vec<CarriedWire>,
    opener: &CustodyOpener<'_>,
) -> Result<()> {
    for wire in carried {
        let pad = CarriedWorldPad::checked(wire)?;
        if !pad.position.same_lineage(&opened.position) {
            return Err(head_corrupt());
        }
        let origin = key_id(&pad.position.to_bytes(), pad.wire.index, Some(pad.scope));
        let wraps = &pad.wire.wraps;
        let Some(key) = unwrap_key(&pad.position, &origin, Some(pad.scope), wraps, opener) else {
            if pad.wire.pad.retired {
                opened.live.remove(&pad.id);
                opened.retired.insert(pad.id);
            } else {
                opened.unopened.insert(pad.scope);
                opened.carried.push(pad);
            }
            continue;
        };
        let mut body = open_body(&pad.position, &origin, &key, &pad.wire.sealed)?;
        if body.control.is_some()
            || body.root.is_some()
            || !body.recipients.is_empty()
            || !body.history.is_empty()
            || !body.evidence.is_empty()
        {
            return Err(head_corrupt());
        }
        check_pad(Some(&pad.wire.pad), &body)?;
        let (kind, generation) = match (body.live.first(), body.retired.first()) {
            (Some(entry), None) => (entry.kind, entry.generation),
            (None, Some(fact)) => (fact.kind, fact.generation),
            _ => return Err(head_corrupt()),
        };
        let item = pad.wire.pad.item;
        let id = typed(
            &pad.position,
            kind,
            &item,
            generation,
            pad.scope,
            pad.wire.pad.retired,
        )?;
        if id != pad.id {
            return Err(head_corrupt());
        }
        if pad.wire.pad.retired {
            opened.live.remove(&id);
            opened.retired.insert(id);
            continue;
        }
        let mut entry = body.live.pop().ok_or_else(head_corrupt)?;
        let secret = std::mem::take(&mut entry.secret);
        if secret.len() != CustodyKind::WorldPad.secret_len() {
            return Err(head_corrupt());
        }
        let secret = CustodySecret::from_bytes(Zeroizing::new(secret));
        if opened.retired.contains(&id) {
            continue;
        }
        match opened.live.get(&id) {
            Some(held) if held.expose() != secret.expose() => return Err(head_corrupt()),
            Some(_) => {}
            None => {
                opened.live.insert(id, secret);
            }
        }
    }
    let (live, retired) = (&opened.live, &opened.retired);
    opened
        .carried
        .retain(|pad| !live.contains_key(&pad.id) && !retired.contains(&pad.id));
    Ok(())
}

/// The carried compartments a head for `recipients` takes, with their
/// commitments: each of a pad its world's eligibility lets ride
/// ([`CustodyRecipients::keeps_local`]), with its wraps to the world's
/// admitted machines and roots alone, verbatim, never wrapped again. One no
/// admitted recipient's wrap is left in stays out.
pub(super) fn eligible(
    carried: &[CarriedWorldPad],
    recipients: &CustodyRecipients,
) -> Result<(Vec<CarriedWire>, Vec<[u8; 32]>)> {
    let mut wires = Vec::new();
    let mut digests = Vec::new();
    for pad in carried {
        let Some(world) = pad.scope.world() else {
            continue;
        };
        if recipients.keeps_local(&pad.id) {
            continue;
        }
        let mut wire = pad.wire.clone();
        retain_admitted(&mut wire.wraps, recipients.pad_worlds.get(&world));
        if wire.wraps.is_empty() {
            continue;
        }
        digests.push(digest(CARRIED_DIGEST_CONTEXT, &wire)?);
        wires.push(wire);
    }
    Ok((wires, digests))
}

/// One digest of every compartment `carried` names, wraps included, in
/// order: what the publication policy hashes, so a change of the carried
/// set alone makes every head due. `None` with none carried.
pub(in crate::store::key_custody) fn carried_set_digest(
    carried: &[CarriedWorldPad],
) -> Result<Option<[u8; 32]>> {
    if carried.is_empty() {
        return Ok(None);
    }
    let mut digests = carried
        .iter()
        .map(|pad| digest(CARRIED_DIGEST_CONTEXT, &pad.wire))
        .collect::<Result<Vec<_>>>()?;
    digests.sort_unstable();
    let mut hasher = blake3::Hasher::new_derive_key(CARRIED_SET_CONTEXT);
    hasher.update(&(digests.len() as u64).to_be_bytes());
    for each in &digests {
        hasher.update(each);
    }
    Ok(Some(*hasher.finalize().as_bytes()))
}
