//! A world key's pad at rest and on the move (KS-5, FIX 5686).
//!
//! A `WORLD_KEY_PAD` row's body takes one of three forms:
//! - the carrier, the form a pad row always had: label ‖ world (16) ‖
//!   generation (8, big-endian) ‖ mint (16) ‖ pad (32). It is how a pad
//!   travels its live routes (its world's window of the month it was
//!   learned, a promotion's pad set, a scoped door), and how it rests where
//!   custody cannot take it.
//! - the row at rest: the reference, label ‖ world ‖ generation ‖ mint ‖
//!   custody namespace (16), with the row's own pad (32) beside it. The
//!   key's custody entry (kind `WorldPad`, item the key's full id,
//!   generation 0) holds the published copy; the namespace is the custody it
//!   was published into, unsigned. The row's header keeps the time it was
//!   learned.
//! - the bare reference, the row at rest without its pad: the form every
//!   physical image takes (`pad_image`, FIX 5686 part 2). No live route ships
//!   one.
//!
//! Every put of a pad row passes [`admit_pad_put_in_txn`]: its pad goes into
//! current custody, synced and its Mint journaled, before the row commits,
//! and the row then rests as the reference with its pad beside it; a store
//! whose custody is closed (an archived vault) or faults keeps the carrier,
//! as before. Every read takes the row's own pad first and custody's second,
//! so no read, route, restore or fork loses a pad to a custody entry that is
//! missing, damaged or unreadable. Every route a pad row leaves by ships its
//! carrier ([`live_route_row`], [`image_pad_row`]). A bare reference lands
//! only with the pad custody here holds for it; else it waits, pending, for
//! its carrier. A checkpoint image and a Layer-1 artifact carry the bare
//! reference, and a restore takes the pad from current custody
//! (`pad_image`).

#[cfg(feature = "sync")]
mod recipients;
mod reference;

#[cfg(feature = "sync")]
pub(crate) use self::recipients::{
    missing_world_pads_in_txn, row_pad_in_txn, world_pad_recipients_in_txn,
    world_pad_row_items_in_txn,
};
#[allow(unused_imports, reason = "02A2 wires the projection (L02, L03)")]
pub(crate) use self::reference::{
    PAD_CAPTURE_FAULT, PadCaptureFault, PadReferenceProjection, WorldPadRef,
    pad_reference_projection, projected_pad_row_equal,
};
#[cfg(feature = "sync")]
#[allow(unused_imports, reason = "02A2 wires the projection (L02, L03)")]
pub(crate) use self::reference::{WindowPadProjection, project_window_pad_refs};

use std::collections::BTreeSet;

use heed::{RoTxn, RwTxn};
use zeroize::Zeroizing;

use super::bundle::stage_retained_pad_key_erase_in_txn;
use super::pads::{WorldKeyPad, pad_row_id, world_keys_destroyed_in_txn};
use super::{WorldKeyId, refused};
use crate::Vault;
use crate::authority::SealedCopies;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::{DeletionMarker, EntityStoreRead, TombstoneStoreRead};
use crate::registry::ENTITY_TYPE_WORLD_KEY_PAD;
use crate::store::{Store, WorldPadCustody};

/// The carrier form's label.
const CARRIER_LABEL: &[u8] = b"oneiron/world-key-pad/v1\0";
/// label ‖ world (16) ‖ generation (8, big-endian) ‖ mint (16) ‖ pad (32).
const CARRIER_LEN: usize = CARRIER_LABEL.len() + 16 + 8 + 16 + 32;
/// The reference form's label (CALLS: KS-5 pad reference form).
const REFERENCE_LABEL: &[u8] = b"oneiron/world-key-pad-ref/v1\0";
/// label ‖ world (16) ‖ generation (8, big-endian) ‖ mint (16) ‖ custody
/// namespace (16): the bare reference.
const REFERENCE_LEN: usize = REFERENCE_LABEL.len() + 16 + 8 + 16 + 16;
/// The reference ‖ the row's own pad (32): the row at rest.
const RESTING_LEN: usize = REFERENCE_LEN + 32;

/// One pad row's body, decoded.
pub(crate) enum PadBody {
    /// The pad itself, as it travels.
    Carrier(WorldKeyId, WorldKeyPad),
    /// The key whose pad current custody holds, with the row's own pad
    /// beside it at rest; `None` for a bare reference.
    Reference(WorldKeyId, Option<WorldKeyPad>),
}

impl PadBody {
    pub(crate) fn key(&self) -> &WorldKeyId {
        match self {
            Self::Carrier(key, _) | Self::Reference(key, _) => key,
        }
    }

    /// The pad the body itself holds: a carrier's, or the one a reference
    /// rests beside.
    pub(super) fn pad(&self) -> Option<&WorldKeyPad> {
        match self {
            Self::Carrier(_, pad) | Self::Reference(_, Some(pad)) => Some(pad),
            Self::Reference(_, None) => None,
        }
    }

    fn into_pad(self) -> Option<WorldKeyPad> {
        match self {
            Self::Carrier(_, pad) | Self::Reference(_, Some(pad)) => Some(pad),
            Self::Reference(_, None) => None,
        }
    }
}

/// The custody item `key`'s pad rests under: its full id, world |
/// generation | mint (CALLS: FIX 5686 pad custody item codec).
pub(super) fn pad_item(key: &WorldKeyId) -> [u8; 40] {
    key.envelope_key_id()
}

/// `key` ‖ `pad` as a carrier body.
pub(super) fn encode_carrier(key: &WorldKeyId, pad: &[u8; 32]) -> Vec<u8> {
    let mut body = Vec::with_capacity(CARRIER_LEN);
    body.extend_from_slice(CARRIER_LABEL);
    body.extend_from_slice(&pad_item(key));
    body.extend_from_slice(pad);
    body
}

/// The bare reference: `key`'s reference into `namespace`, no pad beside it.
pub(super) fn encode_reference(key: &WorldKeyId, namespace: &[u8; 16]) -> Vec<u8> {
    let mut body = Vec::with_capacity(REFERENCE_LEN);
    body.extend_from_slice(REFERENCE_LABEL);
    body.extend_from_slice(&pad_item(key));
    body.extend_from_slice(namespace);
    body
}

/// The custody namespace a reference `body` names, unsigned; `None` for a
/// carrier or a body that does not decode.
pub(super) fn reference_namespace(body: &[u8]) -> Option<[u8; 16]> {
    if !matches!(body.len(), REFERENCE_LEN | RESTING_LEN) || !body.starts_with(REFERENCE_LABEL) {
        return None;
    }
    let at = REFERENCE_LABEL.len() + 40;
    body.get(at..at + 16)?.try_into().ok()
}

/// The row at rest: `key`'s reference into `namespace`, its `pad` beside it.
pub(super) fn encode_resting(key: &WorldKeyId, namespace: &[u8; 16], pad: &[u8; 32]) -> Vec<u8> {
    let mut body = Vec::with_capacity(RESTING_LEN);
    body.extend_from_slice(REFERENCE_LABEL);
    body.extend_from_slice(&pad_item(key));
    body.extend_from_slice(namespace);
    body.extend_from_slice(pad);
    body
}

/// The key a full id names: world (16) ‖ generation (8, big-endian) ‖ mint
/// (16).
fn key_of_id(id: &[u8]) -> Option<WorldKeyId> {
    Some(WorldKeyId {
        world: EntityId::from_bytes(id.get(..16)?.try_into().ok()?).ok()?,
        generation: u64::from_be_bytes(id.get(16..24)?.try_into().ok()?),
        mint: id.get(24..40)?.try_into().ok()?,
    })
}

/// A pad row's body in any of its forms; anything else is malformed.
pub(crate) fn decode_pad_body(body: &[u8]) -> Result<PadBody> {
    let malformed = || Error::CorruptedIndex("world key pad body");
    let (rest, carrier) = if body.len() == CARRIER_LEN && body.starts_with(CARRIER_LABEL) {
        (&body[CARRIER_LABEL.len()..], true)
    } else if matches!(body.len(), REFERENCE_LEN | RESTING_LEN) && body.starts_with(REFERENCE_LABEL)
    {
        (&body[REFERENCE_LABEL.len()..], false)
    } else {
        return Err(malformed());
    };
    let key = key_of_id(rest).ok_or_else(malformed)?;
    // A carrier's pad follows its key; a reference at rest's, its namespace.
    let pad = rest
        .get(if carrier { 40 } else { 56 }..)
        .filter(|raw| raw.len() == 32)
        .map(|raw| {
            let mut pad = Zeroizing::new([0u8; 32]);
            pad.copy_from_slice(raw);
            WorldKeyPad::from_bytes(pad)
        });
    Ok(match pad {
        Some(pad) if carrier => PadBody::Carrier(key, pad),
        pad => PadBody::Reference(key, pad),
    })
}

/// The pad `body` resolves to here: its own first, a carrier's or the one a
/// reference rests beside, and current custody's only for a bare reference.
/// Custody's is never read for a world whose keys were destroyed here: its
/// retirement may still be finishing.
pub(super) fn pad_of_body_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    body: PadBody,
) -> Result<Option<WorldKeyPad>> {
    let key = *body.key();
    if let Some(pad) = body.into_pad() {
        return Ok(Some(pad));
    }
    if world_keys_destroyed_in_txn(store, txn, key.world)? {
        return Ok(None);
    }
    Ok(store
        .world_pad_in_custody(&pad_item(&key))?
        .map(WorldKeyPad::from_bytes))
}

fn changed() -> Error {
    refused("a world key's pad never changes")
}

/// The one refusal of a pad custody holds (Engine 10-21): custody read it,
/// and it is another than the pad the row brings.
fn custody_disagrees() -> Error {
    refused("pad_custody_disagrees: key custody holds another pad for this world key")
}

/// A bare reference whose pad is not here: it waits for its carrier.
fn pad_not_here() -> Error {
    refused("the key's pad has not reached this machine")
}

/// The put door's admission of a pad row, on every path, local or
/// replicated: the body is one pad in any form, the row id is the one its
/// key derives, no pad lands for a world whose keys were destroyed, and a
/// pad never changes, whether its row or custody holds it. Its pad goes
/// into current custody first ([`take_into_custody`]). A bare reference
/// never takes the place of a row that holds its pad, and lands only with
/// the pad custody here holds for it; else it is refused as not here yet.
/// Returns the body to store in place of `data`.
///
/// # Errors
///
/// The refusals above, and storage faults.
pub(crate) fn admit_pad_put_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    data: &[u8],
) -> Result<Option<Vec<u8>>> {
    let body = decode_pad_body(data)?;
    let key = *body.key();
    if pad_row_id(&key)? != *id {
        return Err(refused("a pad row's id is not the one its key derives"));
    }
    if world_keys_destroyed_in_txn(store, wtxn, key.world)? {
        return Err(refused("the world's keys were destroyed with the world"));
    }
    let stored = match store.port_entity_raw(wtxn, id)?.map(Zeroizing::new) {
        None => None,
        Some(raw) => {
            let held = raw.get(ENTITY_METADATA_HEADER_LEN..).unwrap_or_default();
            match decode_pad_body(held) {
                Ok(decoded) if decoded.key() == &key => Some((decoded, held.to_vec())),
                _ => return Err(changed()),
            }
        }
    };
    let held = stored.as_ref().and_then(|(stored, _)| stored.pad());
    let pad = match body.into_pad() {
        Some(pad) => pad,
        // A bare reference never takes the place of a held pad.
        None if held.is_some() => return Ok(stored.as_ref().map(|(_, raw)| raw.clone())),
        None => match store.world_pad_in_custody(&pad_item(&key)) {
            Ok(Some(pad)) => WorldKeyPad::from_bytes(pad),
            Ok(None) | Err(_) => return Err(pad_not_here()),
        },
    };
    if held.is_some_and(|held| held.bytes() != pad.bytes()) {
        return Err(changed());
    }
    take_into_custody(store, wtxn, &key, &pad).map(Some)
}

/// Publishes `key`'s `pad` into current custody in `wtxn`'s writer, its
/// binding pinned in the same transaction, synced and its Mint journaled
/// before the row commits, and returns the body the row stores: the
/// reference with the pad beside it. A pad custody holds already goes
/// through the same door and, when custody reads it, must be the same; a
/// retired entry is the world's erase. A closed custody (an archived vault)
/// or a custody fault, an entry custody cannot read included, leaves the
/// carrier, warned: the row carries its pad as before.
fn take_into_custody(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    key: &WorldKeyId,
    pad: &WorldKeyPad,
) -> Result<Vec<u8>> {
    let item = pad_item(key);
    let taken = match store.world_pad_custody_entry(&item) {
        Ok(WorldPadCustody::Live(held)) if *held != *pad.bytes() => {
            return Err(custody_disagrees());
        }
        Ok(WorldPadCustody::Retired) => {
            return Err(refused("the world's keys were destroyed with the world"));
        }
        Ok(WorldPadCustody::Closed) => return Ok(encode_carrier(key, pad.bytes())),
        Ok(WorldPadCustody::Live(_) | WorldPadCustody::Missing) => {
            store.publish_world_pad_in_txn(wtxn, &item, pad.bytes())
        }
        Err(error) => Err(error),
    };
    let namespace = match taken {
        Ok(()) => store.world_pad_namespace(),
        Err(error) => {
            tracing::warn!(
                kind = ?error.kind(),
                "a world key's pad was not taken into key custody; its row carries it"
            );
            None
        }
    };
    Ok(match namespace {
        Some(namespace) => encode_resting(key, &namespace, pad.bytes()),
        None => encode_carrier(key, pad.bytes()),
    })
}

/// What a route that ships the stored row `raw` ships.
enum Shipment {
    /// Not a pad reference: the row as stored.
    AsStored,
    /// A pad reference as its carrier: the row's own pad, or else current
    /// custody's.
    Carrier(Vec<u8>),
    /// A bare pad reference whose pad custody does not hold here.
    PadAbsent,
}

/// The body of `raw` past its header, when it is a pad row.
pub(super) fn pad_row_body(raw: &[u8]) -> Option<&[u8]> {
    EntityMetadataHeader::parse(raw)
        .filter(|header| header.entity_type == ENTITY_TYPE_WORLD_KEY_PAD)
        .and_then(|_| raw.get(ENTITY_METADATA_HEADER_LEN..))
}

fn shipment(store: &Store, raw: &[u8]) -> Shipment {
    let Some(Ok(PadBody::Reference(key, own))) = pad_row_body(raw).map(decode_pad_body) else {
        return Shipment::AsStored;
    };
    let pad = match own {
        Some(pad) => Ok(Some(pad)),
        None => store
            .world_pad_in_custody(&pad_item(&key))
            .map(|pad| pad.map(WorldKeyPad::from_bytes)),
    };
    match pad {
        Ok(Some(pad)) => {
            let mut row = raw[..ENTITY_METADATA_HEADER_LEN].to_vec();
            row.extend_from_slice(&encode_carrier(&key, pad.bytes()));
            Shipment::Carrier(row)
        }
        Ok(None) => Shipment::PadAbsent,
        Err(error) => {
            tracing::warn!(
                kind = ?error.kind(),
                "a world key's pad could not be read from key custody; its row stays here"
            );
            Shipment::PadAbsent
        }
    }
}

/// The stored row `raw` as a live route ships it (the sync window passes'
/// unsealed reads): a pad reference as its carrier, any other row as it is,
/// and `None` for a bare reference whose pad custody does not hold here.
pub(crate) fn live_route_row(store: &Store, raw: Vec<u8>) -> Option<Vec<u8>> {
    match shipment(store, &raw) {
        Shipment::AsStored => Some(raw),
        Shipment::Carrier(row) => Some(row),
        Shipment::PadAbsent => None,
    }
}

/// The carrier a pad reference row `raw` is shipped as by a door that hands
/// out every row it admitted (a scoped door): `None` keeps the row as
/// stored. A physical image never takes it (`pad_image`).
pub(crate) fn image_pad_row(store: &Store, raw: &[u8]) -> Option<Vec<u8>> {
    match shipment(store, raw) {
        Shipment::Carrier(row) => Some(row),
        Shipment::AsStored | Shipment::PadAbsent => None,
    }
}

/// Whether a row is stored at `id` whose pad is here, or that is no bare
/// pad reference: a promotion's pad row lands only where it is not.
///
/// # Errors
///
/// Storage faults.
#[cfg(feature = "sync")]
pub(crate) fn pad_row_held_in_txn(store: &Store, txn: &RoTxn<'_>, id: &EntityId) -> Result<bool> {
    Ok(store
        .port_entity_raw(txn, id)?
        .is_some_and(|raw| !matches!(shipment(store, &raw), Shipment::PadAbsent)))
}

/// Whether the stored pad row `stored` already holds what `carried`, a pad
/// row a live route brings, does: the same header and key, and the same
/// pad, the stored row's own or else the one current custody holds for it.
/// A held pad holds what any reference to its key names; a bare reference
/// whose pad is not here holds nothing yet. A custody fault reads as not
/// equal: the put door judges the row.
#[cfg(feature = "sync")]
pub(crate) fn pad_echo_equal(store: &Store, stored: &[u8], carried: &[u8]) -> bool {
    if stored.get(..ENTITY_METADATA_HEADER_LEN) != carried.get(..ENTITY_METADATA_HEADER_LEN) {
        return false;
    }
    let (Some(Ok(held)), Some(Ok(brought))) = (
        pad_row_body(stored).map(decode_pad_body),
        pad_row_body(carried).map(decode_pad_body),
    ) else {
        return false;
    };
    let key = *held.key();
    if key != *brought.key() {
        return false;
    }
    let held = match held.into_pad() {
        Some(pad) => pad,
        None => match store.world_pad_in_custody(&pad_item(&key)) {
            Ok(Some(pad)) => WorldKeyPad::from_bytes(pad),
            Ok(None) | Err(_) => return false,
        },
    };
    brought.pad().is_none_or(|pad| pad.bytes() == held.bytes())
}

/// The refusal a pad row `blob` a live route brings for `id` waits under,
/// when it is a bare reference whose pad is not here: no row here holds it
/// and current custody does not. It is no landed pad: it stays pending, its
/// marker kept, until the carrier its live routes ship lands.
///
/// # Errors
///
/// Storage faults.
#[cfg(feature = "sync")]
pub(crate) fn pad_reference_waits_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    id: &EntityId,
    blob: &[u8],
) -> Result<Option<Error>> {
    let Some(Ok(PadBody::Reference(key, None))) = pad_row_body(blob).map(decode_pad_body) else {
        return Ok(None);
    };
    if pad_row_held_in_txn(store, txn, id)?
        || matches!(store.world_pad_in_custody(&pad_item(&key)), Ok(Some(_)))
    {
        return Ok(None);
    }
    Ok(Some(pad_not_here()))
}

/// Stages the retirement of the custody entry of the pad row `id`, when it
/// is one here: a hard erase of that row alone, a peer's tombstone or this
/// vault's own delete door or batch delete (FIX 7192), takes its key's pad
/// out of custody too, carried out after the commit as a world erase's are,
/// never another pad of the world. A soft-erased pad keeps its header only:
/// the pad custody holds whose key derives the row's id is staged. A row
/// that does not decode is warned by its id and stages nothing.
///
/// # Errors
///
/// Custody and storage faults.
pub(crate) fn stage_pad_row_erase_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let Some(raw) = store.port_entity_raw(wtxn, id)?.map(Zeroizing::new) else {
        return Ok(());
    };
    let Some(body) = pad_row_body(&raw) else {
        return Ok(());
    };
    if body.is_empty() {
        // A custody fault here leaves the erase as it was before FIX 7192,
        // warned: never refused for it.
        if let Err(error) = store.stage_world_pad_row_erase_in_txn(wtxn, id) {
            tracing::warn!(
                row = %id.to_hex(),
                kind = ?error.kind(),
                "a hard-erased pad shell's custody entry was not staged for retirement"
            );
        }
        return Ok(());
    }
    match decode_pad_body(body) {
        Ok(body) => {
            // Its key leaves the home's kept pad objects too (FIX 7294).
            stage_retained_pad_key_erase_in_txn(store, wtxn, id, &pad_item(body.key()));
            store.stage_world_pad_key_erase_in_txn(wtxn, &pad_item(body.key()))
        }
        Err(_) => {
            tracing::warn!(
                row = %id.to_hex(),
                "a world key pad row that does not decode stages no custody retirement"
            );
            Ok(())
        }
    }
}

/// [`stage_pad_row_erase_in_txn`] for this vault's own delete door and
/// batch delete (FIX 7192): the exact subject the row's key names is staged
/// with no census of custody's states (a header-only shell's found by its
/// subjects' names), and the finisher keeps it pending until it retires. A
/// custody or storage fault leaves the erase as it was before, warned by
/// kind, never refused for it (CALLS: FIX 7192 local pad-row erase).
pub(crate) fn stage_local_pad_row_erase_in_txn(store: &Store, wtxn: &mut RwTxn<'_>, id: &EntityId) {
    if let Err(error) = stage_local_pad_row_retirement_in_txn(store, wtxn, id) {
        tracing::warn!(
            row = %id.to_hex(),
            kind = ?error.kind(),
            "a hard-erased pad row's custody entry was not staged for retirement"
        );
    }
}

fn stage_local_pad_row_retirement_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let Some(raw) = store.port_entity_raw(wtxn, id)?.map(Zeroizing::new) else {
        return Ok(());
    };
    let Some(body) = pad_row_body(&raw) else {
        return Ok(());
    };
    if body.is_empty() {
        return store.stage_world_pad_row_erase_in_txn(wtxn, id);
    }
    match decode_pad_body(body) {
        Ok(body) => {
            // Its key leaves the home's kept pad objects too (FIX 7294).
            stage_retained_pad_key_erase_in_txn(store, wtxn, id, &pad_item(body.key()));
            store.stage_world_pad_key_retirement_in_txn(wtxn, &pad_item(body.key()))
        }
        Err(_) => {
            tracing::warn!(
                row = %id.to_hex(),
                "a world key pad row that does not decode stages no custody retirement"
            );
            Ok(())
        }
    }
}

/// The pad row id of the key a custody `item` (its full id) names; `None`
/// for an item that names no key.
///
/// # Errors
///
/// An id that does not derive.
pub(crate) fn pad_row_of_item(item: &[u8]) -> Result<Option<EntityId>> {
    key_of_id(item).map(|key| pad_row_id(&key)).transpose()
}

/// Whether the pad row of the key a custody `item` (its full id) names was
/// hard-erased here: the custody finisher's check for a retirement
/// [`stage_pad_row_erase_in_txn`] staged.
///
/// # Errors
///
/// Storage faults.
pub(crate) fn pad_row_erased_in_txn(store: &Store, txn: &RoTxn<'_>, item: &[u8]) -> Result<bool> {
    let Some(key) = key_of_id(item) else {
        return Ok(false);
    };
    store.port_deletion_marked(txn, DeletionMarker::HardDelete, &pad_row_id(&key)?)
}

/// Whether a custody head leaves out the pads [`head_carries`] keeps off
/// where it goes (CALLS: KS-5 pad head eligibility). On since FIX 5686 part
/// 2 (FIX 7191): a publication pass seals a hosted member's head apart from
/// a folder's or the residence home's, and a change of a world's setting
/// alone is journaled as a `PublicationPolicy` frame, so every member's head
/// is sealed and acknowledged again (`store::key_custody`
/// `publication_policy`).
const PAD_HEAD_ELIGIBILITY: bool = true;

/// Whether a custody head carries the pads of a world whose sealed copies
/// are `sealed` (CALLS: KS-5 pad head eligibility), `hosted` when the head
/// goes to a hosted member: never with copies off; to the owner's machines
/// and folders alone with copies on his machines; anywhere with copies in
/// the cloud too. A pad the head leaves out stays in this machine's custody.
fn head_carries(sealed: SealedCopies, hosted: bool) -> bool {
    match sealed {
        SealedCopies::Off => false,
        SealedCopies::MyMachines => !hosted,
        SealedCopies::CloudAndMyMachines => true,
    }
}

impl Vault {
    /// The worlds whose pads a custody head sealed now leaves out
    /// ([`head_carries`]), by their settings folded here; a world not folded
    /// here rides with its head (unknown is not ineligible, FIX 4211). None
    /// while [`PAD_HEAD_ELIGIBILITY`] is off.
    ///
    /// # Errors
    ///
    /// Storage faults.
    pub(crate) fn pad_worlds_kept_local(&self, hosted: bool) -> Result<BTreeSet<[u8; 16]>> {
        if !PAD_HEAD_ELIGIBILITY {
            return Ok(BTreeSet::new());
        }
        let txn = self.store.env.read_txn()?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        Ok(fold
            .worlds
            .keys()
            .filter(|world| !head_carries(fold.world_privacy(**world).sealed, hosted))
            .map(|world| *world.as_bytes())
            .collect())
    }
}
