//! A world key's pad at rest and on the move (KS-5, FIX 5686, part 1 of 2).
//!
//! A `WORLD_KEY_PAD` row's body takes one of two forms:
//! - the reference, the row at rest: label ‖ world (16) ‖ generation (8,
//!   big-endian) ‖ mint (16) ‖ custody namespace (16). It holds no pad: the
//!   row's header keeps the time it was learned, and the key's custody entry
//!   (kind `WorldPad`, item the key's full id, generation 0) holds the pad.
//!   The namespace is the custody the pad was published into, unsigned; a
//!   reader resolves the pad through this store's own custody.
//! - the carrier, the form a pad row always had: label ‖ world ‖ generation
//!   ‖ mint ‖ pad (32). It is how a pad travels its live routes (its
//!   world's window of the month it was learned, a promotion's pad set, a
//!   scoped door), and how it rests where custody cannot take it.
//!
//! Every put of a pad row passes [`admit_pad_put_in_txn`]: a carrier's pad
//! goes into current custody, synced and its Mint journaled, before the row
//! commits, and the row then stores its reference; a store whose custody is
//! closed (an archived vault) or faults keeps the carrier, as before. Every
//! route a pad row leaves by takes its carrier back from current custody
//! ([`live_route_row`], [`image_pad_row`]); a reference whose pad custody
//! does not hold here does not travel a live route. Until PR 2 (FIX 5686
//! part 2), a checkpoint image carries the carrier as it always did.

use std::collections::BTreeSet;

use heed::{RoTxn, RwTxn};
use zeroize::Zeroizing;

use super::pads::{WorldKeyPad, pad_row_id, world_keys_destroyed_in_txn};
use super::{WorldKeyId, refused};
use crate::Vault;
use crate::authority::SealedCopies;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_WORLD_KEY_PAD;
use crate::store::{Store, WorldPadCustody};

/// The carrier form's label.
const CARRIER_LABEL: &[u8] = b"oneiron/world-key-pad/v1\0";
/// label ‖ world (16) ‖ generation (8, big-endian) ‖ mint (16) ‖ pad (32).
const CARRIER_LEN: usize = CARRIER_LABEL.len() + 16 + 8 + 16 + 32;
/// The reference form's label (CALLS: KS-5 pad reference form).
const REFERENCE_LABEL: &[u8] = b"oneiron/world-key-pad-ref/v1\0";
/// label ‖ world (16) ‖ generation (8, big-endian) ‖ mint (16) ‖ custody
/// namespace (16).
const REFERENCE_LEN: usize = REFERENCE_LABEL.len() + 16 + 8 + 16 + 16;

/// One pad row's body, decoded.
pub(crate) enum PadBody {
    /// The pad itself, as it travels.
    Carrier(WorldKeyId, WorldKeyPad),
    /// The key whose pad current custody holds.
    Reference(WorldKeyId),
}

impl PadBody {
    pub(crate) fn key(&self) -> &WorldKeyId {
        match self {
            Self::Carrier(key, _) | Self::Reference(key) => key,
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

fn encode_reference(key: &WorldKeyId, namespace: &[u8; 16]) -> Vec<u8> {
    let mut body = Vec::with_capacity(REFERENCE_LEN);
    body.extend_from_slice(REFERENCE_LABEL);
    body.extend_from_slice(&pad_item(key));
    body.extend_from_slice(namespace);
    body
}

/// A pad row's body in either form; anything else is malformed.
pub(crate) fn decode_pad_body(body: &[u8]) -> Result<PadBody> {
    let malformed = || Error::CorruptedIndex("world key pad body");
    let (rest, carrier) = if body.len() == CARRIER_LEN && body.starts_with(CARRIER_LABEL) {
        (&body[CARRIER_LABEL.len()..], true)
    } else if body.len() == REFERENCE_LEN && body.starts_with(REFERENCE_LABEL) {
        (&body[REFERENCE_LABEL.len()..], false)
    } else {
        return Err(malformed());
    };
    let world = EntityId::from_bytes(rest[..16].try_into().map_err(|_| malformed())?)
        .map_err(|_| malformed())?;
    let generation = u64::from_be_bytes(rest[16..24].try_into().map_err(|_| malformed())?);
    let mint: [u8; 16] = rest[24..40].try_into().map_err(|_| malformed())?;
    let key = WorldKeyId {
        world,
        generation,
        mint,
    };
    if !carrier {
        return Ok(PadBody::Reference(key));
    }
    let mut pad = Zeroizing::new([0u8; 32]);
    pad.copy_from_slice(&rest[40..72]);
    Ok(PadBody::Carrier(key, WorldKeyPad::from_bytes(pad)))
}

/// The pad `body` resolves to here: a carrier's own, a reference's from
/// current custody. Custody's is never read for a world whose keys were
/// destroyed here: its retirement may still be finishing.
pub(super) fn pad_of_body_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    body: PadBody,
) -> Result<Option<WorldKeyPad>> {
    match body {
        PadBody::Carrier(_, pad) => Ok(Some(pad)),
        PadBody::Reference(key) => {
            if world_keys_destroyed_in_txn(store, txn, key.world)? {
                return Ok(None);
            }
            Ok(store
                .world_pad_in_custody(&pad_item(&key))?
                .map(WorldKeyPad::from_bytes))
        }
    }
}

fn changed() -> Error {
    refused("a world key's pad never changes")
}

/// The put door's admission of a pad row, on every path, local or
/// replicated: the body is one pad in either form, the row id is the one
/// its key derives, no pad lands for a world whose keys were destroyed, and
/// a pad never changes, whether its row or custody holds it. A carrier's pad
/// goes into current custody first ([`take_into_custody`]). Returns the body
/// to store in place of `data`, when it is not `data`: a reference, or the
/// carrier a reference may not replace.
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
    match body {
        // A reference never takes the place of a carrier's pad.
        PadBody::Reference(_) => Ok(match stored {
            Some((PadBody::Carrier(..), held)) => Some(held),
            _ => None,
        }),
        PadBody::Carrier(_, pad) => {
            if let Some((PadBody::Carrier(_, held), _)) = &stored
                && held.bytes() != pad.bytes()
            {
                return Err(changed());
            }
            take_into_custody(store, wtxn, &key, &pad)
        }
    }
}

/// Publishes `key`'s `pad` into current custody in `wtxn`'s writer, synced
/// and its Mint journaled before the row commits, and returns the reference
/// the row stores. A pad custody holds already must be the same; a retired
/// entry is the world's erase. A closed custody (an archived vault) or a
/// custody fault leaves the carrier, warned: the row carries its pad as
/// before.
fn take_into_custody(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    key: &WorldKeyId,
    pad: &WorldKeyPad,
) -> Result<Option<Vec<u8>>> {
    let item = pad_item(key);
    let taken = match store.world_pad_custody_entry(&item) {
        Ok(WorldPadCustody::Live(held)) if *held == *pad.bytes() => Ok(()),
        Ok(WorldPadCustody::Live(_)) => return Err(changed()),
        Ok(WorldPadCustody::Retired) => {
            return Err(refused("the world's keys were destroyed with the world"));
        }
        Ok(WorldPadCustody::Closed) => return Ok(None),
        Ok(WorldPadCustody::Missing) => store.publish_world_pad_in_txn(wtxn, &item, pad.bytes()),
        Err(error) => Err(error),
    };
    match taken {
        Ok(()) => Ok(store
            .world_pad_namespace()
            .map(|namespace| encode_reference(key, &namespace))),
        Err(error) => {
            tracing::warn!(
                kind = ?error.kind(),
                "a world key's pad was not taken into key custody; its row carries it"
            );
            Ok(None)
        }
    }
}

/// What a route that ships the stored row `raw` ships.
enum Shipment {
    /// Not a pad reference: the row as stored.
    AsStored,
    /// A pad reference as its carrier, its pad from current custody.
    Carrier(Vec<u8>),
    /// A pad reference whose pad custody does not hold here.
    PadAbsent,
}

fn shipment(store: &Store, raw: &[u8]) -> Shipment {
    let pad_row = EntityMetadataHeader::parse(raw)
        .is_some_and(|header| header.entity_type == ENTITY_TYPE_WORLD_KEY_PAD);
    let Some(body) = raw.get(ENTITY_METADATA_HEADER_LEN..).filter(|_| pad_row) else {
        return Shipment::AsStored;
    };
    let Ok(PadBody::Reference(key)) = decode_pad_body(body) else {
        return Shipment::AsStored;
    };
    match store.world_pad_in_custody(&pad_item(&key)) {
        Ok(Some(pad)) => {
            let mut row = raw[..ENTITY_METADATA_HEADER_LEN].to_vec();
            row.extend_from_slice(&encode_carrier(&key, &pad));
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
/// and `None` for a reference whose pad custody does not hold here.
pub(crate) fn live_route_row(store: &Store, raw: Vec<u8>) -> Option<Vec<u8>> {
    match shipment(store, &raw) {
        Shipment::AsStored => Some(raw),
        Shipment::Carrier(row) => Some(row),
        Shipment::PadAbsent => None,
    }
}

/// The carrier a pad reference row `raw` is shipped as by a door that hands
/// out every row it admitted (a scoped door, a checkpoint image until FIX
/// 5686 part 2): `None` keeps the row as stored.
pub(crate) fn image_pad_row(store: &Store, raw: &[u8]) -> Option<Vec<u8>> {
    match shipment(store, raw) {
        Shipment::Carrier(row) => Some(row),
        Shipment::AsStored | Shipment::PadAbsent => None,
    }
}

/// Whether a row is stored at `id` whose pad is here, or that is no pad
/// reference: a promotion's pad row lands only where it is not.
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
/// row a live route brings, does: the same header and key, and a carrier's
/// pad the one current custody holds for the stored reference. A stored
/// carrier holds what any reference to its key names. A custody fault reads
/// as not equal: the put door judges the row.
#[cfg(feature = "sync")]
pub(crate) fn pad_echo_equal(store: &Store, stored: &[u8], carried: &[u8]) -> bool {
    if !EntityMetadataHeader::parse(stored)
        .is_some_and(|header| header.entity_type == ENTITY_TYPE_WORLD_KEY_PAD)
        || stored.get(..ENTITY_METADATA_HEADER_LEN) != carried.get(..ENTITY_METADATA_HEADER_LEN)
    {
        return false;
    }
    let (Ok(held), Ok(brought)) = (
        decode_pad_body(&stored[ENTITY_METADATA_HEADER_LEN..]),
        decode_pad_body(&carried[ENTITY_METADATA_HEADER_LEN..]),
    ) else {
        return false;
    };
    if held.key() != brought.key() {
        return false;
    }
    match (held, brought) {
        (_, PadBody::Reference(_)) => true,
        (PadBody::Reference(key), PadBody::Carrier(_, pad)) => matches!(
            store.world_pad_in_custody(&pad_item(&key)),
            Ok(Some(custody)) if *custody == *pad.bytes()
        ),
        (PadBody::Carrier(..), PadBody::Carrier(..)) => false,
    }
}

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
    /// here rides with its head (unknown is not ineligible, FIX 4211).
    ///
    /// # Errors
    ///
    /// Storage faults.
    pub(crate) fn pad_worlds_kept_local(&self, hosted: bool) -> Result<BTreeSet<[u8; 16]>> {
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
