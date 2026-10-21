//! A world key pad in a physical image (KS-5, FIX 5686 part 2): a
//! checkpoint or backup image and a Layer-1 artifact carry a pad row as its
//! bare reference (header, the key's full id, the unsigned custody
//! namespace), never its pad; a restore and a side fork take the pad from
//! current scoped custody (CALLS: KS-5 reference-only images).
//!
//! A pad current custody does not hold the same (custody closed, faulted,
//! missing, or holding another pad) keeps its carrier in the image, warned,
//! as every image carried it before ([`PAD_IMAGE_UNPREPARED`]); a restore
//! still drops that row when current custody retired its pad since. A row at
//! rest, its pad beside its reference, is never an image's form: a decode
//! refuses one ([`image_pad_form_ok`]).

use heed::RwTxn;
use zeroize::Zeroizing;

use super::WorldKeyId;
use super::pad_custody::{
    PadBody, decode_pad_body, encode_carrier, encode_reference, encode_resting, pad_item,
    pad_row_body, reference_namespace,
};
use super::pads::{held_pad_world_in_txn, world_keys_destroyed_in_txn};
use crate::Vault;
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_WORLD_KEY_PAD;
use crate::store::{CustodyPlan, PlannedPad, Store, WorldPadCustody, plan_world_pad};

/// What an image carries for a pad current custody does not hold the same
/// (CALLS: KS-5 pad image prepare failure; KS-5 unverified custody keeps
/// carrier).
enum PadImageUnprepared {
    /// Its carrier, warned, as images carried every pad before: an image is
    /// never refused for it, and no pad is left out of it.
    KeepCarrier,
}

const PAD_IMAGE_UNPREPARED: PadImageUnprepared = PadImageUnprepared::KeepCarrier;

/// What a physical image carries for the row `raw` (stored, or a window's)
/// when it is a pad row holding its pad: its bare reference into current
/// custody's namespace when current custody holds that pad, or retired it;
/// else its carrier ([`PAD_IMAGE_UNPREPARED`]). `None` keeps `raw` as it is:
/// any other row, a header-only shell, a bare reference, a body that does
/// not decode, or a carrier custody does not hold.
pub(crate) fn image_pad_projection(store: &Store, raw: &[u8]) -> Option<Vec<u8>> {
    let body = pad_row_body(raw).filter(|body| !body.is_empty())?;
    let decoded = decode_pad_body(body).ok()?;
    let key = *decoded.key();
    let held = decoded.pad()?;
    let custody = store.world_pad_custody_entry(&pad_item(&key));
    let referenced = match &custody {
        Ok(WorldPadCustody::Live(pad)) => **pad == *held.bytes(),
        Ok(WorldPadCustody::Retired) => true,
        Ok(WorldPadCustody::Missing | WorldPadCustody::Closed) | Err(_) => false,
    };
    let namespace = store
        .world_pad_namespace()
        .or_else(|| reference_namespace(body));
    let mut row = raw[..ENTITY_METADATA_HEADER_LEN].to_vec();
    if referenced && let Some(namespace) = namespace {
        row.extend_from_slice(&encode_reference(&key, &namespace));
        return Some(row);
    }
    match PAD_IMAGE_UNPREPARED {
        PadImageUnprepared::KeepCarrier => {
            tracing::warn!(
                kind = ?custody.err().map(|error| error.kind()),
                "a world key pad current custody does not hold rides this image as its carrier"
            );
            if matches!(decoded, PadBody::Carrier(..)) {
                return None;
            }
            row.extend_from_slice(&encode_carrier(&key, held.bytes()));
            Some(row)
        }
    }
}

/// Whether a physical image may carry the row `raw`: anything but a pad row
/// at rest, its pad beside its reference. A body that does not decode is
/// judged where it lands, as before.
pub(crate) fn image_pad_form_ok(raw: &[u8]) -> bool {
    !pad_row_body(raw)
        .filter(|body| !body.is_empty())
        .and_then(|body| decode_pad_body(body).ok())
        .is_some_and(|body| matches!(body, PadBody::Reference(_, Some(_))))
}

/// One pad row an image carries, as a restore plans it.
pub(crate) struct ImagePadRow {
    /// Its key's custody item.
    pub(crate) item: [u8; 40],
    pub(crate) key: WorldKeyId,
    /// The row brings its pad: a carrier the image kept.
    pub(crate) held: bool,
}

/// The pad row `raw` an image carries, when it names a key: `None` for any
/// other row, a header-only shell, or a body that does not decode.
pub(crate) fn image_pad_row_of(raw: &[u8]) -> Option<ImagePadRow> {
    let body = decode_pad_body(pad_row_body(raw).filter(|body| !body.is_empty())?).ok()?;
    Some(ImagePadRow {
        item: pad_item(body.key()),
        key: *body.key(),
        held: body.pad().is_some(),
    })
}

/// The bare reference row `raw` a restore landed, at rest again: the pad
/// this store's current custody holds for it beside its reference, into
/// this store's namespace (else the one it named). `None` for any other
/// row, or when custody holds no pad for it.
///
/// # Errors
///
/// Custody faults.
pub(crate) fn rested_pad_row(store: &Store, raw: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>> {
    let Some(body) = pad_row_body(raw).filter(|body| !body.is_empty()) else {
        return Ok(None);
    };
    let Ok(PadBody::Reference(key, None)) = decode_pad_body(body) else {
        return Ok(None);
    };
    let Some(pad) = store.world_pad_in_custody(&pad_item(&key))? else {
        return Ok(None);
    };
    let Some(namespace) = store
        .world_pad_namespace()
        .or_else(|| reference_namespace(body))
    else {
        return Ok(None);
    };
    let mut row = Zeroizing::new(raw[..ENTITY_METADATA_HEADER_LEN].to_vec());
    row.extend_from_slice(&encode_resting(&key, &namespace, &pad));
    Ok(Some(row))
}

/// The bare reference row `image` with the pad the live row `live` of the
/// same key keeps (its own beside its reference, or a carrier's), as its
/// carrier: a side restore's row whose pad the custody it forks lacks or
/// cannot read (KS-5). `None` when `live` holds no pad of that key.
pub(crate) fn live_pad_carrier(image: &[u8], live: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let key = *decode_pad_body(pad_row_body(image)?).ok()?.key();
    let held = decode_pad_body(pad_row_body(live)?).ok()?;
    let pad = held.pad().filter(|_| *held.key() == key)?;
    let mut row = Zeroizing::new(image.get(..ENTITY_METADATA_HEADER_LEN)?.to_vec());
    row.extend_from_slice(&encode_carrier(&key, pad.bytes()));
    Some(row)
}

/// Every pad row an archived vault holds whose pad its activation's `plan`
/// finds retired: the vault that replaced it erased the pad since, so the
/// row goes, never its own carrier back (KS-5, FIX 5686 part 2). A legal
/// hold on the row, its world or a claim its key seals keeps it, as it
/// keeps a pad from every erase (OF-470). Each other pad is planned too, so
/// the fork copies the live ones. A custody fault planning one keeps its row
/// as it is, warned: the row keeps its own pad.
///
/// # Errors
///
/// Custody and storage faults.
pub(crate) fn plan_archived_pads(
    store: &Store,
    plan: &mut CustodyPlan,
) -> Result<Vec<(EntityId, WorldKeyId)>> {
    let txn = store.env.read_txn()?;
    let mut retired = Vec::new();
    for id in store.port_entity_ids_by_type(&txn, ENTITY_TYPE_WORLD_KEY_PAD, None)? {
        let id = id?;
        let Some(raw) = store.port_entity_raw(&txn, &id)?.map(Zeroizing::new) else {
            continue;
        };
        let Some(row) = image_pad_row_of(&raw) else {
            continue;
        };
        let planned = plan_world_pad(plan, &row.item).unwrap_or_else(|error| {
            tracing::warn!(
                kind = ?error.kind(),
                "an archived pad row's custody did not read; the row stays"
            );
            PlannedPad::Missing
        });
        if planned == PlannedPad::Retired
            && !crate::store::legal_hold::held_in_txn(store, &txn, id.as_bytes())?
            && !held_pad_world_in_txn(store, &txn, &raw)?
        {
            retired.push((id, row.key));
        }
    }
    Ok(retired)
}

/// Tears each pad row of `rows` in `wtxn`: an activation's retired pads.
///
/// # Errors
///
/// Storage faults.
pub(crate) fn drop_pad_rows_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    rows: &[(EntityId, WorldKeyId)],
) -> Result<()> {
    for (id, _) in rows {
        crate::batch::deindex_entity(store, wtxn, id)?;
    }
    Ok(())
}

impl Vault {
    /// Publishes into current custody, before a snapshot takes its custody
    /// guard, each pad a row here holds that custody lacks (a row whose put
    /// found custody faulted), so the image carries it by reference. Never
    /// under the guard: a publication mints. A pad custody still cannot take
    /// is warned and rides the image as its carrier
    /// ([`PAD_IMAGE_UNPREPARED`]).
    ///
    /// # Errors
    ///
    /// Storage faults.
    pub(crate) fn prepare_image_pads(&self) -> Result<()> {
        let mut owed = Vec::new();
        {
            let txn = self.store.env.read_txn()?;
            for id in self
                .store
                .port_entity_ids_by_type(&txn, ENTITY_TYPE_WORLD_KEY_PAD, None)?
            {
                let id = id?;
                let Some(raw) = self.store.port_entity_raw(&txn, &id)?.map(Zeroizing::new) else {
                    continue;
                };
                let Some(Ok(body)) = pad_row_body(&raw)
                    .filter(|body| !body.is_empty())
                    .map(decode_pad_body)
                else {
                    continue;
                };
                let key = *body.key();
                let Some(pad) = body.pad() else {
                    continue;
                };
                if !world_keys_destroyed_in_txn(&self.store, &txn, key.world)?
                    && matches!(
                        self.store.world_pad_custody_entry(&pad_item(&key)),
                        Ok(WorldPadCustody::Missing)
                    )
                {
                    owed.push((key, Zeroizing::new(*pad.bytes())));
                }
            }
        }
        if owed.is_empty() {
            return Ok(());
        }
        self.with_write_txn_grouped(|wtxn| {
            for (key, pad) in &owed {
                if let Err(error) = self
                    .store
                    .publish_world_pad_in_txn(wtxn, &pad_item(key), pad)
                {
                    tracing::warn!(
                        kind = ?error.kind(),
                        "a world key's pad was not taken into key custody before an image; the \
                         image carries it"
                    );
                }
            }
            Ok(())
        })
    }
}
