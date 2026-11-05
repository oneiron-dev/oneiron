//! A durable executor run's wait replies as rows: the delivery a waiter was
//! given, the reply a wait settled with, and what each run holds of it. The
//! code run layer (`code_run::storage`) parks, delivers, settles and erases
//! waits; the store's response body scan, owner lists and shared-wait custody
//! read these rows.
use serde::{Deserialize, Serialize};

use crate::side_table::{
    self, CodecError, ErasedForm, Named, Raw, RawValue, SideKey, SideTable, SideTableDbs,
};
use crate::store::{ResponseCarriage, ResponseScan, is_opaque_erased};
use crate::{EntityId, Error, Result};

/// The reply one wait was answered with, and when it was delivered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WaitDelivery {
    /// The reply as JSON text.
    pub reply: String,
    pub delivered_at_ms: u64,
    /// The rows the reply was derived from, as its settler listed them
    /// (FIX 5455): the rows a connector call's passes picked. `None` when
    /// its settler listed none: the reply then adds no row to its run's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_rows: Option<Vec<EntityId>>,
    /// Whether an erase of its holder's actor took the reply (FIX 5718):
    /// its text is gone, and when it came and its rows stay.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub erased: bool,
}

/// A delivery's erased form (FIX 5718): when it came and the rows its reply
/// was derived from stay, its reply goes. An erase writes it past the
/// side-row wall.
impl ErasedForm for WaitDelivery {
    fn into_erased(self) -> Result<Self> {
        Ok(Self {
            reply: String::new(),
            erased: true,
            ..self
        })
    }
}

impl RawValue for WaitDelivery {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        serde_json::to_vec(self).map_err(|_| Error::CorruptedIndex("code-run wait delivery").into())
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        serde_json::from_slice(bytes)
            .map_err(|_| Error::CorruptedIndex("code-run wait delivery").into())
    }
}

/// Leads a wait's settled row: `s` + wait → the reply it settled with.
pub(crate) const SETTLED_TAG: [u8; 1] = *b"s";

pub(crate) const DELIVERIES: SideTable<(EntityId, EntityId, u64), WaitDelivery, Raw> =
    SideTable::new(&side_table::CODE_RUN_WAIT_DELIVERY);
/// Whether a masked copy of a `CODE_RUN_WAIT_DELIVERY` row still decodes as its typed value,
/// for the historical lift sweep (FIX 2680).
pub(crate) fn code_run_wait_delivery_accepts_masked(bytes: &[u8]) -> bool {
    crate::side_table::decodes::<WaitDelivery, Raw>(bytes)
}

/// The wait's first reply, kept as the delivery every later waiter gets.
pub(crate) const SETTLED: SideTable<([u8; 1], EntityId), WaitDelivery, Raw> =
    SideTable::new(&side_table::CODE_RUN_WAIT_INDEX);

/// The rows. Key: id16(wait) + id16(run) + be64(generation).
pub(crate) const HOLDERS: SideTable<(EntityId, EntityId, u64), WaitHolder, Named> =
    SideTable::new(&side_table::CODE_RUN_WAIT_HOLDER);

/// What one run holds of a wait's reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum WaitHolder {
    /// The reply, for `actor`'s run, when its run's stamps name one.
    Kept { actor: Option<EntityId> },
    /// Its run's actor was erased: the reply reads as erased for it, for
    /// good.
    Erased,
}

impl WaitHolder {
    pub(crate) const fn actor(self) -> Option<EntityId> {
        match self {
            Self::Kept { actor } => actor,
            Self::Erased => None,
        }
    }

    pub(crate) const fn erased(self) -> bool {
        matches!(self, Self::Erased)
    }
}

/// The wait a settled row's full `vault_meta` key names: the wait index's
/// `s` rows alone, never a waiter's.
fn settled_wait(key: &[u8]) -> Option<EntityId> {
    let (tag, wait) = key.strip_prefix(SETTLED.decl().prefix)?.split_first()?;
    if *tag != SETTLED_TAG[0] {
        return None;
    }
    EntityId::decode_key(wait)
}

/// Whether the full `vault_meta` key `key` is a wait's settled row.
pub(crate) fn settled_wait_key(key: &[u8]) -> bool {
    settled_wait(key).is_some()
}

/// What a checkpoint carries of a delivery's or a settled reply's row: the
/// whole row, its erased form the stub an image holds in its place. No
/// response for a row already erased; a row that does not decode, or whose
/// erased form does not encode, is carried whole as an opaque response.
pub(crate) fn wait_reply_scan(value: &[u8]) -> ResponseScan {
    let Ok(reply) = DELIVERIES.decode_value(value) else {
        return ResponseScan::opaque_row();
    };
    if reply.erased {
        return ResponseScan::NotResponse;
    }
    match reply
        .into_erased()
        .and_then(|erased| DELIVERIES.encode_value(&erased))
    {
        Ok(stub) => ResponseScan::Decoded(ResponseCarriage::whole(stub)),
        Err(_) => ResponseScan::opaque_row(),
    }
}

/// Whether a delivery's or a settled reply's row `value` is an erased one:
/// its decoded erased form, or the erased marker of one that never decoded.
pub(crate) fn wait_reply_erased(value: &[u8]) -> bool {
    is_opaque_erased(value)
        || DELIVERIES
            .decode_value(value)
            .is_ok_and(|reply: WaitDelivery| reply.erased)
}

/// Who holds the settled row `key`'s reply (a full `vault_meta` key): each
/// membership of its wait that keeps it, once, by the actor it names (its
/// run's when it names none; a connector caller's is the caller). An erased
/// membership holds nothing.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn wait_settled_owners(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    key: &[u8],
) -> Result<Vec<EntityId>> {
    let Some(wait) = settled_wait(key) else {
        return Ok(Vec::new());
    };
    let mut owners = Vec::new();
    for row in HOLDERS.iter_raw_from(dbs, txn, wait.as_bytes())? {
        let (key, bytes) = row?;
        if let Ok(WaitHolder::Kept { actor }) = HOLDERS.decode_value(&bytes)
            && let Some((_, holder, _)) = <(EntityId, EntityId, u64) as SideKey>::decode_key(&key)
        {
            owners.push(actor.unwrap_or(holder));
        }
    }
    owners.sort_unstable();
    owners.dedup();
    Ok(owners)
}

/// Whether the settled row `key` (a full `vault_meta` key) still holds its
/// reply live: present and not in its erased form. A row that does not
/// decode still holds it (an opaque reply its holders keep), and the erased
/// marker holds none (FIX 9390).
///
/// # Errors
///
/// Storage errors.
pub(crate) fn settled_reply_held_in_txn(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    key: &[u8],
) -> Result<bool> {
    let Some(wait) = settled_wait(key) else {
        return Ok(false);
    };
    Ok(SETTLED
        .get_bytes(dbs, txn, &(SETTLED_TAG, wait))?
        .is_some_and(|bytes| {
            !is_opaque_erased(&bytes)
                && !SETTLED.decode_value(&bytes).is_ok_and(|reply| reply.erased)
        }))
}
