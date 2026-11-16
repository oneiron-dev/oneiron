//! A claim value as the batch door's plan leaves it, for a reader the write
//! asks before the door masks it: the host's auto checker, whose rungs may
//! run off the device (CHECKER-PREVIEW-READS-UNMASKED-CANDIDATE). The claim
//! gate consults it before base apply masks the candidate, so it reads this
//! copy: the value as the write stores it, never a secret the door lifts
//! into custody.

use heed::RwTxn;
use rmpv::Value;

use super::super::{SecretScanMode, sanitize_messagepack_credentials, secret_scan_mode_in_txn};
use super::Masker;
use super::wipe::wipe_value;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::secret_custody::KeptValues;
use crate::store::Store;
use crate::store::known_value_index::KnownValues;

/// `value`, the claim `id`'s, as the batch door's plan leaves it in the
/// writer's transaction: each secret its rules place under a stand-in handle
/// (`[secret sc0]` in text, `sc0` under a credential name), each value
/// custody already holds under that record's handle, and each value the
/// owner kept as text as written. Nothing is minted or written.
///
/// `None` when the copy still holds what a memory read would not serve: a
/// hit no span places (the door refuses such a write), or, with the owner's
/// switch off, a secret the plan leaves as written. The copy is wiped then.
pub(crate) fn plan_masked_claim_value_in_txn(
    store: &Store,
    wtxn: &RwTxn<'_>,
    id: EntityId,
    value: &Value,
) -> Result<Option<Value>> {
    let mut plan = Masker {
        mints: true,
        kept: KeptValues::for_records_in_txn(store, wtxn, [id])?,
        known: KnownValues::shared_in_writer(store, wtxn)?,
        // The switch is off: the plan places known values only (FIX 8644),
        // and the read below refuses what it leaves.
        known_only: secret_scan_mode_in_txn(store, wtxn)? == SecretScanMode::Off,
        places_split_phrases: true,
        at: Some((id, "claim".to_owned())),
        ..Masker::default()
    };
    let mut copy = value.clone();
    // The claim arm's own reading of one value: its texts and fields, then
    // a recovery phrase spread over its parts (LABEL-04).
    let planned = plan
        .mask_value(&mut copy)
        .and_then(|_| plan.mask_spread_phrases(&mut copy, true));
    if let Err(err) = planned {
        wipe_value(&mut copy);
        return Err(err);
    }
    let mut served = copy.clone();
    let withheld = sanitize_messagepack_credentials(&mut served, false);
    wipe_value(&mut served);
    if withheld {
        wipe_value(&mut copy);
        return Ok(None);
    }
    Ok(Some(copy))
}
