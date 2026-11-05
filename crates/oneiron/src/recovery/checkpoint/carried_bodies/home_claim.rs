//! Native checkpoint streams for retained StepClaim embedding copies.

use std::collections::{BTreeMap, BTreeSet};

use heed::RoTxn;

use super::super::{CanonicalRows, CheckpointImage, codec_error, response_rows};
use super::CarriedInline;
use crate::store::{ResponseDb, Store, response_carrier, response_instance_owner_in_rows};
use crate::sync::queue::{
    capture_home_claim_copy, home_claim_copy_skeleton, restore_home_claim_copy,
};
use crate::{EntityId, Result};

fn belongs(database: &str, key: &[u8]) -> bool {
    database == "sync_queue" && key.starts_with(b"e:")
}

pub(in crate::recovery::checkpoint) fn note(
    store: &Store,
    txn: &RoTxn<'_>,
    key: &[u8],
    value: &[u8],
) -> Result<Option<(CarriedInline, Vec<u8>, Vec<u8>)>> {
    let Some(copy) = capture_home_claim_copy(store, txn, key, value)? else {
        return Ok(None);
    };
    let carried = CarriedInline {
        database: "sync_queue".to_owned(),
        key: key.to_vec(),
        keep: u32::try_from(copy.keep).map_err(|_| codec_error())?,
        instance: copy.instance,
        digest: *blake3::hash(&copy.body).as_bytes(),
        len: copy.body.len() as u64,
        stored_len: 0,
        retired: Some(u32::try_from(copy.skeleton.len()).map_err(|_| codec_error())?),
        landed_len: None,
        opaque: false,
        superseded: false,
        replay: None,
    };
    Ok(Some((carried, copy.body, copy.skeleton)))
}

fn checked_skeleton(carried: &CarriedInline, value: &[u8]) -> Result<EntityId> {
    let (id, keep) = home_claim_copy_skeleton(&carried.key, value)?;
    if carried.keep as usize != keep
        || carried.retired.map(|len| len as usize) != Some(value.len())
        || carried.len <= size_of::<u32>() as u64
        || carried.landed_len.is_some()
        || carried.opaque
        || carried.superseded
        || carried.replay.is_some()
    {
        return Err(codec_error());
    }
    Ok(id)
}

/// Historical obligations name the original instance when a later current
/// response binding names a different one. No other history is required.
pub(in crate::recovery::checkpoint) fn required_instances(
    inline: &[CarriedInline],
    databases: &BTreeMap<String, CanonicalRows>,
) -> Result<BTreeSet<[u8; 16]>> {
    let mut named = BTreeSet::new();
    let mut rows_seen = BTreeSet::new();
    for carried in inline
        .iter()
        .filter(|body| belongs(&body.database, &body.key))
    {
        if !rows_seen.insert(carried.key.as_slice()) {
            return Err(codec_error());
        }
        let rows = databases.get("sync_queue").ok_or_else(codec_error)?;
        let at = rows
            .binary_search_by(|(row, _)| row.as_slice().cmp(&carried.key))
            .map_err(|_| codec_error())?;
        let id = checked_skeleton(carried, &rows[at].1)?;
        let carrier = response_carrier(ResponseDb::Entities, id.as_bytes());
        if !response_instance_owner_in_rows(
            databases.get("vault_meta").ok_or_else(codec_error)?,
            id,
            carried.instance,
            &carrier,
        )? {
            return Err(codec_error());
        }
        named.insert(carried.instance);
    }
    Ok(named)
}

/// A retired copy leaves its genuine pending job, not an erased claim and
/// not a truncated header whose length still names unavailable bytes.
pub(in crate::recovery::checkpoint) fn retire(
    image: &mut CheckpointImage,
    database: &str,
    key: &[u8],
) -> Result<bool> {
    if !belongs(database, key) {
        return Ok(false);
    }
    let rows = image.databases.get_mut(database).ok_or_else(codec_error)?;
    let value = response_rows::row_mut(rows, key)?;
    home_claim_copy_skeleton(key, value)?;
    Ok(true)
}

pub(in crate::recovery::checkpoint) fn land(
    store: &Store,
    carried: &CarriedInline,
    value: &mut Vec<u8>,
    body: &[u8],
) -> Result<bool> {
    if !belongs(&carried.database, &carried.key) {
        return Ok(false);
    }
    checked_skeleton(carried, value)?;
    *value = restore_home_claim_copy(store, &carried.key, value, carried.instance, body)?;
    Ok(true)
}
