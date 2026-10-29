//! A terminal `dreamer.step` claim's inline response under body custody
//! (KS-2B1, FIX 5683 part B1): an LLM step's and a compaction step's alike.
//!
//! The response is one body instance, bound the first time a checkpoint
//! carries the claim. The image seals the claim's signed body, exactly as it
//! rests, under the instance alone, and its row holds the claim's header and
//! a stub of its body with the step value taken, so a restore's claim
//! authority comparison reads the same read scope before any body lands. A
//! restore under a live instance lands the exact signed bytes, never signed
//! or encoded again; under a retired one the claim takes the erase's shell
//! (its header alone), its claim projection and step-index rows go and it is
//! marked soft-deleted and fenced, as a soft erase leaves it: never a
//! response edited to empty.
//! A response held in an artifact version is the artifact's ASSET body
//! (KS-2A), the exact version pinned to its claim (FIX 6225).

use std::collections::BTreeMap;

use rmpv::Value;

use super::step_claim::{STEP_INDEX_CLAIM, STEP_INDEX_FORWARD, StepIndexClaimKey};
use super::step_state::{STEP_STATE, StepStateOwners, StepStateRow};
use super::types::{DREAMER_STEP_PREDICATE, KEY_RESPONSE, StepProgression};
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::claim::{decode_claim_body, encode_claim_body};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::{EntityStoreMaintenance, ScrubbedRecord};
use crate::side_table::{self, HexId, Raw, SideKey, SideTable};
use crate::store::{ResponseCarriage, ResponseScan, Store};

type Rows = Vec<(Vec<u8>, Vec<u8>)>;

/// The soft-delete marker and the row fence an erase shell carries, as a
/// soft erase writes them.
const SOFT_DELETED: SideTable<HexId, Vec<u8>, Raw> =
    SideTable::new(&side_table::DELETION_IDENTITY_SOFT_DELETE_MARKER);
const FENCED: SideTable<HexId, Vec<u8>, Raw> = SideTable::new(&side_table::DELETION_ROW_FENCE);

/// What a checkpoint carries of the `entities` row `value` when it is a
/// terminal `dreamer.step` claim whose response rests in it: the claim's
/// body; the stub keeps its header and the claim with its step value taken,
/// and a retired instance keeps its header alone. No response for any other
/// row. A body naming the `dreamer.step` predicate that does not decode, or
/// whose stub does not encode, is carried whole past its header as an opaque
/// response (FIX 6227): a header-only shell names none.
pub(crate) fn step_claim_carriage(value: &[u8]) -> ResponseScan {
    let Some(body) = value.get(ENTITY_METADATA_HEADER_LEN..) else {
        return ResponseScan::NotResponse;
    };
    // Most claims are not a step's: their bodies are never decoded here.
    let predicate = DREAMER_STEP_PREDICATE.as_bytes();
    if !body
        .windows(predicate.len())
        .any(|window| window == predicate)
    {
        return ResponseScan::NotResponse;
    }
    let Ok(mut claim) = decode_claim_body(body, true) else {
        return ResponseScan::opaque_claim(value);
    };
    if claim.predicate != DREAMER_STEP_PREDICATE || !holds_response(&claim.value) {
        return ResponseScan::NotResponse;
    }
    claim.value = Value::Nil;
    let Ok(encoded) = encode_claim_body(&claim) else {
        return ResponseScan::opaque_claim(value);
    };
    let mut stub = value[..ENTITY_METADATA_HEADER_LEN].to_vec();
    stub.extend(encoded);
    ResponseScan::Decoded(ResponseCarriage {
        keep: ENTITY_METADATA_HEADER_LEN,
        stub,
        retired: ENTITY_METADATA_HEADER_LEN,
    })
}

/// Whether a `dreamer.step` claim value holds its response inline.
fn holds_response(value: &Value) -> bool {
    matches!(value, Value::Map(entries)
        if entries.iter().any(|(key, _)| key.as_str() == Some(KEY_RESPONSE)))
}

/// The claim an `entities` key names.
fn claim_of(key: &[u8]) -> Result<Option<EntityId>> {
    match <[u8; 16]>::try_from(key) {
        Ok(raw) => EntityId::from_bytes(raw).map(Some),
        Err(_) => Ok(None),
    }
}

/// The erased disposition of the retired claim `key` in raw image rows,
/// beside its row's shell: its claim projection rows and its step-index
/// rows go, as a soft erase removes and deindexes them (FIX 6231), and it is
/// marked soft-deleted and fenced, as a soft erase marks it. Rows stay in
/// order.
///
/// # Errors
///
/// A row that does not decode.
pub(crate) fn retire_step_claim_in_rows(
    databases: &mut BTreeMap<String, Rows>,
    key: &[u8],
) -> Result<()> {
    let Some(claim) = claim_of(key)? else {
        return Ok(());
    };
    if let Some(rows) = databases.get_mut("vault_meta") {
        crate::claim::remove_claim_projection_index_in_rows(rows, claim)?;
        stamp_erased_before_deindex_in_rows(rows, claim)?;
        deindex_in_rows(rows, claim)?;
    }
    if let Some(rows) = databases.get_mut("sync_state") {
        for marker in [
            SOFT_DELETED.key_bytes(&HexId(claim)),
            FENCED.key_bytes(&HexId(claim)),
        ] {
            if let Err(at) = rows.binary_search_by(|(row, _)| row.as_slice().cmp(&marker)) {
                rows.insert(at, (marker, Vec::new()));
            }
        }
    }
    Ok(())
}

/// The erased disposition of the live claim `key` whose instance its
/// source retired, in `wtxn` (an activation's prune): the erase's shell,
/// its header alone, its claim projection and step-index rows gone (FIX 6231)
/// and its soft-delete marker and fence set, as a soft erase leaves it. Its
/// response pins go first, as an erase takes them (FIX 6225).
///
/// # Errors
///
/// Storage and custody errors.
pub(crate) fn retire_step_claim_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    key: &[u8],
) -> Result<()> {
    let Some(claim) = claim_of(key)? else {
        return Ok(());
    };
    super::response_pins::release_step_response_pins_in_txn(store, wtxn, &claim, true)?;
    let recorded_at = crate::ports::recorded_at_in_txn(store, wtxn)?;
    store.port_entity_scrub(wtxn, &claim, ScrubbedRecord::Shell, recorded_at)?;
    crate::claim::remove_claim_projection_index(store, wtxn, claim)?;
    stamp_erased_before_deindex_in_txn(store, wtxn, &claim, recorded_at)?;
    super::step_claim::deindex_dreamer_step_claim(store, wtxn, &claim)?;
    SOFT_DELETED.put(store, wtxn, &HexId(claim), &Vec::new())?;
    FENCED.put(store, wtxn, &HexId(claim), &Vec::new())
}

/// Stamps the step's erased skeleton before deindex (FIX 6658).
fn stamp_erased_before_deindex_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    claim: &EntityId,
    now_ms: u64,
) -> Result<()> {
    let Some(forward) = STEP_INDEX_CLAIM.get(store, wtxn, &StepIndexClaimKey(*claim))? else {
        return Ok(());
    };
    let Some(key) = forward
        .strip_prefix(STEP_INDEX_FORWARD.decl().prefix)
        .and_then(super::step_claim::StepIndexKey::decode_key)
    else {
        return Ok(());
    };
    if STEP_INDEX_FORWARD.get(store, wtxn, &key)?.as_ref() != Some(claim) {
        return Ok(());
    }
    let state = (key.attempt_id, key.step_hash);
    STEP_STATE.put(
        store,
        wtxn,
        &state,
        &StepStateRow {
            progression: StepProgression::Logged,
            started_at: now_ms,
            updated_at: now_ms,
            response_payload: None,
            owners: StepStateOwners { actor: None, subject: None, claim: Some(*claim) },
            erased: true,
        },
    )
}

/// Stamps the same skeleton into raw image rows before they deindex.
fn stamp_erased_before_deindex_in_rows(rows: &mut Rows, claim: EntityId) -> Result<()> {
    let reverse = STEP_INDEX_CLAIM.key_bytes(&StepIndexClaimKey(claim));
    let Ok(at) = rows.binary_search_by(|(row, _)| row.as_slice().cmp(&reverse)) else {
        return Ok(());
    };
    let forward = rows[at].1.clone();
    let Some(key) = forward
        .strip_prefix(STEP_INDEX_FORWARD.decl().prefix)
        .and_then(super::step_claim::StepIndexKey::decode_key)
    else {
        return Ok(());
    };
    if let Ok(at) = rows.binary_search_by(|(row, _)| row.as_slice().cmp(&forward))
        && STEP_INDEX_FORWARD.decode_value(&rows[at].1)? == claim
    {
        let state = (key.attempt_id, key.step_hash);
        let full = STEP_STATE.key_bytes(&state);
        let bytes = STEP_STATE.encode_value(&StepStateRow {
            progression: StepProgression::Logged,
            started_at: 0,
            updated_at: 0,
            response_payload: None,
            owners: StepStateOwners { actor: None, subject: None, claim: Some(claim) },
            erased: true,
        })?;
        match rows.binary_search_by(|(row, _)| row.as_slice().cmp(&full)) {
            Ok(at) => rows[at].1 = bytes,
            Err(at) => rows.insert(at, (full, bytes)),
        }
    }
    Ok(())
}

/// Takes the step-index rows of `claim` out of raw `vault_meta` rows: its
/// reverse row, and the forward row when it still names this claim.
fn deindex_in_rows(rows: &mut Rows, claim: EntityId) -> Result<()> {
    let reverse = STEP_INDEX_CLAIM.key_bytes(&StepIndexClaimKey(claim));
    let Ok(at) = rows.binary_search_by(|(row, _)| row.as_slice().cmp(&reverse)) else {
        return Ok(());
    };
    let (_, forward) = rows.remove(at);
    if let Ok(at) = rows.binary_search_by(|(row, _)| row.as_slice().cmp(&forward))
        && STEP_INDEX_FORWARD.decode_value(&rows[at].1)? == claim
    {
        rows.remove(at);
    }
    Ok(())
}
