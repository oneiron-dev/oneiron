// Code-memory anchors, row tables and multi-writer slots.
// The ordinary write entry is `attach_code_memory`.
// This fragment defines items in `code_memory::implementation`, not a child module.

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};
use std::ops::ControlFlow;

use heed::{RoTxn, RwTxn};

use crate::Vault;
#[cfg(test)]
use crate::code_document::CodeSpanAnchor;
#[cfg(test)]
use sha2::{Digest, Sha256};
#[cfg(test)]
use crate::side_table::{self, Raw, RawValue, SideTable};

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{ClaimSource, ScopedRead};
use crate::edge::{EdgeActorClass, EdgeKind};
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{CodeError, Error, Result};
use oneiron_retrieval::pipeline::ScoredEntity;
use crate::ppr::{PprNodeVisibility, SeedWeighting, ppr_query_scoped_in_txn};
use crate::provenance::validate_actor_class;
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_CODE_SYMBOL, ENTITY_TYPE_NOTE};
use crate::scan_check::{EngineScan, ScanCount};
use crate::store::Store;
use crate::temporal::TimeRange;
#[cfg(test)]
use crate::write_envelope::WriteActor;

// ---------------------------------------------------------------------------
// Section 1 — dual anchor: symbol identity plus revision locator
// ---------------------------------------------------------------------------

pub use crate::store::code_memory_values::{
    CODE_MEMORY_CONTENT_HASH_LEN, CODE_MEMORY_SLOT_NAME_MAX_BYTES, CODE_MEMORY_MAX_VALUES_PER_SLOT, CODE_MEMORY_MAX_ALWAYS_ON_CONTRACTS, CODE_MEMORY_PPR_DEPTH, CODE_MEMORY_DEFAULT_PULL_LIMIT, CODE_MEMORY_MAX_PULL_LIMIT, CODE_MEMORY_CURSOR_MAX_BYTES, CodeMemoryPayloadRef, CodeMemoryLocator, CodeMemoryAnchor, CodeMemoryAttachment, CodeMemorySlotName, CodeMemorySlotValue, CodeMemorySlot, SlotInsertOutcome, AttachCodeMemory, AnchorTransferKind, AnchorTransfer, AnchorTransferReceipt, AnchorTransferRecord, BlocksWriteContext, CodeMemoryContractKind, AlwaysOnCodeMemoryContract, ProvenanceMaterialKind, CodeMemoryProvenance, ProvenanceLabelled, CodeMemoryPullRequest
};
pub(crate) use crate::store::code_memory_values::{
    SLOT, ATTACHMENT, ALWAYS_ON, TRANSFER, archive_code_memory_tables, record_error, validate_slot_name, validate_time_range, key_with_symbol, key_with_slot, key_with_payload, slot_symbol_prefix, slot_key, attachment_symbol_prefix, attachment_slot_prefix, attachment_key, always_on_symbol_prefix, always_on_key, transfer_key, sha256, push_u16, push_u32, push_u64, push_text, push_time_range, push_payload, push_bytes, push_locator, encode_slot, decode_slot, encode_attachment_row, decode_attachment_row, encode_always_on, decode_always_on, encode_transfer_identity, encode_transfer_record, decode_transfer_record
};

/// Restart probability for an L2 pull, copied from the landed code-symbol
/// PPR entry.
const CODE_MEMORY_PPR_ALPHA: f32 = 0.15;

/// The only ordinary attachment write: it appends/merges, never replaces.
///
/// Validates the symbol anchor and locator, loads the named slot, applies
/// [`CodeMemorySlot::insert_multi_value`], then rewrites the slot body AND
/// re-derives the `(symbol, slot)` attachment-index rows FROM THE WRITTEN
/// BODY — so a payload that loses the actor-scoped dedupe never receives an
/// index row. All in the caller's one transaction.
///
/// The anchor's locator labels ONLY the payloads this attach introduces. A
/// payload already carrying an attachment row keeps the locator it was first
/// attached under: a later write into the same slot is not a relabelling of
/// the material already there.
pub fn attach_code_memory(
    store: &Store,
    txn: &mut RwTxn<'_>,
    input: AttachCodeMemory,
) -> Result<SlotInsertOutcome> {
    let AttachCodeMemory {
        anchor,
        slot: slot_name,
        value,
    } = input;
    validate_code_symbol_anchor(store, txn, &anchor.symbol_id)?;
    anchor.locator.validate()?;
    value.validate()?;

    let mut slot = read_slot(store, txn, &anchor.symbol_id, &slot_name)?
        .unwrap_or_else(|| CodeMemorySlot::empty(slot_name));
    let outcome = slot.insert_multi_value(value)?;

    write_slot(store, txn, &anchor.symbol_id, &slot)?;
    observe_slot_values(store, txn, &anchor.symbol_id, &slot);
    // Nothing is relabelled by an attach: a payload without a row is new and
    // takes this anchor's locator, and every other payload keeps its own.
    derive_attachment_rows(
        store,
        txn,
        &anchor.symbol_id,
        &slot,
        &anchor.locator,
        &BTreeSet::new(),
    )?;
    Ok(outcome)
}

/// One written slot's value count against its scan row: past it the write
/// keeps every value and raises the `code_memory_slot_values` check (FIX
/// 8562). A threshold row that does not read skips the observation, never
/// the write.
fn observe_slot_values(
    store: &Store,
    txn: &RoTxn<'_>,
    symbol_id: &EntityId,
    slot: &CodeMemorySlot,
) {
    if let Ok(mut count) = ScanCount::start(
        store,
        txn,
        EngineScan::CodeMemorySlotValues,
        symbol_id.as_bytes(),
    ) {
        count.rows(slot.values.len());
        count.defer(store);
    }
}

/// One symbol's always-on contract keys, `registered`, against their scan
/// row: past it the registration or transfer keeps every contract and
/// raises the `code_memory_always_on_contracts` check (FIX 8562).
fn observe_always_on_contracts(
    store: &Store,
    txn: &RoTxn<'_>,
    symbol_id: &EntityId,
    registered: usize,
) {
    if let Ok(mut count) = ScanCount::start(
        store,
        txn,
        EngineScan::CodeMemoryAlwaysOnContracts,
        symbol_id.as_bytes(),
    ) {
        count.rows(registered);
        count.defer(store);
    }
}
