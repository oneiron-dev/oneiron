//! The checkpoint getter of the outbound intent ledger (KS7-2): each call's
//! whole frozen record (its payload and its server, tool, endpoint and
//! binding text) and its attempt binding under the call's own compartment,
//! its attempt id and call sequence, never its intent or payload hash. A
//! record names the actor that admitted it (FIX 9283) inside the call's
//! compartment only; the accounting kept outside it stays actor-free. On
//! this head it holds no recorded response, so nothing goes to KS-2B.
//!
//! Its payload is captured as stored: clear, sealed under the call's own
//! ledger custody key (ConnectorResume, generation 0; FIX 9372, 2328), or
//! erased (FIX 9283). A sealed payload opens only at use, through the same
//! ConnectorResume custody restore that PENDING_CALLS' sealed arguments use
//! (FIX 9157).
//!
//! Its accounting and state (what it charged, whether it was sent, settled
//! or abandoned, and when) are also kept as structure outside the
//! compartment, so they outlive the call's erase: a restore that cannot open
//! a call writes neither its record nor its binding, never an empty sendable
//! request, and still knows the call was admitted. It names the call
//! unavailable ([`call_of`]) and drops the attempt's sendable rows (KS7-5).
//!
//! So does the call's per-tool bound (FIX 6260): each call is also kept as
//! one unavailable row, the digest of the server and tool its bound counts
//! it under and its admission times, never the text. The restore writes it
//! back whether the call's compartment opened or not
//! ([`restore_unavailable_in_txn`]), and the bound counts a call that has
//! no record here through it ([`unavailable_calls_since_in_txn`]), so the
//! owner's per-tool bound survives a restore. The accounting rows keep their
//! shape. Nothing calls the getters until KS7-5, and only once
//! CHECKPOINT_PAYLOADS_ENABLED is on.
#![allow(
    dead_code,
    reason = "KS7-2b and KS7-5 call the getters; CHECKPOINT_PAYLOADS_ENABLED is false until KS7-6"
)]

use std::collections::BTreeSet;

use heed::{RoTxn, RwTxn};
use rmpv::Value;

use super::super::codec::{
    KEY_BUDGET_ACCOUNTING, KEY_CREATED_MS, KEY_DELIVERY_UNCERTAIN, KEY_RECORDED_OUTCOME, KEY_STATE,
    KEY_UPDATED_MS,
};
use super::super::types::{IntentEscalationReason, IntentLedgerRecord, RecordedOutboundOutcome};
use super::{AttemptCallKey, INTENT_ATTEMPT_INDEX, LEDGER};
use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::entity_id::bytes_to_hex_lower;
use crate::error::{Error, Result};
use crate::side_table::{self, CodecError, Raw, RawValue, SideKey, SideTable};
use crate::store::ManifestDbs;
use crate::store::checkpoint_payload::Subtype;
use crate::store::checkpoint_payload::rows::{
    self, Captured, OpenedOwnerRows, OwnerRef, OwnerRows, Restored, RowDb, RowLocator, Unresolved,
};

/// The calls this vault holds no record of, by call (FIX 6260): what their
/// admission still counts toward their per-tool bound. Key: id16(attempt) +
/// u64be(call seq).
const UNAVAILABLE: SideTable<AttemptCallKey, UnavailableCall, Raw> =
    SideTable::new(&side_table::OUTBOUND_INTENT_UNAVAILABLE);

/// The domain a per-tool bound's digest derives under.
const TOOL_BOUND_DOMAIN: &str = "oneiron outbound intent per-tool bound v1";

/// One call as its per-tool bound counts it: the digest of its server and
/// tool ([`tool_bound`]), never their text, and when it was admitted and
/// last touched.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct UnavailableCall {
    bound: [u8; 32],
    created_ms: u64,
    updated_ms: u64,
}

impl UnavailableCall {
    fn of(record: &IntentLedgerRecord) -> Self {
        Self {
            bound: tool_bound(&record.server, &record.tool),
            created_ms: record.created_ms,
            updated_ms: record.updated_ms,
        }
    }
}

/// `bound (32) | created_ms (u64be) | updated_ms (u64be)`, exactly.
impl RawValue for UnavailableCall {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        let mut out = self.bound.to_vec();
        out.extend_from_slice(&self.created_ms.to_be_bytes());
        out.extend_from_slice(&self.updated_ms.to_be_bytes());
        Ok(out)
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        let corrupt = || CodecError::from(Error::CorruptedIndex("outbound unavailable call"));
        let (bound, times) = bytes.split_first_chunk::<32>().ok_or_else(corrupt)?;
        let (created, updated) = times.split_first_chunk::<8>().ok_or_else(corrupt)?;
        let updated: [u8; 8] = updated.try_into().map_err(|_| corrupt())?;
        Ok(Self {
            bound: *bound,
            created_ms: u64::from_be_bytes(*created),
            updated_ms: u64::from_be_bytes(updated),
        })
    }
}

/// The digest a per-tool bound counts a call under: its server and tool as
/// the capability lookup compares them (trimmed, ASCII case folded), the
/// server's length first so no two pairs run together.
fn tool_bound(server: &str, tool: &str) -> [u8; 32] {
    let server = server.trim().to_ascii_lowercase();
    let tool = tool.trim().to_ascii_lowercase();
    let mut material = Vec::with_capacity(8 + server.len() + tool.len());
    material.extend_from_slice(&(server.len() as u64).to_be_bytes());
    material.extend_from_slice(server.as_bytes());
    material.extend_from_slice(tool.as_bytes());
    blake3::derive_key(TOOL_BOUND_DOMAIN, &material)
}

/// Whether a record's admission counts toward its per-tool bound: every
/// call but a suppressed semantic duplicate, which never went to transport.
fn counts_toward_bound(record: &IntentLedgerRecord) -> bool {
    record.recorded_outcome
        != Some(RecordedOutboundOutcome::Abandoned(
            IntentEscalationReason::DedupeSuppressed,
        ))
}

/// How many calls of `server` and `tool` with no record here were admitted
/// or last touched at or after `since_ms`, read in `txn` (FIX 6260): every
/// unavailable row whose call has no attempt binding, but the `exclude`d
/// attempt's. A call whose record stands counts through its record. A row
/// that does not decode counts as well: an accounting gap never opens a
/// bound.
///
/// # Errors
///
/// Storage faults.
pub(super) fn unavailable_calls_since_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    server: &str,
    tool: &str,
    since_ms: u64,
    exclude: Option<AttemptId>,
) -> Result<u32> {
    let bound = tool_bound(server, tool);
    let mut counted = 0_u32;
    for row in UNAVAILABLE.iter_raw_from(&vault.store, txn, &[])? {
        let (key, bytes) = row?;
        let counts = match (AttemptCallKey::decode_key(&key), UNAVAILABLE.decode_value(&bytes)) {
            (Some(call), Ok(unavailable)) => {
                unavailable.bound == bound
                    && unavailable.created_ms.max(unavailable.updated_ms) >= since_ms
                    && Some(call.attempt_id) != exclude
                    && !INTENT_ATTEMPT_INDEX.contains(&vault.store, txn, &call)?
            }
            _ => true,
        };
        if counts {
            counted = counted.saturating_add(1);
        }
    }
    Ok(counted)
}

/// Writes a captured call's unavailable row back in `txn` (FIX 6260): the
/// KS7-5 restore calls this for each structure row the ledger's capture
/// kept, whether the call's compartment opened or not, so a call whose
/// record does not come back still counts toward its per-tool bound.
/// `false` for a structure row of another kind, which this writes nothing
/// for.
///
/// # Errors
///
/// A row its codec does not read; storage faults.
pub(crate) fn restore_unavailable_in_txn(
    dbs: &impl ManifestDbs,
    txn: &mut RwTxn<'_>,
    at: &RowLocator,
    value: &[u8],
) -> Result<bool> {
    if !at.in_table(UNAVAILABLE.decl()) {
        return Ok(false);
    }
    rows::check_row(UNAVAILABLE, at, value)?;
    rows::restore_row_in_txn(dbs, txn, at, value)?;
    Ok(true)
}

/// The entries of a record's own map that are its accounting and state.
const ACCOUNTING_KEYS: [&str; 6] = [
    KEY_BUDGET_ACCOUNTING,
    KEY_RECORDED_OUTCOME,
    KEY_DELIVERY_UNCERTAIN,
    KEY_STATE,
    KEY_CREATED_MS,
    KEY_UPDATED_MS,
];

/// The path a call's accounting and state are kept at, before the call.
const ACCOUNTING: &str = "accounting ";

/// A call's compartment: its attempt id (16), then its call sequence
/// (u64be).
pub(super) fn call(attempt_id: &AttemptId, call_seq: u64) -> Result<OwnerRef> {
    let mut id = [0; 24];
    id[..16].copy_from_slice(attempt_id.as_bytes());
    id[16..].copy_from_slice(&call_seq.to_be_bytes());
    let subtype = Subtype::OutboundCall;
    Ok(OwnerRef {
        subtype,
        owner32: subtype.owner(&id)?,
    })
}

/// The attempt and call sequence an outbound-call compartment names, for a
/// restore that drops the sendable rows of a call it could not open.
pub(crate) fn call_of(owner: &OwnerRef) -> Option<(AttemptId, u64)> {
    if owner.subtype != Subtype::OutboundCall {
        return None;
    }
    let attempt_id = AttemptId::from_bytes(&owner.owner32[..16]).ok()?;
    let call_seq = u64::from_be_bytes(owner.owner32[16..24].try_into().ok()?);
    Some((attempt_id, call_seq))
}

/// A call's accounting and state, out of its stored row: the entries of the
/// row's own MessagePack map that [`ACCOUNTING_KEYS`] names, in its order.
fn accounting(bytes: &[u8]) -> Result<Vec<u8>> {
    let mut cursor = bytes;
    let Ok(Value::Map(entries)) = rmpv::decode::read_value(&mut cursor) else {
        return Err(rows::bad_part());
    };
    let kept: Vec<(Value, Value)> = entries
        .into_iter()
        .filter(|(key, _)| {
            key.as_str()
                .is_some_and(|key| ACCOUNTING_KEYS.contains(&key))
        })
        .collect();
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &Value::Map(kept)).map_err(|_| rows::bad_part())?;
    Ok(out)
}

/// Every ledger record and attempt binding in `txn`, by call, with each
/// call's accounting and its unavailable row as structure; and every
/// unavailable row of a call with no record here, as it stands.
pub(crate) fn capture(dbs: &impl ManifestDbs, txn: &RoTxn<'_>) -> Result<Captured> {
    let mut out = Captured::default();
    let mut recorded = BTreeSet::new();
    for row in rows::typed_rows(dbs, txn, LEDGER, &mut out)? {
        let record = &row.value;
        if record.id != row.key {
            out.unclassified(row.at, None, Unresolved::NoOwner);
            continue;
        }
        let owner = call(&record.attempt_id, record.call_seq)?;
        let kept = RowLocator {
            db: row.at.db,
            key: LEDGER.decl().prefix.to_vec(),
            path: format!(
                "{ACCOUNTING}{}:{}",
                bytes_to_hex_lower(record.attempt_id.as_bytes()),
                record.call_seq
            ),
        };
        out.structure(kept, accounting(&row.bytes)?, Vec::new());
        if counts_toward_bound(record) {
            let key = UNAVAILABLE.key_bytes(&AttemptCallKey {
                attempt_id: record.attempt_id,
                call_seq: record.call_seq,
            });
            let value = UNAVAILABLE.encode_value(&UnavailableCall::of(record))?;
            recorded.insert(key.clone());
            let at = RowLocator::row(RowDb::of(UNAVAILABLE.decl()), key);
            out.structure(at, value, Vec::new());
        }
        out.exact(owner, row.at, row.bytes);
    }
    for row in rows::typed_rows(dbs, txn, INTENT_ATTEMPT_INDEX, &mut out)? {
        let owner = call(&row.key.attempt_id, row.key.call_seq)?;
        out.exact(owner, row.at, row.bytes);
    }
    for row in rows::typed_rows(dbs, txn, UNAVAILABLE, &mut out)? {
        if !recorded.contains(&row.at.key) {
            out.structure(row.at, row.bytes, Vec::new());
        }
    }
    Ok(out)
}

fn owns(at: &RowLocator) -> bool {
    at.in_table(LEDGER.decl()) || at.in_table(INTENT_ATTEMPT_INDEX.decl())
}

/// The bundle framing of `rows`' ledger parts.
pub(crate) fn bytes_for_owner(rows: &OwnerRows) -> Result<Vec<u8>> {
    rows::frame_owner(rows, owns)
}

/// A record must read with its codec (its stored shape, digest and intent
/// identity checked) under the id it carries. The hash of a sealed or erased
/// payload is checked when it opens at use, not at restore.
fn check(at: &RowLocator, value: &[u8]) -> Result<()> {
    if at.in_table(LEDGER.decl()) {
        rows::check_row(LEDGER, at, value)?;
        let record = LEDGER.decode_value(value)?;
        if at.key.strip_prefix(LEDGER.decl().prefix) != Some(record.id.as_slice()) {
            return Err(rows::bad_part());
        }
        Ok(())
    } else if at.in_table(INTENT_ATTEMPT_INDEX.decl()) {
        rows::check_row(INTENT_ATTEMPT_INDEX, at, value)
    } else {
        Err(rows::bad_part())
    }
}

/// Puts `opened`'s ledger rows back exactly: a call's record and its
/// binding, or neither.
pub(crate) fn restore_in_txn(
    dbs: &impl ManifestDbs,
    txn: &mut RwTxn<'_>,
    opened: OpenedOwnerRows,
) -> Result<Restored> {
    rows::restore_parts(dbs, txn, &opened, check, rows::no_join)
}
