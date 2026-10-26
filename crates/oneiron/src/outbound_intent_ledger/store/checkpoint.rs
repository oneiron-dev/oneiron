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
//! Nothing calls this until KS7-5, and only once CHECKPOINT_PAYLOADS_ENABLED
//! is on.
#![allow(
    dead_code,
    reason = "KS7-2b and KS7-5 call the getters; CHECKPOINT_PAYLOADS_ENABLED is false until KS7-6"
)]

use heed::{RoTxn, RwTxn};
use rmpv::Value;

use super::super::codec::{
    KEY_BUDGET_ACCOUNTING, KEY_CREATED_MS, KEY_DELIVERY_UNCERTAIN, KEY_RECORDED_OUTCOME, KEY_STATE,
    KEY_UPDATED_MS,
};
use super::{INTENT_ATTEMPT_INDEX, LEDGER};
use crate::attempt_queue::AttemptId;
use crate::entity_id::bytes_to_hex_lower;
use crate::error::Result;
use crate::store::ManifestDbs;
use crate::store::checkpoint_payload::Subtype;
use crate::store::checkpoint_payload::rows::{
    self, Captured, OpenedOwnerRows, OwnerRef, OwnerRows, Restored, RowLocator, Unresolved,
};

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
fn call(attempt_id: &AttemptId, call_seq: u64) -> Result<OwnerRef> {
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

/// Every ledger record and attempt binding in `txn`, by call.
pub(crate) fn capture(dbs: &impl ManifestDbs, txn: &RoTxn<'_>) -> Result<Captured> {
    let mut out = Captured::default();
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
        out.exact(owner, row.at, row.bytes);
    }
    for row in rows::typed_rows(dbs, txn, INTENT_ATTEMPT_INDEX, &mut out)? {
        let owner = call(&row.key.attempt_id, row.key.call_seq)?;
        out.exact(owner, row.at, row.bytes);
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
