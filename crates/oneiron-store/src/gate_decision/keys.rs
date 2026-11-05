//! Gate-decision ledger key prefixes, key constructors, and the id successor.

use crate::pending_gate_consent::keys::hashed_string_index_prefix;
use crate::pending_gate_consent::keys::index_key_with_id;
use crate::pending_gate_consent::keys::string_index_prefix;
use oneiron_base::error::Error;
use oneiron_base::error::Result;

pub const GATE_DECISION_KEY_PREFIX: &[u8] = b"gate_decision:v0:";

// The `gate_delete_pending:v0:` crash-recovery sidecar and the
// `gate_delete_required:v0:` durable-proof marker moved onto the typed
// `PENDING_DELETION`/`DELETE_REQUIRED` side tables in `gate_decision/sidecar.rs`
// (side_table::GATE_DELETE_PENDING_SIDECAR / GATE_DELETE_REQUIRED_MARKER); the
// hand-spelled prefixes and key builders that used to live here are gone.

pub const GATE_DECISION_GRANT_REF_INDEX_PREFIX: &[u8] = b"gate_decision:grant_ref_index:v1:";

/// ERASE-A (ONE-1637) claim-keyed secondary index over the Gate decision
/// ledger: `prefix ‖ claim_id(16B) ‖ decision_id(16B)`, empty value.
///
/// ACCELERATION ONLY. Erase-completeness verification must never consult it —
/// an index cannot vouch for the completeness of the erase it accelerated (see
/// [`Store::verify_claim_erasure_by_scan_in_txn`]).
///
/// INVARIANT: every mutation of a `gate_decision:v0:` row MUST route through
/// `append_gate_decision_in_txn` (the sole write route) or
/// `delete_gate_decision_record_in_txn` (the sole primary-delete route, which
/// drops this index row and the grant-ref index row in the same transaction).
/// A future deleter loads/decodes the record and calls the latter; a raw
/// `vault_meta.delete` of a primary key orphans both indexes. The
/// `gate_delete_pending:v0:` recovery sidecar is a distinct keyspace and is not
/// covered by this rule.
pub const GATE_DECISION_CLAIM_INDEX_PREFIX: &[u8] = b"gate_decision_by_claim:v0:";

/// Durable proof that every pre-existing ledger row is claim-indexed. While
/// ABSENT, per-claim discovery falls back to a full keyspace scan; erase is
/// never refused during backfill.
pub const GATE_DECISION_CLAIM_INDEX_BACKFILL_COMPLETE_KEY: &[u8] =
    b"gate_decision_by_claim_backfill_complete";

/// Only accepted value byte for the backfill-complete flag row.
pub const GATE_DECISION_CLAIM_INDEX_BACKFILL_COMPLETE_VALUE: [u8; 1] = [1];

pub const ATTEMPT_RUN_INDEX_PREFIX: &[u8] = b"job:run_index:v2:";

pub fn gate_decision_upper_bound() -> Vec<u8> {
    let mut key = Vec::from(GATE_DECISION_KEY_PREFIX);
    let last = key
        .last_mut()
        .expect("gate decision key prefix must be non-empty");
    *last = last
        .checked_add(1)
        .expect("gate decision key prefix upper bound must not overflow");
    key
}

pub fn gate_decision_grant_ref_index_prefix(grant_ref: &str) -> Vec<u8> {
    string_index_prefix(GATE_DECISION_GRANT_REF_INDEX_PREFIX, grant_ref)
}

/// Both key components are fixed 16-byte ids, so the index needs no
/// `string_index_prefix` length header to stay unambiguous.
pub fn gate_decision_claim_index_prefix(claim_id: &[u8; 16]) -> Vec<u8> {
    index_key_with_id(GATE_DECISION_CLAIM_INDEX_PREFIX, claim_id)
}

pub fn attempt_run_index_prefix(run_id: &str) -> Vec<u8> {
    hashed_string_index_prefix(ATTEMPT_RUN_INDEX_PREFIX, run_id)
}

pub fn attempt_run_index_key(run_id: &str, attempt_id: &[u8; 16]) -> Vec<u8> {
    index_key_with_id(&attempt_run_index_prefix(run_id), attempt_id)
}
