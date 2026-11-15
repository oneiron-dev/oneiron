//! Door for `tests/mcp_page_continuation_unknown_rows.rs` in
//! oneiron-server (FIX-LIST L23762): park a claim in the gate consent tray,
//! as a gated write the gate pended leaves it, so `vault.writes.pending`
//! serves it. That verb's producer lists no rows in `McpServed`, so its page
//! is the unknown-rows page that test pages.

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::{GateDecisionId, PENDING_GATE_CONSENT_VERSION, PendingGateConsentRecord};

/// Parks `claim` in the consent tray under a decision id made of `seed`,
/// recorded at `created_at`, as a write the gate pended for review leaves it.
///
/// # Errors
/// The vault's and the store's.
pub fn park_pending_write(
    vault: &Vault,
    claim: &EntityId,
    seed: u8,
    created_at: u64,
) -> Result<()> {
    let row = PendingGateConsentRecord {
        version: PENDING_GATE_CONSENT_VERSION,
        claim_id: *claim.as_bytes(),
        decision_id: GateDecisionId::from_bytes([seed; 16]),
        created_at,
        diff_handle: b"mcp-continuation-unknown-rows".to_vec(),
        read_frontier_hash: [seed; 32],
        reason_codes: vec!["gate.pending.review".to_owned()],
        dreamer_run_id: None,
        predicate: None,
        expires_at: None,
    };
    vault.with_write_txn(|wtxn| vault.store.put_pending_gate_consent_in_txn(wtxn, &row))
}
