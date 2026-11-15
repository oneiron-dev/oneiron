//! Doors for `tests/run_changes_journal_cost.rs` (the stored size of a run's
//! change journal rows, `memory::run_review`), `tests/run_revert_unsettled.rs`
//! (a run's claim put that asks Auto), `tests/run_changes_topology.rs` (a
//! run's journal read with no owner) and `tests/run_changes_effects.rs` (a
//! held call's gate receipts joining a run's journal). Compiled only under
//! `--cfg oneiron_test_support`; never API.

use crate::Result;
use crate::claim::ClaimApprovalStatus;
use crate::code_run::{HostSelfDispatcher, SelfDispatchOutcome, SelfMemoryPutClaimCall};
use crate::vault::Vault;

/// Each stored journal row of `run`, in write order: its whole key's and its
/// value's byte lengths.
///
/// # Errors
/// The store's.
#[doc(hidden)]
pub fn journal_row_sizes(vault: &Vault, run: &str) -> Result<Vec<(usize, usize)>> {
    crate::memory::run_review::journal_row_sizes(vault, run)
}

/// The changes `run` wrote, each once and in write order, as
/// `vault.runs.changes.get` lists them, read with no owner.
///
/// # Errors
/// The store's.
#[doc(hidden)]
pub fn journal_changes(vault: &Vault, run: &str) -> Result<serde_json::Value> {
    crate::memory::run_review::journal_changes(vault, run)
}

/// The run's claim put asking Auto of the gates, as a caller's live run asks
/// first (`HostSelfDispatcher::put_claim_from_host`, FIX 3983), without the
/// live run's acquired lease. Code mode asks Proposed, so a run's claim lands
/// at once only this way. A gate that pends the request answers its refusal
/// here; nothing resubmits it Proposed.
///
/// # Errors
/// The gate's refusal, or the store's.
#[doc(hidden)]
pub fn put_claim_asking_auto(
    run: &HostSelfDispatcher<'_>,
    call: SelfMemoryPutClaimCall,
) -> Result<SelfDispatchOutcome> {
    run.dispatch_memory_put_claim_requesting(call, None, ClaimApprovalStatus::Auto, true)
}

/// Appends one external-effect gate receipt with `outcome` on the effect
/// binding `binding`, as the gate records a decision on a held call: its
/// `gate:` ref. Two calls of one AlwaysAsk tool that differ only in their
/// arguments share such a binding, which this door builds with no
/// connector.
///
/// # Errors
/// The store's.
#[doc(hidden)]
pub fn append_effect_receipt(vault: &Vault, outcome: &str, binding: &[u8]) -> Result<String> {
    let record = crate::store::GateDecisionRecord {
        version: 0,
        decision_id: crate::store::GateDecisionId::now(),
        created_at: vault.store.clock.now_recorded_at(),
        outcome: outcome.to_owned(),
        reason_codes: Vec::new(),
        receipt_reasons: Vec::new(),
        system_notices: Vec::new(),
        actor_class: "first_party".to_owned(),
        actor_ref: None,
        content_kind: "external_effect".to_owned(),
        policy_manifest_version: crate::gate::POLICY_SCHEMA_VERSION.to_owned(),
        claim_id: None,
        grant_ref: None,
        diff_handle: binding.to_vec(),
        read_frontier_hash: [0; 32],
        context: Default::default(),
        redacted_at: None,
    };
    let mut wtxn = vault.store.env.write_txn()?;
    vault
        .store
        .append_gate_decision_in_txn(&mut wtxn, &record)?;
    wtxn.commit()?;
    Ok(format!("gate:{}", record.decision_id.to_hex()))
}

/// Joins the gate receipt `receipt` to `run`'s change journal as the held
/// call `call` (its approval target's digest) asks it, in one write, as the
/// outbound chokepoint does.
///
/// # Errors
/// A malformed receipt ref, or the store's.
#[doc(hidden)]
pub fn journal_run_effect(
    vault: &Vault,
    run: &str,
    receipt: &str,
    call: Option<&str>,
) -> Result<()> {
    let id = crate::EntityId::from_hex(receipt.strip_prefix("gate:").unwrap_or(receipt))?;
    let mut wtxn = vault.store.env.write_txn()?;
    crate::memory::run_review::record_run_effect_in_txn(
        &vault.store,
        &mut wtxn,
        run,
        crate::store::GateDecisionId::from_bytes(*id.as_bytes()),
    )?;
    // The base journals no call: the red scratch drops `call`.
    let _ = call;
    wtxn.commit()?;
    Ok(())
}
