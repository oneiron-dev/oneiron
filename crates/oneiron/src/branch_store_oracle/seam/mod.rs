//! Thinnest plausible seam for the machinery the arming tickets own; the oracle tests reach it through these re-exports.

mod binding;
mod session;
mod substrate;

#[cfg(feature = "sync")]
pub(super) use self::binding::promote_then_crash_post_commit;
pub(super) use self::binding::{
    apply_through_a_route_captured_before_a_flip, attempt_row_counts,
    base_batch_referencing_overlay_id, base_scoped_read_visible_claim_count, bind_session,
    binding_mismatch_directions, crash_and_reopen, job_rows_referencing, open_with_abi_pair,
    replay_put_racing_a_committed_change, search_through_a_route_captured_before_a_flip,
    stale_handle_and_rebind_refusals, witness_turn_with_mismatched_binding,
};
pub(super) use self::session::{ModelRow, SeamError, SessionVault};
pub(super) use self::substrate::{
    OverlayModelHarness, OverlayOp, overflow_budget, read_after_close,
    snapshot_vs_concurrent_apply, stage_direct_crash_payload, stage_then_abort,
    with_txn_segment_read_back,
};
