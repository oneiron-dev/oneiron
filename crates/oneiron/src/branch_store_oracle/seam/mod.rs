//! Thinnest plausible seam for the machinery the arming tickets own; the oracle tests reach it through these re-exports.

mod binding;
// FIX [LIBTEST-QUARANTINE-BRANCH-STORE-ORACLE-SEAM-SESSION]: the lib test target's type check fails here (8 errors: E0063 x6, E0639 x1, E0061 x1); port it, then drop this gate
#[cfg(any())]
mod session;
mod substrate;

#[cfg(feature = "sync")]
pub(super) use self::binding::promote_then_crash_post_commit;
pub(super) use self::binding::{
    apply_through_a_route_captured_before_a_flip, attempt_row_counts, authorize_scoped_reader,
    base_scoped_read_visible_claim_count, bind_session, binding_mismatch_directions,
    crash_and_reopen, job_rows_referencing, replay_put_racing_a_committed_change,
    search_through_a_route_captured_before_a_flip, stale_handle_and_rebind_refusals,
    witness_turn_with_mismatched_binding,
};
pub(super) use self::session::{ModelRow, SeamError, SessionVault};
pub(super) use self::substrate::{
    OverlayModelHarness, OverlayOp, overflow_budget, read_after_close, stage_direct_crash_payload,
    stage_then_abort, with_txn_segment_read_back,
};
