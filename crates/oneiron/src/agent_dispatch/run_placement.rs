//! Cloud placement of an agent run at its dispatch (FIX 4747 slice 7; canon
//! CROSS-ARCH-0019 "Where work runs", item 01: "Cloud users run in the
//! cloud").
//!
//! When the vault's elected home node is a cloud node and this machine is
//! not it, the dispatch mints the run TASK's lease released (`held_until` =
//! now, `super::run_task::mint_agent_run_task_in_txn`), so the cloud's
//! reaper, which takes at expiry as the home node (`super::run_handover`),
//! takes the run at once. This machine's claim of the run's try leaves that
//! lease for [`AGENT_RUN_CLOUD_PLACEMENT_GRACE_SECS`] past its release;
//! after the grace it takes its own expired lease again at its claim, as
//! before, so a cloud that cannot run the run never strands it. A vault with
//! no elected home, or whose home is this machine or no cloud node, places
//! nothing: its runs run where they were dispatched, as before.

use super::run_task::AgentRunExecutorLease;
use crate::Vault;
use crate::dreamer_runner::{DreamerHomeNodeClass, DreamerRunnerStore};
use crate::error::Result;

/// How long past its release a run's own lease is left for a cloud home
/// elsewhere at this machine's claim (FIX 4747 slice 7). Engine call (CALLS,
/// FIX 4747): two minutes, four agent pump rechecks, inside the five-minute
/// handover grace other machines wait (`AGENT_RUN_HANDOVER_GRACE_SECS`), so
/// the cloud takes first and the dispatching machine next.
pub(super) const AGENT_RUN_CLOUD_PLACEMENT_GRACE_SECS: u64 = 2 * 60;

/// Whether the vault's elected home node is a cloud node other than this
/// machine (`node_id`), read in `txn` (FIX 4747 slice 7). Engine call
/// (CALLS, FIX 4747): the committed MACRO home designation the handover's
/// ruled order reads (`run_handover::elected_home_here_in`) names the node;
/// the host's home candidacy says whether it is a cloud node, by its
/// `cloud` flag. A candidacy that lists no row for that node falls back to
/// the designation's own election class (`CloudAttached`). No designation
/// places nothing.
pub(super) fn cloud_home_elsewhere_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    node_id: u64,
) -> Result<bool> {
    let store = DreamerRunnerStore::new(vault);
    let Some(home) = store.home_node_designation_in_txn(txn)? else {
        return Ok(false);
    };
    if home.node_id == node_id {
        return Ok(false);
    }
    let listed = store.home_candidates_in_txn(txn)?.and_then(|candidates| {
        candidates
            .into_iter()
            .find(|candidate| candidate.node_id == home.node_id)
    });
    Ok(match listed {
        Some(candidate) => candidate.cloud,
        None => home.class == DreamerHomeNodeClass::CloudAttached,
    })
}

/// Whether this machine's claim at `now` leaves its own open run's `lease`
/// for the vault's cloud home (FIX 4747 slice 7). Engine call (CALLS, FIX
/// 4747): only while the home is a cloud node elsewhere
/// (`cloud_home_elsewhere`), the lease is expired (minted released, or
/// released or lapsed since), and less than
/// [`AGENT_RUN_CLOUD_PLACEMENT_GRACE_SECS`] has passed since its
/// `held_until`. A lease still held runs here as before.
pub(super) fn leaves_lease_for_cloud(
    lease: AgentRunExecutorLease,
    cloud_home_elsewhere: bool,
    now: u64,
) -> bool {
    cloud_home_elsewhere
        && lease.expired_at(now)
        && now
            < lease
                .held_until
                .saturating_add(AGENT_RUN_CLOUD_PLACEMENT_GRACE_SECS)
}
