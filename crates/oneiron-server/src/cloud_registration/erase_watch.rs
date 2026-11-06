//! Pending device-flow cleanup after the owner's hard erase (FIX 10947 S1).
//!
//! A running server's pending device flows live in this process's memory,
//! each bound to the owner whose request started it. When that owner's
//! PERSON hard-erase commits, the pending flow must end instead of staying
//! for a dead owner or linking. Only the exact flow the erased owner
//! started ends: never the flows' global cancel, which bumps the epoch
//! and would kill unrelated co-owners' in-flight starts and polls.
//!
//! The only proof is the committed delete marker, read through the
//! existing public `oneiron::sync::bridge::local_deletion_is_materialized`:
//! a read fault, a soft notice, or an unknown id is not proof, and the
//! flow stays. The probe runs outside the flows guard; only when it
//! proves the erase does the exact handle-plus-actor pair take under the
//! guard. The finalization hooks and the per-server watcher share the one
//! helper below, so the two paths cannot drift.

use oneiron::EntityId;
use oneiron::Vault;

use super::CloudRegistration;

impl CloudRegistration {
    /// The held flows' opaque handles with the actor that started each,
    /// for the erase watch's revalidation passes. Under the flows guard
    /// alone; no vault read happens here, so the caller drops the guard
    /// before it probes.
    pub(crate) fn snapshot_held_flows(&self) -> Vec<(String, EntityId)> {
        self.flows().snapshot_held()
    }

    /// Ends the exact pending flow `handle` names when `actor`'s hard
    /// erase is proven committed, and reports whether it was proven. The
    /// marker probe runs outside the flows guard; only `Ok(true)` is
    /// proof, and any read fault preserves the flow. On proof the exact
    /// handle-plus-actor pair takes under the guard, with no epoch
    /// movement and no global cancel. The answer is the erase proof even
    /// when another pass took the flow first: the caller still ends the
    /// flow rather than leaving it pending.
    pub(crate) fn take_flow_if_owner_erased(
        &self,
        vault: &Vault,
        handle: &str,
        actor: &EntityId,
    ) -> bool {
        let erased = matches!(
            oneiron::sync::bridge::local_deletion_is_materialized(vault, actor),
            Ok(true)
        );
        if erased {
            let _ = self.flows().take(handle, actor);
        }
        erased
    }
}
