//! The source half of the host-order legal holds a cold restore carries
//! (FIX 1485): `host_order_holds`, its pages and its confirm (FIX 6820),
//! answered under the reap freeze.

use std::sync::atomic::Ordering;

use oneiron_vault_contract::restore::{
    HostHoldsCursor, HostHoldsSource, HostOrderHoldsExport, HostOrderHoldsNotProven,
    ManagedRestoreIdentity,
};

use super::super::ManagedState;
use crate::managed::ManagedError;

impl ManagedState {
    /// This vault's whole host-order family for the cold restore attempt
    /// `identity` names, as the page at `cursor`. It answers only for the
    /// vault `source` names, only while frozen for reap, and only while
    /// quiescent as `prepare_reap` judges it, before the read and again
    /// after it; anything else answers not proven, never an empty family.
    /// Each page reads the family again, whole, in one read transaction, and
    /// names its id, so a family that changed between pages answers
    /// `export_changed`. A cursor at the family's end is the confirm (FIX
    /// 6820): the same checks and the same read, answered with no bytes
    /// while the family is still the cursor's and `export_changed` once it
    /// is not. It writes no hold, keeps nothing between pages and
    /// changes no reap state; the lease drain is the one `prepare_reap`
    /// runs.
    pub(in crate::managed::state_serve) async fn host_order_holds(
        &self,
        identity: &ManagedRestoreIdentity,
        source: &HostHoldsSource,
        cursor: Option<&HostHoldsCursor>,
    ) -> Result<HostOrderHoldsExport, ManagedError> {
        let not_proven = |reason| HostOrderHoldsExport::NotProven {
            identity: identity.clone(),
            source: source.clone(),
            reason,
        };
        if source.registry_id != self.vault_name
            || source.engine_vault_id != self.server.vault().vault_key_vault_id()
        {
            return Ok(not_proven(HostOrderHoldsNotProven::SourceMismatch));
        }
        if !self.is_frozen() {
            return Ok(not_proven(HostOrderHoldsNotProven::NotFrozen));
        }
        // Read before the drain and the export, as `prepare_reap` reads it.
        let in_flight = self.http_mutating_in_flight.load(Ordering::SeqCst);
        let drained = self.drain_lease_table().await;
        if !self.quiescent(in_flight, drained) {
            return Ok(not_proven(HostOrderHoldsNotProven::NotQuiescent));
        }
        let family = match self.server.vault().carried_host_order_holds() {
            Ok(family) => family,
            Err(error) => {
                tracing::warn!(
                    kind = ?error.kind(),
                    reason = "host_order_holds_read_failed",
                    "the host-order legal holds did not read; answered not proven"
                );
                return Ok(not_proven(HostOrderHoldsNotProven::ReadFailed));
            }
        };
        let Ok(family) = serde_json::to_vec(&family) else {
            tracing::warn!(
                reason = "host_order_holds_serialization_failed",
                "the host-order legal holds did not serialize; answered not proven"
            );
            return Ok(not_proven(HostOrderHoldsNotProven::SerializationFailed));
        };
        // Again after the read: a freeze lifted or a writer let in meanwhile
        // makes the family not proven, never a page.
        let in_flight = self.http_mutating_in_flight.load(Ordering::SeqCst);
        if !self.quiescent(in_flight, drained) {
            return Ok(not_proven(HostOrderHoldsNotProven::NotQuiescent));
        }
        HostOrderHoldsExport::page(identity, source, &family, cursor).map_err(|error| {
            ManagedError::CtlRequestRefused {
                reason: error.to_string(),
            }
        })
    }
}
