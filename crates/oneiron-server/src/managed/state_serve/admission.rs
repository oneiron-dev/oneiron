//! The reap freeze's write admission: what a served write and a background
//! pass take, held until their last write.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use oneiron_vault_contract::REAP_PAUSE_REFUSAL;

use super::{ManagedState, WRITES_FROZEN_TAG};
use crate::managed::ManagedError;

pub(super) struct HttpMutation(Arc<ManagedState>);

impl Drop for HttpMutation {
    fn drop(&mut self) {
        self.0
            .http_mutating_in_flight
            .fetch_sub(1, Ordering::SeqCst);
    }
}

impl ManagedState {
    pub(super) fn admit_http_mutation(self: &Arc<Self>) -> Result<HttpMutation, ManagedError> {
        // Increment BEFORE checking freeze. A concurrent freeze must either see
        // this writer or make this admission fail; check-then-increment races.
        self.http_mutating_in_flight.fetch_add(1, Ordering::SeqCst);
        let admission = HttpMutation(Arc::clone(self));
        self.guard_write()?;
        Ok(admission)
    }

    /// A background pass's admission, taken as a served write's and held on
    /// the pass's own thread until its last write. A refused pass logs the
    /// pause's typed reason, once per freeze, and asks again later.
    pub(super) fn admit_background(self: &Arc<Self>) -> Option<Box<dyn Send>> {
        match self.admit_http_mutation() {
            Ok(admission) => Some(Box::new(admission)),
            Err(_) => {
                if !self.background_waiting.swap(true, Ordering::SeqCst) {
                    tracing::info!(
                        reason = WRITES_FROZEN_TAG,
                        bound_kind = REAP_PAUSE_REFUSAL.bound.kind.as_str(),
                        bound_resource = REAP_PAUSE_REFUSAL.bound.resource.as_str(),
                        bound_phase = REAP_PAUSE_REFUSAL.bound.phase.as_str(),
                        "background passes wait: the vault is paused for reap preparation until the reap is aborted or the vault wakes again"
                    );
                }
                None
            }
        }
    }

    /// [`Self::admit_background`] as the admission a background worker takes.
    pub(super) fn background_admission(self: &Arc<Self>) -> crate::server::HousekeepingAdmission {
        let state = Arc::clone(self);
        Arc::new(move || state.admit_background())
    }
}
