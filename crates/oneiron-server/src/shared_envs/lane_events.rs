//! One shared env lane's sync events: errors to the log, statuses to debug,
//! and a refused upgrade to the env's leave check (FIX 12442).

use std::sync::{Arc, Weak};

use super::{SharedEnvInner, SharedEnvKey, SharedEnvRegistry};

/// The env a lane runs for, with the registry held weakly so a running lane
/// never keeps the registry alive.
#[derive(Clone)]
pub(super) struct LaneMark {
    registry: Weak<SharedEnvInner>,
    key: SharedEnvKey,
}

impl LaneMark {
    pub(super) fn new(registry: &SharedEnvRegistry, key: SharedEnvKey) -> Self {
        Self {
            registry: Arc::downgrade(&registry.inner),
            key,
        }
    }

    pub(super) fn vault_id(&self) -> u64 {
        self.key.0
    }

    /// Makes this env's leave check due at the next lifecycle round, as a
    /// freshly opened env's is. The home refused the lane's credential, and
    /// a removed membership is one cause. Only the signed check decides; the
    /// refusal itself is never a leave. Refusals before that round share its
    /// one check.
    fn owe_leave_check(&self) {
        let Some(inner) = self.registry.upgrade() else {
            return;
        };
        let registry = SharedEnvRegistry { inner };
        if let Some(entry) = registry.lock().get_mut(&self.key) {
            entry.last_leave_check = 0;
        }
    }
}

/// One lane's event observer: errors to the log, statuses to debug, a
/// refused upgrade to the env's leave check, the rest ignored. A sync
/// error here is never a leave.
pub(super) fn lane_observer(mark: LaneMark) -> impl FnMut(oneiron::sync::SyncEvent) + Send {
    let vault_id = mark.vault_id();
    move |event| match event {
        oneiron::sync::SyncEvent::StatusChanged(status) => {
            tracing::debug!(vault_id = vault_id, ?status, "shared env lane");
        }
        oneiron::sync::SyncEvent::UpgradeUnauthorized => {
            tracing::info!(
                vault_id = vault_id,
                "shared env lane's credential refused; its leave check runs next round"
            );
            mark.owe_leave_check();
        }
        oneiron::sync::SyncEvent::Error(error) => {
            tracing::warn!(vault_id = vault_id, %error, "shared env lane");
        }
        _ => {}
    }
}
