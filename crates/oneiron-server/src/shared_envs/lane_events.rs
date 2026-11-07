//! One shared env lane's sync events: errors to the log, statuses to debug,
//! and a refused upgrade to the env's leave check (FIX 12442).

use std::sync::{Arc, Weak};

use super::{SharedEnvInner, SharedEnvKey, SharedEnvRegistry};

/// One env's 401 upgrades: how many the lane saw, and how many a clean leave
/// check covers. A clean answer covers only the refusals counted before its
/// round read them, so one that lands while a check is in flight stays owed.
#[derive(Clone, Copy, Default)]
pub(super) struct RefusedUpgrades {
    seen: u64,
    covered: u64,
}

impl RefusedUpgrades {
    /// A refusal no clean check covers yet: the env's check is due.
    pub(super) fn owed(self) -> bool {
        self.seen > self.covered
    }

    pub(super) fn seen(self) -> u64 {
        self.seen
    }

    /// A clean check whose round read `seen` refusals answered.
    pub(super) fn covered(&mut self, seen: u64) {
        self.covered = self.covered.max(seen);
    }

    fn note(&mut self) {
        self.seen = self.seen.saturating_add(1);
    }
}

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

    /// Makes this env's leave check due at the next lifecycle round. The
    /// home refused the lane's credential, and a removed membership is one
    /// cause. Only the signed check decides; the refusal itself is never a
    /// leave. Refusals before that round share its one check, and the check
    /// stays owed until a clean one started after the refusal answers.
    fn owe_leave_check(&self) {
        let Some(inner) = self.registry.upgrade() else {
            return;
        };
        let registry = SharedEnvRegistry { inner };
        if let Some(entry) = registry.lock().get_mut(&self.key) {
            entry.refused.note();
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
