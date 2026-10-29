//! In-flight native schedule updates for one device. A registration lives
//! beside its Call; a foreground arrival yields only update-capable
//! background calls and never touches a FIFO worker.
use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock, PoisonError};

use oneiron::llm::{ScheduleAction, ScheduleUpdate, SchedulingCapability, WorkClass};

use super::transport::CallUpdates;

struct Active {
    grant_id: u64,
    class: WorkClass,
    capability: SchedulingCapability,
    updates: CallUpdates,
    revision: u64,
}

static ACTIVE: OnceLock<Mutex<BTreeMap<String, Vec<Active>>>> = OnceLock::new();

fn active() -> &'static Mutex<BTreeMap<String, Vec<Active>>> {
    ACTIVE.get_or_init(|| Mutex::new(BTreeMap::new()))
}

/// Removes one call's update row when its Sent custody ends.
pub(super) struct Registration {
    device: String,
    grant_id: u64,
}

impl Drop for Registration {
    fn drop(&mut self) {
        let mut active = active().lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(calls) = active.get_mut(&self.device) {
            calls.retain(|call| call.grant_id != self.grant_id);
            if calls.is_empty() {
                active.remove(&self.device);
            }
        }
    }
}

/// Registers one accepted call when its worker actually takes updates.
pub(super) fn register(
    device: String,
    grant_id: u64,
    revision: u64,
    class: WorkClass,
    capability: Option<SchedulingCapability>,
    updates: Option<CallUpdates>,
) -> Option<Registration> {
    let capability = capability.filter(SchedulingCapability::takes_updates)?;
    let updates = updates?;
    active()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .entry(device.clone())
        .or_default()
        .push(Active {
            grant_id,
            class,
            capability,
            updates,
            revision,
        });
    Some(Registration { device, grant_id })
}

/// Foreground work on this device makes background work yield at its next
/// engine round. The grant and its bytes stay held; no memory is freed.
pub(super) async fn foreground_arrival(device: &str) {
    let calls: Vec<(u64, CallUpdates)> = {
        let mut active = active().lock().unwrap_or_else(PoisonError::into_inner);
        active
            .get_mut(device)
            .into_iter()
            .flat_map(|calls| calls.iter_mut())
            .filter(|call| call.class == WorkClass::Background && call.capability.takes_updates())
            .map(|call| {
                call.revision = call.revision.saturating_add(1);
                (call.revision, call.updates.clone())
            })
            .collect()
    };
    for (revision, updates) in calls {
        let update = ScheduleUpdate {
            revision,
            action: ScheduleAction::Yield,
            work_class: None,
            priority: None,
            deadline: None,
        };
        if let Err(error) = updates.send(&update).await {
            tracing::warn!(%error, "a native background yield could not be sent");
        }
    }
}
