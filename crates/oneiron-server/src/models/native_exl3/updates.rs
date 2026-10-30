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
static ARRIVING: OnceLock<Mutex<BTreeMap<String, u64>>> = OnceLock::new();

fn active() -> &'static Mutex<BTreeMap<String, Vec<Active>>> {
    ACTIVE.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn arriving() -> &'static Mutex<BTreeMap<String, u64>> {
    ARRIVING.get_or_init(|| Mutex::new(BTreeMap::new()))
}

/// Removes one call's update row when its Sent custody ends. The last
/// foreground exit resumes background work; another foreground call still
/// active keeps it yielded.
pub(super) struct Registration {
    device: String,
    grant_id: u64,
}

impl Drop for Registration {
    fn drop(&mut self) {
        {
            let mut active = active().lock().unwrap_or_else(PoisonError::into_inner);
            if let Some(calls) = active.get_mut(&self.device) {
                calls.retain(|call| call.grant_id != self.grant_id);
            }
            if active
                .get(&self.device)
                .is_some_and(|calls| calls.is_empty())
            {
                active.remove(&self.device);
            }
        }
        resume_if_idle(&self.device);
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
/// engine round. The returned guard keeps "arriving" true until the call
/// registers or its begin fails, closing the arrival/registration race.
pub(super) struct Foreground {
    device: String,
}

impl Drop for Foreground {
    fn drop(&mut self) {
        {
            let mut arriving = arriving().lock().unwrap_or_else(PoisonError::into_inner);
            if let Some(count) = arriving.get_mut(&self.device) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    arriving.remove(&self.device);
                }
            }
        }
        resume_if_idle(&self.device);
    }
}

pub(super) async fn foreground_arrival(device: &str) -> Foreground {
    *arriving()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .entry(device.to_owned())
        .or_insert(0) += 1;
    send_action(device, ScheduleAction::Yield).await;
    Foreground {
        device: device.to_owned(),
    }
}

fn resume_if_idle(device: &str) {
    let idle = arriving()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(device)
        .copied()
        .unwrap_or(0)
        == 0
        && active()
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(device)
            .is_none_or(|calls| {
                calls.iter().any(|call| call.class == WorkClass::Background)
                    && !calls.iter().any(|call| call.class == WorkClass::Foreground)
            });
    if idle {
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let device = device.to_owned();
            runtime.spawn(async move { send_action(&device, ScheduleAction::Resume).await });
        }
    }
}

async fn send_action(device: &str, action: ScheduleAction) {
    if matches!(&action, ScheduleAction::Resume) {
        let foreground = arriving()
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(device)
            .copied()
            .unwrap_or(0)
            > 0
            || active()
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .get(device)
                .is_some_and(|calls| calls.iter().any(|call| call.class == WorkClass::Foreground));
        if foreground {
            return;
        }
    }
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
            action: action.clone(),
            work_class: None,
            priority: None,
            deadline: None,
        };
        if let Err(error) = updates.send(&update).await {
            tracing::warn!(%error, action = ?action, "a native schedule update could not be sent");
        }
    }
}
