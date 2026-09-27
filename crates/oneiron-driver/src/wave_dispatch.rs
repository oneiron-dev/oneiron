//! Bounded, per-item delivery of durable wave TASKs to a host dispatcher.
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use oneiron::attempt_queue::{AttemptId, AttemptQueue, AttemptState};
use oneiron::task_verb::WaveDispatchGeneration;
use oneiron::{EntityId, Result, Vault, WavePlanner, WriteActor};
use tokio::time::Instant;

use crate::WaveHost;
use crate::supervisor::PassExecutorFactory;

/// Exact TASK handoff identity. Retry replaces the attempt id; lease reclaim
/// retains that id and raises its generation. External work has no queue row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WaveDispatchCandidate {
    pub task: EntityId,
    pub route: WaveDispatchRoute,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WaveDispatchRoute {
    External,
    Attempt { id: AttemptId, generation: u32 },
}

/// The callback's claimed lease is a receipt to VERIFY, not an assertion the
/// driver trusts. External effects have no queue lease to verify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WaveHandoffReceipt {
    External,
    Local { lease_owner: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WaveHandoffOutcome {
    Accepted(WaveHandoffReceipt),
    Deferred,
    NoLongerCurrent,
}

/// Holder narrowing of manifest-resolved work bounds for one supervisor turn.
/// Runtime defaults are read from the vault's operational policy manifest.
#[derive(Debug, Clone, Copy)]
pub struct WaveDispatchLimits {
    pub page_size: usize,
    pub retry_quantum: usize,
    pub retry_initial: Duration,
    pub retry_max: Duration,
}

impl WaveDispatchLimits {
    pub fn validate(self) -> Result<()> {
        if !(1..=256).contains(&self.page_size)
            || !(1..=self.page_size).contains(&self.retry_quantum)
            || self.retry_initial.is_zero()
            || self.retry_max < self.retry_initial
        {
            return Err(oneiron::Error::InvalidConfig(
                "invalid wave dispatch limits".into(),
            ));
        }
        Ok(())
    }
}

/// One bounded pump quantum. Failures are per candidate; an outer `Err`
/// means the page itself could not be read or evaluated.
#[derive(Debug, Default)]
pub(crate) struct WaveDispatchPass {
    pub(crate) progressed: bool,
    pub(crate) next_cursor: Option<EntityId>,
    pub(crate) earliest_retry: Option<Duration>,
    pub(crate) item_failures: Vec<WaveHandoffFailure>,
}

#[derive(Debug)]
pub(crate) struct WaveHandoffFailure {
    pub(crate) candidate: WaveDispatchCandidate,
    pub(crate) reason: String,
}

#[derive(Debug, Clone, Copy)]
struct Retry {
    due: Instant,
    next_delay: Duration,
}

/// Process-local delivery state. On restart, the durable TASK scan and queue
/// generations rebuild it; failed callbacks do not pin the raw page cursor.
pub(crate) struct WaveDispatchPump {
    limits: WaveDispatchLimits,
    cursor: Option<EntityId>,
    scanning: bool,
    dirty: bool,
    plan_pending: bool,
    scan_retry: Option<Instant>,
    due_task: Option<u64>,
    failed: HashMap<WaveDispatchCandidate, Retry>,
    delivered: HashMap<EntityId, WaveDispatchRoute>,
}

impl WaveDispatchPump {
    pub(crate) fn new(limits: WaveDispatchLimits) -> Self {
        Self {
            limits,
            cursor: None,
            scanning: true, // subscribe before this startup scan
            dirty: false,
            plan_pending: true,
            scan_retry: None,
            due_task: None,
            failed: HashMap::new(),
            delivered: HashMap::new(),
        }
    }

    pub(crate) fn set_limits(&mut self, limits: WaveDispatchLimits) -> Result<()> {
        limits.validate()?;
        self.limits = limits;
        Ok(())
    }

    pub(crate) fn notify(&mut self) {
        self.plan_pending = true;
        if self.scanning {
            self.dirty = true;
        } else {
            self.cursor = None;
            self.scanning = true;
        }
    }

    pub(crate) fn on_timer(&mut self, now: u64) {
        if self.due_task.is_none_or(|due| due > now) {
            return;
        }
        self.due_task = None;
        if self.scanning {
            self.dirty = true;
        } else {
            self.cursor = None;
            self.scanning = true;
        }
    }

    pub(crate) fn ready(&self) -> bool {
        let now = Instant::now();
        self.plan_pending
            || (self.scanning && self.scan_retry.is_none_or(|due| due <= now))
            || self.failed.values().any(|retry| retry.due <= now)
    }

    pub(crate) fn next_delay(&self, wall_now: u64) -> Option<Duration> {
        let now = Instant::now();
        let mut delay = self
            .failed
            .values()
            .map(|retry| retry.due.saturating_duration_since(now))
            .min();
        if let Some(retry) = self.scan_retry {
            delay = Some(delay.map_or(retry.saturating_duration_since(now), |old| {
                old.min(retry.saturating_duration_since(now))
            }));
        }
        if let Some(due) = self.due_task {
            // A frozen test wall clock must not make a due wake a hot loop.
            let seconds = due.saturating_sub(wall_now).max(1);
            let wall = Duration::from_secs(seconds);
            delay = Some(delay.map_or(wall, |old| old.min(wall)));
        }
        delay
    }

    pub(crate) fn work_one<F: PassExecutorFactory>(
        &mut self,
        vault: &Vault,
        factory: &mut F,
        planner: &Arc<dyn WavePlanner + Send + Sync>,
        actor: WriteActor,
        lease_owner: &str,
        now: u64,
    ) -> Result<WaveDispatchPass> {
        let host = WaveHost::new(
            vault,
            Arc::clone(planner),
            actor.entity_ref(),
            actor.actor_class(),
        );
        let mut pass = WaveDispatchPass::default();
        if self.plan_pending {
            self.plan_pending = false;
            match host.run_plan_once(lease_owner, now) {
                Ok(Some(_)) => {
                    self.notify();
                    pass.progressed = true;
                }
                Ok(None) => {}
                // The planning attempt stays queued; its lease expiry retries it.
                Err(error) => tracing::error!(%error, "wave plan attempt failed"),
            }
            pass.next_cursor = self.cursor;
            pass.earliest_retry = self.next_delay(now);
            return Ok(pass);
        }
        let due: Vec<_> = self
            .failed
            .iter()
            .filter(|(_, retry)| retry.due <= Instant::now())
            .take(self.limits.retry_quantum)
            .map(|(&candidate, _)| candidate)
            .collect();
        for candidate in due {
            match self.handoff(vault, factory, &host, candidate, now) {
                Ok(accepted) => pass.progressed |= accepted,
                Err(failure) => pass.item_failures.push(failure),
            }
        }
        // A retry quantum and one raw page are the maximum synchronous work.
        if self.scanning && self.scan_retry.is_none_or(|due| due <= Instant::now()) {
            self.scan_retry = None;
            if let Err(error) = self.scan_page(vault, factory, &host, now, &mut pass) {
                self.scan_retry = Some(Instant::now() + self.limits.retry_initial);
                return Err(error);
            }
            pass.progressed = true; // raw cursor advanced, even if no candidates matched
        }
        pass.next_cursor = self.cursor;
        pass.earliest_retry = self.next_delay(now);
        Ok(pass)
    }

    fn scan_page<F: PassExecutorFactory>(
        &mut self,
        vault: &Vault,
        factory: &mut F,
        host: &WaveHost<'_, Arc<dyn WavePlanner + Send + Sync>>,
        now: u64,
        pass: &mut WaveDispatchPass,
    ) -> Result<()> {
        let page = vault.wave_dispatch_page(self.cursor, self.limits.page_size)?;
        let ready = host
            .ready_to_dispatch(&page.task_refs)
            .map_err(|error| oneiron::Error::InvalidConfig(error.to_string()))?;
        for task in ready {
            match vault.wave_dispatch_generation(task, now) {
                Ok(Some(WaveDispatchGeneration::DueAt(due))) => {
                    self.due_task = Some(self.due_task.map_or(due, |old| old.min(due)));
                }
                Ok(Some(generation)) => {
                    let route = match generation {
                        WaveDispatchGeneration::External => WaveDispatchRoute::External,
                        WaveDispatchGeneration::Attempt { id, generation } => {
                            WaveDispatchRoute::Attempt { id, generation }
                        }
                        WaveDispatchGeneration::DueAt(_) => unreachable!(),
                    };
                    self.failed
                        .retain(|key, _| key.task != task || key.route == route);
                    match self.handoff(
                        vault,
                        factory,
                        host,
                        WaveDispatchCandidate { task, route },
                        now,
                    ) {
                        Ok(accepted) => pass.progressed |= accepted,
                        Err(failure) => pass.item_failures.push(failure),
                    }
                }
                Ok(None) => {
                    self.failed.retain(|key, _| key.task != task);
                }
                Err(error) => {
                    // Keep scanning this page and later pages, but revisit a
                    // transiently unreadable TASK after a bounded delay.
                    self.dirty = true;
                    self.scan_retry = Some(Instant::now() + self.limits.retry_initial);
                    pass.item_failures.push(WaveHandoffFailure {
                        candidate: WaveDispatchCandidate {
                            task,
                            route: WaveDispatchRoute::External,
                        },
                        reason: error.to_string(),
                    });
                }
            }
        }
        self.cursor = page.next_after;
        if page.exhausted {
            self.scanning = self.dirty;
            self.dirty = false;
            self.cursor = None;
        }
        Ok(())
    }

    fn handoff<F: PassExecutorFactory>(
        &mut self,
        vault: &Vault,
        factory: &mut F,
        host: &WaveHost<'_, Arc<dyn WavePlanner + Send + Sync>>,
        candidate: WaveDispatchCandidate,
        now: u64,
    ) -> std::result::Result<bool, WaveHandoffFailure> {
        if self.delivered.get(&candidate.task) == Some(&candidate.route) {
            self.failed.remove(&candidate);
            return Ok(false);
        }
        if self
            .failed
            .get(&candidate)
            .is_some_and(|retry| retry.due > Instant::now())
        {
            return Ok(false);
        }
        // Re-evaluate blockers and generation before each retry. A claim or
        // terminal transition since the scan makes the old receipt stale.
        let current = host
            .ready_to_dispatch(&[candidate.task])
            .map_err(|error| oneiron::Error::InvalidConfig(error.to_string()))
            .and_then(|ready| {
                if !ready.contains(&candidate.task) {
                    return Ok(false);
                }
                let generation = vault.wave_dispatch_generation(candidate.task, now)?;
                Ok(match (candidate.route, generation) {
                    (WaveDispatchRoute::External, Some(WaveDispatchGeneration::External)) => true,
                    (
                        WaveDispatchRoute::Attempt { id, generation },
                        Some(WaveDispatchGeneration::Attempt {
                            id: actual,
                            generation: current,
                        }),
                    ) => id == actual && generation == current,
                    _ => false,
                })
            });
        match current {
            Ok(false) => {
                self.failed.remove(&candidate);
                return Ok(false);
            }
            Err(error) => {
                self.defer(candidate);
                return Err(WaveHandoffFailure {
                    candidate,
                    reason: error.to_string(),
                });
            }
            Ok(true) => {}
        }
        match factory.dispatch_wave_candidate(vault, candidate) {
            Ok(WaveHandoffOutcome::Accepted(receipt)) => {
                match verify_receipt(vault, candidate, &receipt) {
                    Ok(true) => {
                        self.failed.remove(&candidate);
                        self.delivered.insert(candidate.task, candidate.route);
                        Ok(true)
                    }
                    Ok(false) => {
                        self.defer(candidate);
                        Err(WaveHandoffFailure {
                            candidate,
                            reason: "handoff receipt is stale".into(),
                        })
                    }
                    Err(error) => {
                        self.defer(candidate);
                        Err(WaveHandoffFailure {
                            candidate,
                            reason: error.to_string(),
                        })
                    }
                }
            }
            Ok(WaveHandoffOutcome::NoLongerCurrent) => {
                self.failed.remove(&candidate);
                Ok(false)
            }
            Ok(WaveHandoffOutcome::Deferred) => {
                self.defer(candidate);
                Err(WaveHandoffFailure {
                    candidate,
                    reason: "deferred".into(),
                })
            }
            Err(error) => {
                self.defer(candidate);
                Err(WaveHandoffFailure {
                    candidate,
                    reason: error.to_string(),
                })
            }
        }
    }

    fn defer(&mut self, candidate: WaveDispatchCandidate) {
        let next = self
            .failed
            .get(&candidate)
            .map_or(self.limits.retry_initial, |retry| retry.next_delay)
            .min(self.limits.retry_max);
        self.failed.insert(
            candidate,
            Retry {
                due: Instant::now() + next,
                next_delay: next.saturating_mul(2).min(self.limits.retry_max),
            },
        );
    }
}

fn verify_receipt(
    vault: &Vault,
    candidate: WaveDispatchCandidate,
    receipt: &WaveHandoffReceipt,
) -> Result<bool> {
    match (candidate.route, receipt) {
        (WaveDispatchRoute::External, WaveHandoffReceipt::External) => Ok(matches!(
            vault.wave_dispatch_generation(candidate.task, 0)?,
            Some(WaveDispatchGeneration::External)
        )),
        (
            WaveDispatchRoute::Attempt { id, generation },
            WaveHandoffReceipt::Local { lease_owner },
        ) if !lease_owner.is_empty() => {
            let row = AttemptQueue::new(vault).get(id)?;
            Ok(row.is_some_and(|row| {
                row.id == id
                    && row.attempt_count == generation.saturating_add(1)
                    && row.state == AttemptState::Leased
                    && row.lease_owner.as_deref() == Some(lease_owner)
                    && row.task_ref.as_deref() == Some(candidate.task.to_hex().as_str())
            }))
        }
        _ => Ok(false),
    }
}
