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

/// Work bound for each supervisor arbitration turn. A gate-policy resolver
/// can inject its resolved ceilings here; defaults are temporary until wired.
#[derive(Debug, Clone, Copy)]
pub struct WaveDispatchLimits {
    pub page_size: usize,
    pub retry_quantum: usize,
    pub retry_initial: Duration,
    pub retry_max: Duration,
}

impl Default for WaveDispatchLimits {
    fn default() -> Self {
        Self {
            page_size: 256,
            retry_quantum: 8,
            retry_initial: Duration::from_millis(500),
            retry_max: Duration::from_secs(60),
        }
    }
}

impl WaveDispatchLimits {
    pub fn validate(self) -> Result<()> {
        if !(1..=256).contains(&self.page_size)
            || !(1..=256).contains(&self.retry_quantum)
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
    ) {
        let host = WaveHost::new(
            vault,
            Arc::clone(planner),
            actor.entity_ref(),
            actor.actor_class(),
        );
        if self.plan_pending {
            self.plan_pending = false;
            match host.run_plan_once(lease_owner, now) {
                Ok(Some(_)) => self.notify(), // one plan per arbitration turn
                Ok(None) => {}
                Err(error) => tracing::error!(%error, "wave plan attempt failed"),
            }
            return;
        }
        let mut retried = 0;
        let due: Vec<_> = self
            .failed
            .iter()
            .filter(|(_, retry)| retry.due <= Instant::now())
            .take(self.limits.retry_quantum)
            .map(|(&candidate, _)| candidate)
            .collect();
        for candidate in due {
            self.handoff(vault, factory, &host, candidate, now);
            retried += 1;
        }
        // A retry quantum and a raw page are the maximum synchronous work.
        if self.scanning && self.scan_retry.is_none_or(|due| due <= Instant::now()) {
            self.scan_retry = None;
            let result = self.scan_page(vault, factory, &host, now);
            if let Err(error) = result {
                tracing::error!(?error, "wave page scan failed; retrying with delay");
                self.scan_retry = Some(Instant::now() + self.limits.retry_initial);
            }
        } else if retried == 0 {
            // Nothing ready: the supervisor will await an event or due timer.
        }
    }

    fn scan_page<F: PassExecutorFactory>(
        &mut self,
        vault: &Vault,
        factory: &mut F,
        host: &WaveHost<'_, Arc<dyn WavePlanner + Send + Sync>>,
        now: u64,
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
                    self.handoff(
                        vault,
                        factory,
                        host,
                        WaveDispatchCandidate { task, route },
                        now,
                    );
                }
                Ok(None) => {
                    self.failed.retain(|key, _| key.task != task);
                }
                Err(error) => tracing::error!(?error, ?task, "wave TASK generation read failed"),
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
    ) {
        if self.delivered.get(&candidate.task) == Some(&candidate.route) {
            self.failed.remove(&candidate);
            return;
        }
        if self
            .failed
            .get(&candidate)
            .is_some_and(|retry| retry.due > Instant::now())
        {
            return;
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
                return;
            }
            Err(error) => {
                self.defer(candidate);
                tracing::error!(?error, "wave handoff preflight failed");
                return;
            }
            Ok(true) => {}
        }
        let outcome = factory.dispatch_wave_candidate(vault, candidate);
        match outcome {
            Ok(WaveHandoffOutcome::Accepted(receipt)) => {
                match verify_receipt(vault, candidate, &receipt) {
                    Ok(true) => {
                        self.failed.remove(&candidate);
                        self.delivered.insert(candidate.task, candidate.route);
                    }
                    Ok(false) => {
                        self.defer(candidate);
                        tracing::warn!(
                            ?candidate,
                            "wave handoff receipt did not match current lease"
                        );
                    }
                    Err(error) => {
                        self.defer(candidate);
                        tracing::error!(?error, "wave handoff receipt verification failed");
                    }
                }
            }
            Ok(WaveHandoffOutcome::NoLongerCurrent) => {
                self.failed.remove(&candidate);
            }
            Ok(WaveHandoffOutcome::Deferred) => self.defer(candidate),
            Err(error) => {
                self.defer(candidate);
                tracing::error!(?error, "wave TASK handoff failed");
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
        (WaveDispatchRoute::External, WaveHandoffReceipt::External) => Ok(true),
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
