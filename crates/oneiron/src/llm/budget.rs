use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, MutexGuard};

use serde::{Deserialize, Serialize};

use super::{BudgetDenied, BudgetLease, LlmRequest, LlmUsage, ModelLocality};

pub const DEFAULT_BUDGET_RESERVE_UNITS: u64 = 8_000;

pub const BUDGET_PLAN_PROMPT_TEMPLATE_ID: &str = "budget.plan.80";
pub const BUDGET_LAND_PROMPT_TEMPLATE_ID: &str = "budget.land.95";
pub const BUDGET_OWNER_DIGEST_PROMPT_TEMPLATE_ID: &str = "budget.owner_digest";
pub const BUDGET_RESUME_PREAMBLE_PROMPT_TEMPLATE_ID: &str = "budget.resume_preamble";

pub const BUDGET_PLAN_PROMPT_TEMPLATE: &str = "\
Budget is at or above 80%. Re-rank the remaining work by value, keep quality \
honest, and make a compact PLAN for what still deserves compute.";
pub const BUDGET_LAND_PROMPT_TEMPLATE: &str = "\
Budget is at or above 95%. Enter LAND: start no new work, write durable \
checkpoints, and list unfinished work as cold-resumable TODOs. An \
incomplete-but-honest checkpoint is a successful landing.";
pub const BUDGET_OWNER_DIGEST_PROMPT_TEMPLATE: &str = "\
Explain the budget stop clearly, summarize what landed, name unfinished work, \
and offer explicit choices: suspend, continue locally, or approve overdraft \
where policy allows.";
pub const BUDGET_RESUME_PREAMBLE_PROMPT_TEMPLATE: &str = "\
Resume from the last budget landing checkpoint. Treat already-completed steps \
as done, preserve the user's quality bar, and spend only against a fresh lease.";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub struct BudgetPromptTemplate {
    pub id: &'static str,
    pub text: &'static str,
}

pub const BUDGET_PROMPT_TEMPLATES: &[BudgetPromptTemplate] = &[
    BudgetPromptTemplate {
        id: BUDGET_PLAN_PROMPT_TEMPLATE_ID,
        text: BUDGET_PLAN_PROMPT_TEMPLATE,
    },
    BudgetPromptTemplate {
        id: BUDGET_LAND_PROMPT_TEMPLATE_ID,
        text: BUDGET_LAND_PROMPT_TEMPLATE,
    },
    BudgetPromptTemplate {
        id: BUDGET_OWNER_DIGEST_PROMPT_TEMPLATE_ID,
        text: BUDGET_OWNER_DIGEST_PROMPT_TEMPLATE,
    },
    BudgetPromptTemplate {
        id: BUDGET_RESUME_PREAMBLE_PROMPT_TEMPLATE_ID,
        text: BUDGET_RESUME_PREAMBLE_PROMPT_TEMPLATE,
    },
];

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BudgetExhaustionPolicy {
    #[default]
    Suspend,
    ContinueOnLocal,
    Overdraft {
        cap: u64,
    },
}

impl BudgetExhaustionPolicy {
    #[must_use]
    pub fn admission_cap(self, limit_units: u64) -> u64 {
        match self {
            Self::Suspend | Self::ContinueOnLocal => limit_units,
            Self::Overdraft { cap } => limit_units.saturating_add(cap),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetThreshold {
    Silent50,
    Plan80,
    Land95,
}

impl BudgetThreshold {
    #[must_use]
    pub fn percent(self) -> u64 {
        match self {
            Self::Silent50 => 50,
            Self::Plan80 => 80,
            Self::Land95 => 95,
        }
    }

    #[must_use]
    pub fn template_id(self) -> Option<&'static str> {
        match self {
            Self::Silent50 => None,
            Self::Plan80 => Some(BUDGET_PLAN_PROMPT_TEMPLATE_ID),
            Self::Land95 => Some(BUDGET_LAND_PROMPT_TEMPLATE_ID),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetSignalDeliveryChannel {
    SteeringQueueNextTurn,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetSteeringSignal {
    pub threshold: BudgetThreshold,
    pub channel: BudgetSignalDeliveryChannel,
    pub template_id: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetLadderEvent {
    pub threshold: BudgetThreshold,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub steering: Option<BudgetSteeringSignal>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetRead {
    pub job_id: String,
    pub limit_units: u64,
    pub cap_units: u64,
    pub used_units: u64,
    pub reserved_units: u64,
    pub remaining_units: u64,
    pub on_budget_exhausted: BudgetExhaustionPolicy,
    pub fired_thresholds: Vec<BudgetThreshold>,
}

impl BudgetRead {
    #[must_use]
    pub fn depleted_percent(&self) -> u64 {
        percent_used(
            self.used_units.saturating_add(self.reserved_units),
            self.limit_units,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetAdmission {
    pub lease: BudgetLease,
    pub read: BudgetRead,
    pub ladder_events: Vec<BudgetLadderEvent>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetSettlement {
    pub read: BudgetRead,
    pub ladder_events: Vec<BudgetLadderEvent>,
}

#[derive(Debug, Clone)]
pub struct BudgetGuard {
    state: Arc<Mutex<BudgetState>>,
}

impl BudgetGuard {
    #[must_use]
    pub fn new(
        job_id: impl Into<String>,
        limit_units: u64,
        on_budget_exhausted: BudgetExhaustionPolicy,
    ) -> Self {
        Self::with_reserve_units(
            job_id,
            limit_units,
            DEFAULT_BUDGET_RESERVE_UNITS,
            on_budget_exhausted,
        )
    }

    #[must_use]
    pub fn with_reserve_units(
        job_id: impl Into<String>,
        limit_units: u64,
        reserve_units: u64,
        on_budget_exhausted: BudgetExhaustionPolicy,
    ) -> Self {
        Self {
            state: Arc::new(Mutex::new(BudgetState {
                job_id: job_id.into(),
                limit_units,
                reserve_units,
                on_budget_exhausted,
                used_units: 0,
                reserved_units: 0,
                next_lease_seq: 0,
                fired_thresholds: BTreeSet::new(),
                leases: BTreeMap::new(),
            })),
        }
    }

    pub fn admit(&self) -> Result<BudgetAdmission, BudgetDenied> {
        let reserve_units = self.lock_state().reserve_units;
        self.admit_reserve(reserve_units)
    }

    pub fn admit_for_request(&self, request: &LlmRequest) -> Result<BudgetAdmission, BudgetDenied> {
        let continue_local = {
            let state = self.lock_state();
            matches!(request.envelope.locality, ModelLocality::OnDevice)
                && matches!(
                    state.on_budget_exhausted,
                    BudgetExhaustionPolicy::ContinueOnLocal
                )
                && state.is_exhausted()
        };
        if continue_local {
            return self.admit_local();
        }
        self.admit()
    }

    pub fn admit_local(&self) -> Result<BudgetAdmission, BudgetDenied> {
        let mut state = self.lock_state();
        if !matches!(
            state.on_budget_exhausted,
            BudgetExhaustionPolicy::ContinueOnLocal
        ) || !state.is_exhausted()
        {
            return Err(BudgetDenied::AdmissionDenied);
        }

        let lease = state.issue_lease(0, false, "local");
        let read = state.read();
        Ok(BudgetAdmission {
            lease,
            read,
            ladder_events: Vec::new(),
        })
    }

    pub fn admit_reserve(&self, reserve_units: u64) -> Result<BudgetAdmission, BudgetDenied> {
        if reserve_units == 0 {
            return Err(BudgetDenied::AdmissionDenied);
        }

        let mut state = self.lock_state();
        let cap_units = state.cap_units();
        let projected = state
            .used_units
            .saturating_add(state.reserved_units)
            .saturating_add(reserve_units);
        if projected > cap_units {
            return Err(BudgetDenied::Exhausted);
        }

        let lease = state.issue_lease(reserve_units, true, "metered");
        state.reserved_units = state.reserved_units.saturating_add(reserve_units);
        let ladder_events = state.fire_ladder_events();
        let read = state.read();
        Ok(BudgetAdmission {
            lease,
            read,
            ladder_events,
        })
    }

    pub fn settle_terminal(
        &self,
        lease: &BudgetLease,
        usage: &LlmUsage,
    ) -> Result<BudgetSettlement, BudgetDenied> {
        self.settle_absolute(lease, llm_usage_units(usage))
    }

    pub fn settle_absolute(
        &self,
        lease: &BudgetLease,
        absolute_used_units: u64,
    ) -> Result<BudgetSettlement, BudgetDenied> {
        let mut state = self.lock_state();
        let mut released_reserve = None;
        let mut metered_settlement = false;
        {
            let Some(record) = state.leases.get_mut(lease.id()) else {
                return Err(BudgetDenied::LeaseInvalid);
            };
            match record.state {
                LeaseState::Open => {
                    released_reserve = Some(record.reserve_units);
                    if record.metered {
                        metered_settlement = true;
                    }
                    record.state = LeaseState::Settled {
                        absolute_used_units,
                    };
                }
                LeaseState::Settled { .. } => {}
                LeaseState::Aborted => return Err(BudgetDenied::LeaseInvalid),
            }
        }
        if let Some(reserve_units) = released_reserve {
            state.reserved_units = state.reserved_units.saturating_sub(reserve_units);
            if metered_settlement {
                state.used_units = state.used_units.max(absolute_used_units);
            }
        }
        let ladder_events = state.fire_ladder_events();
        let read = state.read();
        Ok(BudgetSettlement {
            read,
            ladder_events,
        })
    }

    pub fn abort(&self, lease: &BudgetLease) -> Result<BudgetSettlement, BudgetDenied> {
        let mut state = self.lock_state();
        let mut released_reserve = None;
        {
            let Some(record) = state.leases.get_mut(lease.id()) else {
                return Err(BudgetDenied::LeaseInvalid);
            };
            match record.state {
                LeaseState::Open => {
                    released_reserve = Some(record.reserve_units);
                    record.state = LeaseState::Aborted;
                }
                LeaseState::Aborted => {}
                LeaseState::Settled { .. } => return Err(BudgetDenied::LeaseInvalid),
            }
        }
        if let Some(reserve_units) = released_reserve {
            state.reserved_units = state.reserved_units.saturating_sub(reserve_units);
        }
        let ladder_events = state.fire_ladder_events();
        let read = state.read();
        Ok(BudgetSettlement {
            read,
            ladder_events,
        })
    }

    #[must_use]
    pub fn read(&self) -> BudgetRead {
        self.lock_state().read()
    }

    #[must_use]
    pub fn self_budget(&self) -> BudgetRead {
        self.read()
    }

    fn lock_state(&self) -> MutexGuard<'_, BudgetState> {
        self.state.lock().expect("budget guard mutex poisoned")
    }
}

#[derive(Debug)]
struct BudgetState {
    job_id: String,
    limit_units: u64,
    reserve_units: u64,
    on_budget_exhausted: BudgetExhaustionPolicy,
    used_units: u64,
    reserved_units: u64,
    next_lease_seq: u64,
    fired_thresholds: BTreeSet<BudgetThreshold>,
    leases: BTreeMap<String, LeaseRecord>,
}

impl BudgetState {
    fn cap_units(&self) -> u64 {
        self.on_budget_exhausted.admission_cap(self.limit_units)
    }

    fn is_exhausted(&self) -> bool {
        self.used_units.saturating_add(self.reserved_units) >= self.cap_units()
    }

    fn issue_lease(&mut self, reserve_units: u64, metered: bool, kind: &str) -> BudgetLease {
        self.next_lease_seq = self.next_lease_seq.saturating_add(1);
        let lease_id = format!("{}:{kind}:{}", self.job_id, self.next_lease_seq);
        let lease = BudgetLease::issued(lease_id.clone());
        self.leases.insert(
            lease_id,
            LeaseRecord {
                reserve_units,
                metered,
                state: LeaseState::Open,
            },
        );
        lease
    }

    fn read(&self) -> BudgetRead {
        let cap_units = self.cap_units();
        let committed = self.used_units.saturating_add(self.reserved_units);
        BudgetRead {
            job_id: self.job_id.clone(),
            limit_units: self.limit_units,
            cap_units,
            used_units: self.used_units,
            reserved_units: self.reserved_units,
            remaining_units: cap_units.saturating_sub(committed),
            on_budget_exhausted: self.on_budget_exhausted,
            fired_thresholds: self.fired_thresholds.iter().copied().collect(),
        }
    }

    fn fire_ladder_events(&mut self) -> Vec<BudgetLadderEvent> {
        let metered_units = self.used_units.saturating_add(self.reserved_units);
        [
            BudgetThreshold::Silent50,
            BudgetThreshold::Plan80,
            BudgetThreshold::Land95,
        ]
        .into_iter()
        .filter_map(|threshold| {
            if percent_used(metered_units, self.limit_units) < threshold.percent() {
                return None;
            }
            if !self.fired_thresholds.insert(threshold) {
                return None;
            }
            Some(BudgetLadderEvent {
                threshold,
                steering: steering_signal(threshold),
            })
        })
        .collect()
    }
}

#[derive(Debug)]
struct LeaseRecord {
    reserve_units: u64,
    metered: bool,
    state: LeaseState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LeaseState {
    Open,
    Settled { absolute_used_units: u64 },
    Aborted,
}

fn steering_signal(threshold: BudgetThreshold) -> Option<BudgetSteeringSignal> {
    let template_id = threshold.template_id()?;
    let message = match threshold {
        BudgetThreshold::Silent50 => return None,
        BudgetThreshold::Plan80 => BUDGET_PLAN_PROMPT_TEMPLATE,
        BudgetThreshold::Land95 => BUDGET_LAND_PROMPT_TEMPLATE,
    };
    Some(BudgetSteeringSignal {
        threshold,
        channel: BudgetSignalDeliveryChannel::SteeringQueueNextTurn,
        template_id: template_id.to_owned(),
        message: message.to_owned(),
    })
}

fn llm_usage_units(usage: &LlmUsage) -> u64 {
    usage.input.total.saturating_add(usage.output.total)
}

fn percent_used(used_units: u64, limit_units: u64) -> u64 {
    if limit_units == 0 {
        return 100;
    }
    let numerator = u128::from(used_units).saturating_mul(100);
    (numerator / u128::from(limit_units)).min(100) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::llm::{LlmInputUsage, LlmOutputUsage};
    use serde_json::Value as JsonValue;

    #[test]
    fn admission_reserves_lease_and_exhaustion_denies_new_leases() {
        let guard = BudgetGuard::with_reserve_units("job", 10, 4, BudgetExhaustionPolicy::Suspend);

        let first = guard.admit().expect("first lease");
        assert_eq!(first.lease.id(), "job:metered:1");
        assert_eq!(first.read.reserved_units, 4);
        assert_eq!(first.read.remaining_units, 6);

        let second = guard.admit().expect("second lease");
        assert_eq!(second.lease.id(), "job:metered:2");
        assert_eq!(second.read.reserved_units, 8);
        assert_eq!(second.read.remaining_units, 2);

        assert!(matches!(guard.admit(), Err(BudgetDenied::Exhausted)));
    }

    #[test]
    fn terminal_settlement_uses_absolute_counters_without_double_counting_retry() {
        let guard =
            BudgetGuard::with_reserve_units("job", 100, 20, BudgetExhaustionPolicy::Suspend);
        let first = guard.admit().expect("lease");

        let settlement = guard
            .settle_absolute(&first.lease, 30)
            .expect("terminal settlement");
        assert_eq!(settlement.read.used_units, 30);
        assert_eq!(settlement.read.reserved_units, 0);
        assert_eq!(settlement.read.remaining_units, 70);

        let duplicate = guard
            .settle_absolute(&first.lease, 60)
            .expect("duplicate terminal settlement is idempotent");
        assert_eq!(duplicate.read.used_units, 30);

        let retry = guard.admit().expect("retry lease");
        let retried = guard
            .settle_absolute(&retry.lease, 30)
            .expect("retry reports same absolute total");
        assert_eq!(retried.read.used_units, 30);
    }

    #[test]
    fn admitted_call_is_not_killed_when_terminal_usage_overshoots() {
        let guard = BudgetGuard::with_reserve_units("job", 10, 8, BudgetExhaustionPolicy::Suspend);
        let admission = guard.admit().expect("lease before cap");

        let settlement = guard
            .settle_absolute(&admission.lease, 14)
            .expect("admitted call settles even after cap");
        assert_eq!(settlement.read.used_units, 14);
        assert_eq!(settlement.read.remaining_units, 0);
        assert!(matches!(guard.admit(), Err(BudgetDenied::Exhausted)));
    }

    #[test]
    fn abort_refunds_reserved_units_without_spend() {
        let guard = BudgetGuard::with_reserve_units("job", 10, 8, BudgetExhaustionPolicy::Suspend);
        let admission = guard.admit().expect("lease");

        let aborted = guard.abort(&admission.lease).expect("abort");
        assert_eq!(aborted.read.used_units, 0);
        assert_eq!(aborted.read.reserved_units, 0);
        assert_eq!(aborted.read.remaining_units, 10);
        assert!(matches!(
            guard.settle_absolute(&admission.lease, 8),
            Err(BudgetDenied::LeaseInvalid)
        ));
    }

    #[test]
    fn ladder_events_fire_once_and_use_only_steering_queue_delivery() {
        let guard =
            BudgetGuard::with_reserve_units("job", 100, 50, BudgetExhaustionPolicy::Suspend);

        let fifty = guard.admit().expect("50 percent");
        assert_eq!(fifty.ladder_events.len(), 1);
        assert_eq!(fifty.ladder_events[0].threshold, BudgetThreshold::Silent50);
        assert!(fifty.ladder_events[0].steering.is_none());

        let lease = guard.admit().expect("100 percent projected");
        let thresholds: Vec<_> = lease
            .ladder_events
            .iter()
            .map(|event| event.threshold)
            .collect();
        assert_eq!(
            thresholds,
            vec![BudgetThreshold::Plan80, BudgetThreshold::Land95]
        );
        for event in &lease.ladder_events {
            let steering = event.steering.as_ref().expect("80/95 steering signal");
            assert_eq!(
                steering.channel,
                BudgetSignalDeliveryChannel::SteeringQueueNextTurn
            );
        }

        let duplicate = guard
            .settle_absolute(&lease.lease, 100)
            .expect("settlement after thresholds");
        assert!(duplicate.ladder_events.is_empty());
    }

    #[test]
    fn overdraft_policy_extends_admission_cap() {
        let suspend =
            BudgetGuard::with_reserve_units("suspend", 10, 11, BudgetExhaustionPolicy::Suspend);
        assert!(matches!(suspend.admit(), Err(BudgetDenied::Exhausted)));

        let overdraft = BudgetGuard::with_reserve_units(
            "overdraft",
            10,
            11,
            BudgetExhaustionPolicy::Overdraft { cap: 2 },
        );
        let admission = overdraft.admit().expect("overdraft cap admits");
        assert_eq!(admission.read.cap_units, 12);
        assert_eq!(admission.read.remaining_units, 1);
    }

    #[test]
    fn continue_on_local_requires_explicit_unmetered_lease_after_exhaustion() {
        let guard =
            BudgetGuard::with_reserve_units("job", 10, 10, BudgetExhaustionPolicy::ContinueOnLocal);
        assert!(matches!(
            guard.admit_local(),
            Err(BudgetDenied::AdmissionDenied)
        ));

        let metered = guard.admit().expect("metered lease reaches cap");
        assert!(matches!(guard.admit(), Err(BudgetDenied::Exhausted)));

        let local = guard.admit_local().expect("explicit local continuation");
        assert_eq!(local.lease.id(), "job:local:2");
        let settled = guard
            .settle_absolute(&local.lease, 99)
            .expect("local lease settles without paid spend");
        assert_eq!(settled.read.used_units, 0);
        assert_eq!(settled.read.reserved_units, 10);

        guard
            .settle_absolute(&metered.lease, 10)
            .expect("metered settlement");
        let after_metered = guard.read();
        assert_eq!(after_metered.used_units, 10);
        assert_eq!(after_metered.reserved_units, 0);
        assert!(matches!(guard.admit(), Err(BudgetDenied::Exhausted)));
    }

    #[test]
    fn self_budget_read_reports_current_meter() {
        let guard = BudgetGuard::with_reserve_units(
            "job",
            100,
            20,
            BudgetExhaustionPolicy::ContinueOnLocal,
        );
        let admission = guard.admit().expect("lease");
        let usage = LlmUsage {
            input: LlmInputUsage {
                total: 12,
                cache_read: 2,
                cache_write: 1,
            },
            output: LlmOutputUsage {
                total: 8,
                text: 5,
                reasoning: 3,
            },
            raw_provider: JsonValue::Null,
        };
        guard
            .settle_terminal(&admission.lease, &usage)
            .expect("terminal settlement");

        let read = guard.self_budget();
        assert_eq!(read.job_id, "job");
        assert_eq!(read.used_units, 20);
        assert_eq!(read.reserved_units, 0);
        assert_eq!(read.remaining_units, 80);
        assert_eq!(
            read.on_budget_exhausted,
            BudgetExhaustionPolicy::ContinueOnLocal
        );
    }

    #[test]
    fn prompt_templates_ship_as_data() {
        let ids: Vec<_> = BUDGET_PROMPT_TEMPLATES
            .iter()
            .map(|template| template.id)
            .collect();
        assert_eq!(
            ids,
            vec![
                BUDGET_PLAN_PROMPT_TEMPLATE_ID,
                BUDGET_LAND_PROMPT_TEMPLATE_ID,
                BUDGET_OWNER_DIGEST_PROMPT_TEMPLATE_ID,
                BUDGET_RESUME_PREAMBLE_PROMPT_TEMPLATE_ID,
            ]
        );
        assert!(BUDGET_LAND_PROMPT_TEMPLATE.contains("incomplete-but-honest"));
    }
}
