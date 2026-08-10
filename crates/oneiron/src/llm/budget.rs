use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Mutex, MutexGuard};

use serde::{Deserialize, Serialize};

use super::{BudgetDenied, BudgetLease, CallPurpose, LlmRequest, LlmUsage, ModelLocality};
use crate::entity_id::EntityId;
use crate::write_envelope::WriteActor;

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
    /// Which policy row of the EMITTING meter fired this event. `Some(i)` is
    /// the resolved row index of that meter's own policy table — effector
    /// key/compiled-cap rows (GOV-02) or LLM [`BudgetPolicyTable`] rows; `None`
    /// is a meter's global ladder. A call or dispatch matching several rows can
    /// cross the same threshold on more than one; the row identity keeps those
    /// events distinguishable so a steering consumer can dedupe or present
    /// per-dimension. Indices are only meaningful against the emitting meter's
    /// table: consumers keying off them, including the effector ladder emitters
    /// in `connector_key.rs`, already filter their own meter's events.
    /// Wire-compatible: absent when `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub row_index: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetRead {
    #[serde(rename = "job_id")] // wire key pinned pre-rename (ONE-1714)
    pub attempt_id: String,
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

/// Resolved `budget_policy` manifest table: ordered per-purpose/per-actor
/// floors and caps for ONE budget meter.
///
/// Each row selects exactly one call set — one call purpose or one actor ref —
/// and carries a floor, a cap, or both, in the meter's own units:
///
/// * a floor is a non-borrowable reservation. Matching calls may draw that
///   row's slice; non-matching calls may not, so the slice every call can
///   reach is `total - sum(all floors)`;
/// * a cap is conjunctive admission policy. A call matching several cap rows
///   must fit every one of them, and a cap denial is final.
///
/// Both directions are deliberate policy rather than capacity tuning: floors
/// strand budget on quiet days, and caps refuse matching work while the pool
/// still has room. An empty table is the plain single-pool meter.
///
/// Rows are data the host manifest authors; the engine installs none of its
/// own and gives no purpose an implicit reservation. Two shapes a manifest may
/// author (the numbers are illustrative, never engine defaults):
///
/// ```text
/// # Consolidation is guaranteed a reserved slice.
/// { purpose: "consolidation", floor: 200_000 }
///
/// # One autonomous agent is guaranteed a slice but cannot consume the vault.
/// { actor: "<canonical-actor-ref>", floor: 50_000, cap: 150_000 }
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct BudgetPolicyTable {
    rows: Vec<BudgetPolicyRow>,
}

impl BudgetPolicyTable {
    #[must_use]
    pub(crate) fn from_rows(rows: Vec<BudgetPolicyRow>) -> Self {
        Self { rows }
    }

    #[must_use]
    pub(crate) fn rows(&self) -> &[BudgetPolicyRow] {
        &self.rows
    }

    #[must_use]
    pub(crate) fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Appends one decoded manifest's rows, preserving resolved order: row
    /// indices are manifest-scan order, then row order inside each manifest.
    pub(crate) fn extend_rows(&mut self, other: Self) {
        self.rows.extend(other.rows);
    }
}

/// One `budget_policy` row: a selector plus a floor, a cap, or both.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BudgetPolicyRow {
    selector: BudgetPolicySelector,
    floor_units: Option<u64>,
    cap_units: Option<u64>,
}

impl BudgetPolicyRow {
    #[must_use]
    pub(crate) fn new(
        selector: BudgetPolicySelector,
        floor_units: Option<u64>,
        cap_units: Option<u64>,
    ) -> Self {
        Self {
            selector,
            floor_units,
            cap_units,
        }
    }

    #[must_use]
    pub(crate) fn selector(&self) -> &BudgetPolicySelector {
        &self.selector
    }

    #[must_use]
    pub(crate) fn floor_units(&self) -> Option<u64> {
        self.floor_units
    }

    #[must_use]
    pub(crate) fn cap_units(&self) -> Option<u64> {
        self.cap_units
    }
}

/// The one call set a policy row selects.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum BudgetPolicySelector {
    Purpose(CallPurpose),
    Actor(EntityId),
}

impl BudgetPolicySelector {
    /// Literal, purpose-independent on the actor axis: an actor row binds every
    /// call from the guard's construction-bound actor, including the
    /// purpose-less generic admissions, and a purpose row never matches one.
    fn matches(&self, purpose: Option<&CallPurpose>, actor: Option<EntityId>) -> bool {
        match self {
            Self::Purpose(row_purpose) => purpose == Some(row_purpose),
            Self::Actor(row_actor) => actor == Some(*row_actor),
        }
    }

    /// Pinned snake-case manifest name of a purpose selector. `Other` rows
    /// carry their own name; the manifest parser maps every built-in name to
    /// its variant, so an `Other` name never collides with a built-in one.
    pub(crate) fn purpose_manifest_name(purpose: &CallPurpose) -> &str {
        match purpose {
            CallPurpose::Extraction => "extraction",
            CallPurpose::Consolidation => "consolidation",
            CallPurpose::AnswerGen => "answer_gen",
            CallPurpose::AutoCheck => "auto_check",
            CallPurpose::ToolRouting => "tool_routing",
            CallPurpose::Voice => "voice",
            CallPurpose::Eval => "eval",
            CallPurpose::Other { name } => name,
        }
    }
}

#[derive(Debug, Clone)]
pub struct BudgetGuard {
    state: Arc<Mutex<BudgetState>>,
}

impl BudgetGuard {
    #[must_use]
    pub fn new(
        attempt_id: impl Into<String>,
        limit_units: u64,
        on_budget_exhausted: BudgetExhaustionPolicy,
    ) -> Self {
        Self::with_reserve_units(
            attempt_id,
            limit_units,
            DEFAULT_BUDGET_RESERVE_UNITS,
            on_budget_exhausted,
        )
    }

    #[must_use]
    pub fn with_reserve_units(
        attempt_id: impl Into<String>,
        limit_units: u64,
        reserve_units: u64,
        on_budget_exhausted: BudgetExhaustionPolicy,
    ) -> Self {
        Self {
            state: Arc::new(Mutex::new(BudgetState::new(
                attempt_id.into(),
                limit_units,
                reserve_units,
                on_budget_exhausted,
                None,
                BudgetPolicyTable::default(),
            ))),
        }
    }

    /// The policy-aware primitive: the same single meter, plus the resolved
    /// [`BudgetPolicyTable`] and the engine-stamped actor this guard is bound
    /// to. The actor comes from durable write provenance at construction and
    /// is never read from request JSON, so one policy-aware guard belongs to
    /// one actor and must not be reused for another's calls.
    ///
    /// The table must already have passed `resolve_policy_manifest`: this
    /// constructor performs no fallible row validation.
    #[must_use]
    pub(crate) fn with_policy_table(
        attempt_id: impl Into<String>,
        limit_units: u64,
        reserve_units: u64,
        on_budget_exhausted: BudgetExhaustionPolicy,
        actor: WriteActor,
        policy: &BudgetPolicyTable,
    ) -> Self {
        debug_assert!(
            policy.rows().len() <= usize::from(u16::MAX) + 1,
            "resolved budget policy rows must stay addressable by a u16 row index"
        );
        let state = BudgetState::new(
            attempt_id.into(),
            limit_units,
            reserve_units,
            on_budget_exhausted,
            Some(actor.entity_ref()),
            policy.clone(),
        );
        debug_assert_eq!(state.row_tallies.len(), state.policy.rows().len());
        Self {
            state: Arc::new(Mutex::new(state)),
        }
    }

    pub fn admit(&self) -> Result<BudgetAdmission, BudgetDenied> {
        let mut state = self.lock_state();
        let reserve_units = state.reserve_units;
        let lease = state.reserve(reserve_units)?;
        Ok(state.metered_admission(lease))
    }

    pub fn admit_for_request(&self, request: &LlmRequest) -> Result<BudgetAdmission, BudgetDenied> {
        let mut state = self.lock_state();
        let purpose = &request.envelope.purpose;
        let reserve_units = state.reserve_units;
        let continue_local = matches!(request.envelope.locality, ModelLocality::OnDevice)
            && matches!(
                state.on_budget_exhausted,
                BudgetExhaustionPolicy::ContinueOnLocal
            )
            && state.local_continuation_available(reserve_units, Some(purpose));
        if continue_local {
            let lease = state.issue_lease(0, false, "local");
            let read = state.read();
            return Ok(BudgetAdmission {
                lease,
                read,
                ladder_events: Vec::new(),
            });
        }

        let lease = state.reserve_for(reserve_units, Some(purpose))?;
        Ok(state.metered_admission(lease))
    }

    pub fn admit_local(&self) -> Result<BudgetAdmission, BudgetDenied> {
        let mut state = self.lock_state();
        let reserve_units = state.reserve_units;
        if !matches!(
            state.on_budget_exhausted,
            BudgetExhaustionPolicy::ContinueOnLocal
        ) || !state.local_continuation_available(reserve_units, None)
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
        let mut state = self.lock_state();
        let lease = state.reserve(reserve_units)?;
        Ok(state.metered_admission(lease))
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
        let mut settled = None;
        {
            let Some(record) = state.leases.get_mut(lease.id()) else {
                return Err(BudgetDenied::LeaseInvalid);
            };
            match record.state {
                LeaseState::Open => {
                    record.state = LeaseState::Settled {
                        absolute_used_units,
                    };
                    settled = Some(record.clone());
                }
                LeaseState::Settled { .. } => {}
                LeaseState::Aborted => return Err(BudgetDenied::LeaseInvalid),
            }
        }
        if let Some(record) = settled {
            release_reservations_for_lease(&mut state, &record);
            if record.metered {
                state.used_units = state.used_units.max(absolute_used_units);
                apply_absolute_usage_for_lease(&mut state, &record, absolute_used_units);
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
        let mut aborted = None;
        {
            let Some(record) = state.leases.get_mut(lease.id()) else {
                return Err(BudgetDenied::LeaseInvalid);
            };
            match record.state {
                LeaseState::Open => {
                    record.state = LeaseState::Aborted;
                    aborted = Some(record.clone());
                }
                LeaseState::Aborted => {}
                LeaseState::Settled { .. } => return Err(BudgetDenied::LeaseInvalid),
            }
        }
        if let Some(record) = aborted {
            release_reservations_for_lease(&mut state, &record);
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

/// Per-row bookkeeping inside the one meter. `used_units`/`reserved_units`
/// carry the full charge of every call matching the row — those are the cap
/// and ladder tallies. The `floor_*` pair is the allocation partition: how
/// much of that spend the row's own floor protects.
#[derive(Debug, Clone, Default)]
struct BudgetRowTally {
    used_units: u64,
    reserved_units: u64,
    floor_used_units: u64,
    floor_reserved_units: u64,
    fired_thresholds: BTreeSet<BudgetThreshold>,
}

/// How much of one lease is protected by one matched row's floor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FloorAllocation {
    row_index: u16,
    units: u64,
}

/// The floor/shared split one admission would take, computed before any
/// mutation and then committed verbatim.
#[derive(Debug, Clone, Default)]
struct ReserveAllocation {
    matched_rows: Vec<u16>,
    floor_allocations: Vec<FloorAllocation>,
    shared_units: u64,
}

/// Outcome of the pure pre-mutation projection for one reserve request.
#[derive(Debug)]
enum ReservePlan {
    Admit(ReserveAllocation),
    /// A matched row cap refuses the call. Deliberate policy, never capacity:
    /// this denial is final and never yields a local-continuation lease.
    DeniedByCap,
    /// Global, shared-slice, or floor-headroom capacity refuses the call.
    DeniedByCapacity,
}

#[derive(Debug)]
struct BudgetState {
    attempt_id: String,
    limit_units: u64,
    reserve_units: u64,
    on_budget_exhausted: BudgetExhaustionPolicy,
    used_units: u64,
    reserved_units: u64,
    next_lease_seq: u64,
    fired_thresholds: BTreeSet<BudgetThreshold>,
    leases: BTreeMap<String, LeaseRecord>,
    /// Engine-stamped actor this meter is bound to, for actor selectors.
    actor: Option<EntityId>,
    policy: BudgetPolicyTable,
    row_tallies: Vec<BudgetRowTally>,
    total_floor_units: u64,
    row_horizons: Vec<u64>,
    shared_used_units: u64,
    shared_reserved_units: u64,
}

impl BudgetState {
    fn new(
        attempt_id: String,
        limit_units: u64,
        reserve_units: u64,
        on_budget_exhausted: BudgetExhaustionPolicy,
        actor: Option<EntityId>,
        policy: BudgetPolicyTable,
    ) -> Self {
        let row_tallies = vec![BudgetRowTally::default(); policy.rows().len()];
        let total_floor_units = policy
            .rows()
            .iter()
            .filter_map(BudgetPolicyRow::floor_units)
            .fold(0, u64::saturating_add);
        let mut selector_floor_units = HashMap::new();
        for row in policy.rows() {
            let Some(floor_units) = row.floor_units() else {
                continue;
            };
            selector_floor_units
                .entry(row.selector().clone())
                .and_modify(|sum: &mut u64| *sum = sum.saturating_add(floor_units))
                .or_insert(floor_units);
        }
        let row_horizons = policy
            .rows()
            .iter()
            .map(|row| {
                let leaseable_floor_units = selector_floor_units
                    .get(row.selector())
                    .copied()
                    .unwrap_or(0);
                let inaccessible_floor_units =
                    total_floor_units.saturating_sub(leaseable_floor_units);
                row.cap_units()
                    .unwrap_or(u64::MAX)
                    .min(limit_units.saturating_sub(inaccessible_floor_units))
            })
            .collect();
        Self {
            attempt_id,
            limit_units,
            reserve_units,
            on_budget_exhausted,
            used_units: 0,
            reserved_units: 0,
            next_lease_seq: 0,
            fired_thresholds: BTreeSet::new(),
            leases: BTreeMap::new(),
            actor,
            policy,
            row_tallies,
            total_floor_units,
            row_horizons,
            shared_used_units: 0,
            shared_reserved_units: 0,
        }
    }

    fn reserve(&mut self, reserve_units: u64) -> Result<BudgetLease, BudgetDenied> {
        self.reserve_for(reserve_units, None)
    }

    /// `purpose` is `None` for the generic admissions: it suppresses
    /// purpose-row matching only, the construction-bound actor still binds.
    fn reserve_for(
        &mut self,
        reserve_units: u64,
        purpose: Option<&CallPurpose>,
    ) -> Result<BudgetLease, BudgetDenied> {
        if reserve_units == 0 {
            return Err(BudgetDenied::AdmissionDenied);
        }

        let allocation = match self.plan_reserve(reserve_units, purpose) {
            ReservePlan::Admit(allocation) => allocation,
            ReservePlan::DeniedByCap | ReservePlan::DeniedByCapacity => {
                return Err(BudgetDenied::Exhausted);
            }
        };

        self.commit_reservation(reserve_units, &allocation);
        Ok(self.issue_lease_with(reserve_units, true, "metered", allocation))
    }

    /// Projects one admission without mutating any global, shared, row, floor,
    /// threshold, or lease state.
    fn plan_reserve(&self, reserve_units: u64, purpose: Option<&CallPurpose>) -> ReservePlan {
        if self.policy.is_empty() {
            // Empty/absent table: the single-pool branch, taken before any row
            // allocation, so lease ids, denials, reads, and ladders stay
            // byte-identical to the plain meter.
            return self.plan_single_pool(reserve_units);
        }

        let matched_rows = self.matched_rows(purpose);
        if self.matched_cap_denies(&matched_rows, reserve_units) {
            return ReservePlan::DeniedByCap;
        }

        let (floor_allocations, shared_units) = self.allocate_floors(&matched_rows, reserve_units);
        let shared_projected = self.shared_committed().saturating_add(shared_units);
        if shared_units > 0 && shared_projected > self.shared_admission_ceiling() {
            return ReservePlan::DeniedByCapacity;
        }
        if self.global_denies(reserve_units) {
            // Floors partition the base total; they never create budget.
            return ReservePlan::DeniedByCapacity;
        }

        ReservePlan::Admit(ReserveAllocation {
            matched_rows,
            floor_allocations,
            shared_units,
        })
    }

    fn plan_single_pool(&self, reserve_units: u64) -> ReservePlan {
        if self.global_denies(reserve_units) {
            return ReservePlan::DeniedByCapacity;
        }
        ReservePlan::Admit(ReserveAllocation::default())
    }

    fn global_denies(&self, reserve_units: u64) -> bool {
        self.global_committed().saturating_add(reserve_units) > self.cap_units()
    }

    /// Row indices whose selector matches this call, in resolved order.
    fn matched_rows(&self, purpose: Option<&CallPurpose>) -> Vec<u16> {
        self.policy
            .rows()
            .iter()
            .enumerate()
            .filter(|(_, row)| row.selector().matches(purpose, self.actor))
            .filter_map(|(index, _)| u16::try_from(index).ok())
            .collect()
    }

    /// Caps are conjunctive: a matching call must fit every matched cap.
    fn matched_cap_denies(&self, matched_rows: &[u16], reserve_units: u64) -> bool {
        matched_rows.iter().any(|&row_index| {
            let Some(cap_units) = self
                .policy_row(row_index)
                .and_then(BudgetPolicyRow::cap_units)
            else {
                return false;
            };
            let Some(tally) = self.row_tally(row_index) else {
                return false;
            };
            tally
                .used_units
                .saturating_add(tally.reserved_units)
                .saturating_add(reserve_units)
                > cap_units
        })
    }

    /// Draws matched floor headroom in resolved manifest order, then hands the
    /// remainder to the shared slice. An unmatched floor is never touched.
    fn allocate_floors(
        &self,
        matched_rows: &[u16],
        reserve_units: u64,
    ) -> (Vec<FloorAllocation>, u64) {
        let mut allocations = Vec::new();
        let mut remaining = reserve_units;
        for &row_index in matched_rows {
            if remaining == 0 {
                break;
            }
            let Some(floor_units) = self
                .policy_row(row_index)
                .and_then(BudgetPolicyRow::floor_units)
            else {
                continue;
            };
            let Some(tally) = self.row_tally(row_index) else {
                continue;
            };
            let committed = tally
                .floor_used_units
                .saturating_add(tally.floor_reserved_units);
            let units = remaining.min(floor_units.saturating_sub(committed));
            if units == 0 {
                continue;
            }
            allocations.push(FloorAllocation { row_index, units });
            remaining -= units;
        }
        (allocations, remaining)
    }

    fn commit_reservation(&mut self, reserve_units: u64, allocation: &ReserveAllocation) {
        self.reserved_units = self.reserved_units.saturating_add(reserve_units);
        for &row_index in &allocation.matched_rows {
            if let Some(tally) = self.row_tallies.get_mut(usize::from(row_index)) {
                tally.reserved_units = tally.reserved_units.saturating_add(reserve_units);
            }
        }
        for floor in &allocation.floor_allocations {
            if let Some(tally) = self.row_tallies.get_mut(usize::from(floor.row_index)) {
                tally.floor_reserved_units = tally.floor_reserved_units.saturating_add(floor.units);
            }
        }
        self.shared_reserved_units = self
            .shared_reserved_units
            .saturating_add(allocation.shared_units);
    }

    /// Global exhaustion, or a policy capacity block (shared slice or floor
    /// headroom) the metered branch would deny. A matched cap denial is
    /// deliberate policy, so it never reaches here.
    fn local_continuation_available(
        &self,
        reserve_units: u64,
        purpose: Option<&CallPurpose>,
    ) -> bool {
        if self.policy.is_empty() {
            return self.is_exhausted();
        }
        match self.plan_reserve(reserve_units, purpose) {
            ReservePlan::DeniedByCap => false,
            ReservePlan::DeniedByCapacity => true,
            ReservePlan::Admit(_) => self.is_exhausted(),
        }
    }

    /// `T - sum(all floors)`, saturating: oversubscribed floors leave no
    /// shared slice at all rather than wrapping.
    fn shared_slice_units(&self) -> u64 {
        self.limit_units.saturating_sub(self.total_floor_units)
    }

    fn shared_admission_ceiling(&self) -> u64 {
        let overdraft = self.cap_units().saturating_sub(self.limit_units);
        self.shared_slice_units().saturating_add(overdraft)
    }

    fn shared_committed(&self) -> u64 {
        self.shared_used_units
            .saturating_add(self.shared_reserved_units)
    }

    fn global_committed(&self) -> u64 {
        self.used_units.saturating_add(self.reserved_units)
    }

    fn policy_row(&self, row_index: u16) -> Option<&BudgetPolicyRow> {
        self.policy.rows().get(usize::from(row_index))
    }

    fn row_tally(&self, row_index: u16) -> Option<&BudgetRowTally> {
        self.row_tallies.get(usize::from(row_index))
    }

    fn metered_admission(&mut self, lease: BudgetLease) -> BudgetAdmission {
        let ladder_events = self.fire_ladder_events();
        let read = self.read();
        BudgetAdmission {
            lease,
            read,
            ladder_events,
        }
    }

    fn cap_units(&self) -> u64 {
        self.on_budget_exhausted.admission_cap(self.limit_units)
    }

    fn is_exhausted(&self) -> bool {
        self.used_units.saturating_add(self.reserved_units) >= self.cap_units()
    }

    fn issue_lease(&mut self, reserve_units: u64, metered: bool, kind: &str) -> BudgetLease {
        self.issue_lease_with(reserve_units, metered, kind, ReserveAllocation::default())
    }

    /// The lease id stays `<attempt>:<kind>:<seq>`: row indices, actor refs,
    /// and selector names never enter the public token.
    fn issue_lease_with(
        &mut self,
        reserve_units: u64,
        metered: bool,
        kind: &str,
        allocation: ReserveAllocation,
    ) -> BudgetLease {
        self.next_lease_seq = self.next_lease_seq.saturating_add(1);
        let lease_id = format!("{}:{kind}:{}", self.attempt_id, self.next_lease_seq);
        let lease = BudgetLease::issued(lease_id.clone());
        self.leases.insert(
            lease_id,
            LeaseRecord {
                reserve_units,
                metered,
                state: LeaseState::Open,
                matched_rows: allocation.matched_rows,
                floor_allocations: allocation.floor_allocations,
                shared_reserved_units: allocation.shared_units,
            },
        );
        lease
    }

    fn read(&self) -> BudgetRead {
        let cap_units = self.cap_units();
        let committed = self.used_units.saturating_add(self.reserved_units);
        BudgetRead {
            attempt_id: self.attempt_id.clone(),
            limit_units: self.limit_units,
            cap_units,
            used_units: self.used_units,
            reserved_units: self.reserved_units,
            remaining_units: cap_units.saturating_sub(committed),
            on_budget_exhausted: self.on_budget_exhausted,
            fired_thresholds: self.fired_thresholds.iter().copied().collect(),
        }
    }

    /// Fires the global ladder first, then row ladders. The global half is
    /// the unchanged single-pool ladder with `row_index: None`; row events
    /// follow in resolved row order, thresholds in 50/80/95 order, carrying
    /// `row_index: Some(i)` for the emitting meter's own policy table.
    fn fire_ladder_events(&mut self) -> Vec<BudgetLadderEvent> {
        let mut events = self.fire_global_ladder_events();
        events.extend(self.fire_row_ladder_events());
        events
    }

    /// The byte-identical single-pool ladder: global `used + reserved`
    /// against the meter's own `limit_units`, `row_index: None`.
    fn fire_global_ladder_events(&mut self) -> Vec<BudgetLadderEvent> {
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
                row_index: None,
            })
        })
        .collect()
    }

    /// Row ladders fire once per `(threshold, row)` — each row owns its
    /// threshold set, so the fire-once key is structural. The empty-table
    /// branch returns without a single event, keeping the single-pool
    /// meter's output exactly the global ladder.
    fn fire_row_ladder_events(&mut self) -> Vec<BudgetLadderEvent> {
        if self.policy.is_empty() {
            return Vec::new();
        }
        let mut events = Vec::new();
        for index in 0..self.policy.rows().len() {
            let horizon = self.row_horizon(index);
            let metered_units = {
                let Some(tally) = self.row_tallies.get(index) else {
                    continue;
                };
                tally.used_units.saturating_add(tally.reserved_units)
            };
            for threshold in [
                BudgetThreshold::Silent50,
                BudgetThreshold::Plan80,
                BudgetThreshold::Land95,
            ] {
                if percent_used(metered_units, horizon) < threshold.percent() {
                    continue;
                }
                let Some(tally) = self.row_tallies.get_mut(index) else {
                    continue;
                };
                if !tally.fired_thresholds.insert(threshold) {
                    continue;
                }
                events.push(BudgetLadderEvent {
                    threshold,
                    steering: steering_signal(threshold),
                    row_index: u16::try_from(index).ok(),
                });
            }
        }
        events
    }

    /// One row's fixed ladder horizon: its own cap when present, then bounded
    /// by the shared total minus every floor this row's selector can never
    /// draw. Saturating throughout, so oversubscribed floors pin the horizon
    /// at zero — 100% depleted — instead of wrapping or panicking.
    fn row_horizon(&self, row_index: usize) -> u64 {
        self.row_horizons.get(row_index).copied().unwrap_or(0)
    }
}

#[derive(Debug, Clone)]
struct LeaseRecord {
    reserve_units: u64,
    metered: bool,
    state: LeaseState,
    /// Resolved policy rows this lease's call matched; empty on the
    /// single-pool branch and on unmetered local leases.
    matched_rows: Vec<u16>,
    floor_allocations: Vec<FloorAllocation>,
    shared_reserved_units: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LeaseState {
    Open,
    Settled { absolute_used_units: u64 },
    Aborted,
}

/// Releases every reservation one lease holds, in the one critical section:
/// the global reserve, the full-charge reserve on every matched row, every
/// floor allocation, and the shared-slice share. Settlement calls this before
/// applying absolute usage; abort calls it alone and records no spend.
fn release_reservations_for_lease(state: &mut BudgetState, record: &LeaseRecord) {
    state.reserved_units = state.reserved_units.saturating_sub(record.reserve_units);
    for &row_index in &record.matched_rows {
        if let Some(tally) = state.row_tallies.get_mut(usize::from(row_index)) {
            tally.reserved_units = tally.reserved_units.saturating_sub(record.reserve_units);
        }
    }
    for floor in &record.floor_allocations {
        if let Some(tally) = state.row_tallies.get_mut(usize::from(floor.row_index)) {
            tally.floor_reserved_units = tally.floor_reserved_units.saturating_sub(floor.units);
        }
    }
    state.shared_reserved_units = state
        .shared_reserved_units
        .saturating_sub(record.shared_reserved_units);
}

/// Charges one metered lease's terminal absolute usage to every matched row.
///
/// Rows meter per-lease matched spend, so they may sum above the global
/// watermark when producers report per-response absolutes: rows are the
/// cap/ladder authority for matched traffic while the global meter stays the
/// total authority. The per-lease amount partitions floor-first — matched
/// floor headroom in resolved manifest order — and any remainder lands in
/// the shared partition, so overshoot beyond the slice is recorded as shared
/// spend and later admissions saturate-deny rather than any admitted call
/// being killed.
fn apply_absolute_usage_for_lease(
    state: &mut BudgetState,
    record: &LeaseRecord,
    absolute_used_units: u64,
) {
    for &row_index in &record.matched_rows {
        if let Some(tally) = state.row_tallies.get_mut(usize::from(row_index)) {
            tally.used_units = tally.used_units.saturating_add(absolute_used_units);
        }
    }
    let mut remaining = absolute_used_units;
    for &row_index in &record.matched_rows {
        if remaining == 0 {
            break;
        }
        let Some(floor_units) = state
            .policy_row(row_index)
            .and_then(BudgetPolicyRow::floor_units)
        else {
            continue;
        };
        let committed = state.row_tally(row_index).map_or(0, |tally| {
            tally
                .floor_used_units
                .saturating_add(tally.floor_reserved_units)
        });
        let units = remaining.min(floor_units.saturating_sub(committed));
        if units == 0 {
            continue;
        }
        if let Some(tally) = state.row_tallies.get_mut(usize::from(row_index)) {
            tally.floor_used_units = tally.floor_used_units.saturating_add(units);
        }
        remaining = remaining.saturating_sub(units);
    }
    state.shared_used_units = state.shared_used_units.saturating_add(remaining);
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
mod tests;
