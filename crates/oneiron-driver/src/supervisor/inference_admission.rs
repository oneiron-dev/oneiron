//! Host/device admission for inference work (DESIGN-V2 R4). One queue per
//! configured device orders foreground before background, then deadline and
//! arrival; the worker's own engine still chooses its microbatches.
//!
//! A ticket is only a queue position. It holds no execution grant while a
//! dependency or capacity blocks it. A successful grant atomically reserves
//! incremental bytes in the device ledger and lives until terminal release
//! or reap. Unknown capacity admits and records under the lead ruling.
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;

use oneiron::llm::{AdmissionGrant, ResourceClass, WorkClass, WorkPriority};
use tokio::sync::Notify;

use super::inference_device::{
    DeclaredEnvelope, DeviceLedger, DeviceSnapshot, TryReserveOutcome, WorkEnvelope,
};

mod load;
mod policy;
mod status;
mod ticket;
pub use policy::*;

pub type TicketId = u64;
pub type GrantId = u64;

/// One call's place on a device. The envelope is incremental: the worker's
/// weights and KV pool are charged once by its load/resident row.
#[derive(Debug, Clone)]
pub struct WorkRequest {
    pub worker_id: String,
    pub resource: ResourceClass,
    pub class: WorkClass,
    pub priority: WorkPriority,
    pub deadline: Option<Instant>,
    pub envelope: WorkEnvelope,
    pub parent: Option<TicketId>,
    pub cancel: Arc<AtomicBool>,
    pub profile_id: String,
}

impl WorkRequest {
    #[must_use]
    pub fn new(
        worker_id: impl Into<String>,
        resource: ResourceClass,
        profile_id: impl Into<String>,
    ) -> Self {
        Self {
            worker_id: worker_id.into(),
            resource,
            class: DEFAULT_WORK_CLASS,
            priority: WorkPriority::default(),
            deadline: DEFAULT_DEADLINE,
            envelope: WorkEnvelope::default(),
            parent: None,
            cancel: Arc::new(AtomicBool::new(false)),
            profile_id: profile_id.into(),
        }
    }
}

/// A queued call. Clones name the same ticket; cancellation is idempotent.
#[derive(Debug, Clone)]
pub struct WorkTicket {
    pub ticket: TicketId,
    pub device: String,
    pub request: WorkRequest,
    pub enqueued_at: Instant,
    pub blocked_by: Option<TicketId>,
    admission: Arc<DeviceAdmission>,
}

/// An execution reservation. Drop is the cancellation/reap backstop; explicit
/// release is the normal terminal path.
#[derive(Debug)]
pub struct DeviceGrant {
    admission: Arc<DeviceAdmission>,
    ticket: TicketId,
    grant: AdmissionGrant,
    unknown_capacity: bool,
    released: bool,
}

impl DeviceGrant {
    #[must_use]
    pub fn grant_id(&self) -> GrantId {
        self.grant.grant_id
    }

    #[must_use]
    pub fn revision(&self) -> u64 {
        self.grant.revision
    }

    #[must_use]
    pub fn resource_class(&self) -> ResourceClass {
        self.grant.resource_class
    }

    #[must_use]
    pub fn profile_id(&self) -> &str {
        &self.grant.profile_id
    }

    #[must_use]
    pub fn envelope_mib(&self) -> u64 {
        self.grant.envelope_mib
    }

    #[must_use]
    pub fn unknown_capacity(&self) -> bool {
        self.unknown_capacity
    }

    #[must_use]
    pub fn admission(&self) -> AdmissionGrant {
        self.grant.clone()
    }

    pub fn release(mut self) {
        self.release_inner();
    }

    fn release_inner(&mut self) {
        if self.released {
            return;
        }
        self.released = true;
        self.admission
            .release_grant(self.ticket, self.grant.grant_id);
    }
}

impl Drop for DeviceGrant {
    fn drop(&mut self) {
        self.release_inner();
    }
}

/// A transient load reservation. It never includes the call's incremental
/// workspace, so a queued call cannot block the launch that would serve it.
#[derive(Debug)]
pub struct LoadGrant {
    admission: Arc<DeviceAdmission>,
    worker_id: String,
    holder: String,
    released: bool,
}

impl LoadGrant {
    pub fn release(mut self) {
        self.release_inner();
    }

    fn release_inner(&mut self) {
        if !self.released {
            self.released = true;
            self.admission.release_load(&self.worker_id, &self.holder);
        }
    }
}

impl Drop for LoadGrant {
    fn drop(&mut self) {
        self.release_inner();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionStop {
    Deadline,
    Cancelled,
    DeviceStopped,
}

#[derive(Debug)]
pub enum PressureDecision {
    Grant(DeviceGrant),
    UnloadIdle(String),
    ApprovedSmallerProfile(String),
    Wait,
    Stop(AdmissionStop),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PressureState {
    None,
    UnloadedIdle(String),
    WaitingGrant,
    UnknownCapacityAdmitted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutorRegistration {
    pub worker_id: String,
    pub external: bool,
    pub idle: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WorkerQueueStatus {
    pub queued: u64,
    pub active: u64,
    pub paused: u64,
}

#[derive(Debug, Clone)]
struct LoadWaiter {
    class: WorkClass,
    sequence: u64,
}

#[derive(Debug, Clone)]
pub struct AdmissionSnapshot {
    pub device: String,
    pub capacity_mib: Option<u64>,
    pub queued_foreground: u64,
    pub queued_background: u64,
    pub active_grants: u64,
    pub paused: u64,
    pub ledger: DeviceSnapshot,
    pub pressure: PressureState,
    pub executors: Vec<ExecutorRegistration>,
    pub workers: BTreeMap<String, WorkerQueueStatus>,
    pub loads: BTreeMap<String, WorkClass>,
}

#[derive(Debug, Clone)]
struct TicketState {
    request: WorkRequest,
    enqueued_at: Instant,
    blocked_by: Option<TicketId>,
}

#[derive(Debug)]
struct AdmissionState {
    tickets: BTreeMap<TicketId, TicketState>,
    grants: BTreeMap<GrantId, TicketId>,
    paused: std::collections::BTreeSet<TicketId>,
    executors: BTreeMap<String, ExecutorRegistration>,
    reaping: std::collections::BTreeSet<String>,
    load_waiters: BTreeMap<String, LoadWaiter>,
    next_load: u64,
    background_serviced: HashMap<(ResourceClass, String), u64>,
    next_ticket: TicketId,
    next_grant: GrantId,
    revision: u64,
    pressure: PressureState,
    stopped: bool,
}

/// One host/device queue and its shared memory ledger.
pub struct DeviceAdmission {
    device: String,
    ledger: Arc<DeviceLedger>,
    state: Mutex<AdmissionState>,
    changed: Notify,
}

impl fmt::Debug for DeviceAdmission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceAdmission")
            .field("device", &self.device)
            .finish_non_exhaustive()
    }
}

impl DeviceAdmission {
    #[must_use]
    pub fn new(device: impl Into<String>, ledger: Arc<DeviceLedger>) -> Self {
        Self {
            device: device.into(),
            ledger,
            state: Mutex::new(AdmissionState {
                tickets: BTreeMap::new(),
                grants: BTreeMap::new(),
                paused: std::collections::BTreeSet::new(),
                executors: BTreeMap::new(),
                reaping: std::collections::BTreeSet::new(),
                load_waiters: BTreeMap::new(),
                next_load: 1,
                background_serviced: HashMap::new(),
                next_ticket: 1,
                next_grant: 1,
                revision: 1,
                pressure: PressureState::None,
                stopped: false,
            }),
            changed: Notify::new(),
        }
    }

    /// Registers an executor row for status and idle-unload decisions.
    pub fn register_executor(&self, registration: ExecutorRegistration) {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .executors
            .insert(registration.worker_id.clone(), registration);
        self.changed.notify_waiters();
    }

    /// Enqueues work without taking an execution grant.
    pub fn enqueue(self: &Arc<Self>, mut request: WorkRequest) -> WorkTicket {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let ticket = state.next_ticket;
        state.next_ticket = state.next_ticket.saturating_add(1);
        let enqueued_at = Instant::now();
        let parent = request
            .parent
            .filter(|parent| state.tickets.contains_key(parent));
        if let Some(parent) = parent.and_then(|id| state.tickets.get(&id)) {
            request.class = parent.request.class;
            request.deadline = parent.request.deadline;
            request.cancel = fresh_cancel(&parent.request.cancel);
        }
        request.parent = parent;
        if state.reaping.contains(&request.worker_id) {
            request.cancel.store(true, Ordering::Release);
        }
        state.tickets.insert(
            ticket,
            TicketState {
                request: request.clone(),
                enqueued_at,
                blocked_by: parent,
            },
        );
        drop(state);
        self.changed.notify_waiters();
        WorkTicket {
            ticket,
            device: self.device.clone(),
            request,
            enqueued_at,
            blocked_by: parent,
            admission: Arc::clone(self),
        }
    }

    /// Pure selection: no reservation or fairness cursor changes here.
    #[must_use]
    pub fn choose_next(self: &Arc<Self>) -> Option<WorkTicket> {
        let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let next = next_ticket(&state)?;
        Some(ticket_from(self, &state, next))
    }

    /// Attempts the selected ticket's atomic check-and-reserve. `Ok(None)`
    /// means it is blocked, not next, or has no qualified room.
    pub fn grant(
        self: &Arc<Self>,
        ticket: &WorkTicket,
    ) -> Result<Option<DeviceGrant>, AdmissionStop> {
        if !Arc::ptr_eq(self, &ticket.admission) {
            return Err(AdmissionStop::Cancelled);
        }
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(stop) = ticket_stop_locked(&state, ticket.ticket) {
            return Err(stop);
        }
        if next_ticket(&state) != Some(ticket.ticket) {
            return Ok(None);
        }
        let grant_id = state.next_grant;
        let holder = work_holder(grant_id);
        let request = state
            .tickets
            .get(&ticket.ticket)
            .expect("ticket checked")
            .request
            .clone();
        let outcome = self
            .ledger
            .try_reserve(&holder, &request.envelope, request.resource);
        if outcome == TryReserveOutcome::NoRoom {
            let announce = state.pressure != PressureState::WaitingGrant;
            state.pressure = PressureState::WaitingGrant;
            drop(state);
            if announce {
                self.changed.notify_waiters();
            }
            return Ok(None);
        }
        state.next_grant = state.next_grant.saturating_add(1);
        state.grants.insert(grant_id, ticket.ticket);
        if request.class == WorkClass::Background {
            state
                .background_serviced
                .insert((request.resource, request.worker_id.clone()), grant_id);
        }
        state.revision = state.revision.saturating_add(1);
        let grant = AdmissionGrant {
            grant_id,
            revision: state.revision,
            resource_class: request.resource,
            profile_id: request.profile_id.clone(),
            envelope_mib: request.envelope.known_total_mib(),
        };
        state.pressure = if outcome == TryReserveOutcome::AdmittedUnknown {
            PressureState::UnknownCapacityAdmitted
        } else {
            PressureState::None
        };
        drop(state);
        self.changed.notify_waiters();
        Ok(Some(DeviceGrant {
            admission: Arc::clone(&ticket.admission),
            ticket: ticket.ticket,
            grant,
            unknown_capacity: outcome == TryReserveOutcome::AdmittedUnknown,
            released: false,
        }))
    }

    /// Updates a dependency without granting or reserving. A missing parent
    /// has ended, so its child loses the block but keeps the inherited facts.
    pub fn update_dependency(&self, ticket: TicketId, parent: Option<TicketId>) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let parent = parent.filter(|parent| {
            state.tickets.contains_key(parent) && !dependency_reaches(&state, *parent, ticket)
        });
        let inherited = parent.and_then(|id| {
            state
                .tickets
                .get(&id)
                .map(|parent| (id, parent.request.clone()))
        });
        if let Some(ticket) = state.tickets.get_mut(&ticket) {
            match inherited {
                Some((parent_id, parent)) => {
                    ticket.request.class = parent.class;
                    ticket.request.deadline = parent.deadline;
                    ticket.request.cancel = fresh_cancel(&parent.cancel);
                    ticket.request.parent = Some(parent_id);
                    ticket.blocked_by = Some(parent_id);
                }
                None => {
                    ticket.request.cancel = fresh_cancel(&ticket.request.cancel);
                    ticket.request.parent = None;
                    ticket.blocked_by = None;
                }
            }
        }
        drop(state);
        self.changed.notify_waiters();
    }

    /// Cancels a ticket and its dependent descendants. Granted bytes are
    /// released only through the same ledger door as terminal Drop.
    pub fn cancel(&self, ticket: TicketId) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let mut pending = vec![ticket];
        let mut released = Vec::new();
        while let Some(ticket) = pending.pop() {
            let children: Vec<TicketId> = state
                .tickets
                .iter()
                .filter(|(_, child)| child.blocked_by == Some(ticket))
                .map(|(id, _)| *id)
                .collect();
            pending.extend(children);
            if let Some(ticket) = state.tickets.remove(&ticket) {
                ticket.request.cancel.store(true, Ordering::Release);
            }
            if let Some(grant) = state
                .grants
                .iter()
                .find(|(_, attempt)| **attempt == ticket)
                .map(|(grant, _)| *grant)
            {
                state.grants.remove(&grant);
                released.push(grant);
            }
            state.paused.remove(&ticket);
        }
        drop(state);
        for grant in released {
            self.ledger.release_hold(&work_holder(grant));
        }
        self.changed.notify_waiters();
    }

    /// Stops this device queue and cancels every queued or granted ticket.
    pub fn stop(&self) {
        let tickets: Vec<TicketId> = {
            let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            state.stopped = true;
            state.tickets.keys().copied().collect()
        };
        for ticket in tickets {
            self.cancel(ticket);
        }
        self.changed.notify_waiters();
    }

    /// Fit, else idle unload, then an approved smaller profile, then wait.
    /// Unknown capacity has already admitted inside `grant`.
    pub fn resolve_pressure(self: &Arc<Self>, ticket: &WorkTicket) -> PressureDecision {
        self.resolve_pressure_excluding(ticket, &BTreeSet::new())
    }

    /// One pressure pass, excluding victims already tried. A victim must be
    /// idle both in its executor row and across its tickets and load holds.
    pub fn resolve_pressure_excluding(
        self: &Arc<Self>,
        ticket: &WorkTicket,
        tried: &BTreeSet<String>,
    ) -> PressureDecision {
        match self.grant(ticket) {
            Ok(Some(grant)) => return PressureDecision::Grant(grant),
            Err(stop) => return PressureDecision::Stop(stop),
            Ok(None) => {}
        }
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if next_ticket(&state) != Some(ticket.ticket) {
            return PressureDecision::Wait;
        }
        if !AUTO_PROFILE_SUBSTITUTION {
            // No approved profile list exists, so the second action is inert.
        }
        let idle = state
            .executors
            .values()
            .find(|executor| {
                executor.idle
                    && (UNLOAD_EXTERNAL || !executor.external)
                    && executor.worker_id != ticket.request.worker_id
                    && !tried.contains(&executor.worker_id)
                    && !state
                        .tickets
                        .values()
                        .any(|ticket| ticket.request.worker_id == executor.worker_id)
                    && !state.load_waiters.contains_key(&executor.worker_id)
                    && !self.ledger.has_hold(&load_holder(&executor.worker_id))
            })
            .map(|executor| executor.worker_id.clone());
        if let Some(worker) = idle {
            state.pressure = PressureState::UnloadedIdle(worker.clone());
            return PressureDecision::UnloadIdle(worker);
        }
        PressureDecision::Wait
    }

    /// Releases every grant/ticket of a reaped worker, then its load and row.
    pub fn reaped(&self, worker_id: &str) {
        let tickets: Vec<TicketId> = {
            let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            state.reaping.insert(worker_id.to_owned());
            worker_tickets(&state, worker_id)
        };
        for ticket in tickets {
            self.cancel(ticket);
        }
        // Tickets that arrived during the first sweep were marked cancelled
        // at enqueue. Remove them before the next incarnation may admit.
        let tickets: Vec<TicketId> = {
            let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            state.reaping.remove(worker_id);
            state.load_waiters.remove(worker_id);
            state
                .background_serviced
                .retain(|(_, worker), _| worker != worker_id);
            worker_tickets(&state, worker_id)
        };
        for ticket in tickets {
            self.cancel(ticket);
        }
        self.ledger.release_hold(&load_holder(worker_id));
        self.ledger.release(worker_id);
        self.changed.notify_waiters();
    }

    fn ticket_deadline(&self, ticket: TicketId) -> Option<Instant> {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .tickets
            .get(&ticket)
            .and_then(|ticket| ticket.request.deadline)
    }

    fn ticket_stop(&self, ticket: TicketId) -> Option<AdmissionStop> {
        ticket_stop_locked(
            &self.state.lock().unwrap_or_else(PoisonError::into_inner),
            ticket,
        )
    }

    fn release_grant(&self, ticket: TicketId, grant: GrantId) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.grants.remove(&grant);
        state.tickets.remove(&ticket);
        for child in state
            .tickets
            .values_mut()
            .filter(|child| child.blocked_by == Some(ticket))
        {
            child.blocked_by = None;
            child.request.parent = None;
            child.request.cancel = fresh_cancel(&child.request.cancel);
        }
        state.paused.remove(&ticket);
        state.pressure = PressureState::None;
        drop(state);
        self.ledger.release_hold(&work_holder(grant));
        self.changed.notify_waiters();
    }

    pub(crate) fn changed(&self) -> tokio::sync::futures::Notified<'_> {
        self.changed.notified()
    }
}

fn worker_tickets(state: &AdmissionState, worker_id: &str) -> Vec<TicketId> {
    state
        .tickets
        .iter()
        .filter(|(_, ticket)| ticket.request.worker_id == worker_id)
        .map(|(id, _)| *id)
        .collect()
}

fn fresh_cancel(current: &AtomicBool) -> Arc<AtomicBool> {
    Arc::new(AtomicBool::new(current.load(Ordering::Acquire)))
}

fn dependency_reaches(state: &AdmissionState, parent: TicketId, target: TicketId) -> bool {
    let mut current = Some(parent);
    let mut seen = std::collections::BTreeSet::new();
    while let Some(id) = current {
        if id == target || !seen.insert(id) {
            return true;
        }
        current = state.tickets.get(&id).and_then(|ticket| ticket.blocked_by);
    }
    false
}

fn ticket_live(ticket: &TicketState, now: Instant) -> bool {
    !ticket.request.cancel.load(Ordering::Acquire)
        && ticket
            .request
            .deadline
            .is_none_or(|deadline| deadline > now)
}

fn is_granted(state: &AdmissionState, ticket: TicketId) -> bool {
    state.grants.values().any(|granted| *granted == ticket)
}

fn ticket_from(
    admission: &Arc<DeviceAdmission>,
    state: &AdmissionState,
    id: TicketId,
) -> WorkTicket {
    let ticket = &state.tickets[&id];
    WorkTicket {
        ticket: id,
        device: admission.device.clone(),
        request: ticket.request.clone(),
        enqueued_at: ticket.enqueued_at,
        blocked_by: ticket.blocked_by,
        admission: Arc::clone(admission),
    }
}

fn next_ticket(state: &AdmissionState) -> Option<TicketId> {
    if state.stopped {
        return None;
    }
    let now = Instant::now();
    let runnable = |ticket: &TicketState| {
        ticket.blocked_by.is_none()
            && !ticket.request.cancel.load(Ordering::Acquire)
            && ticket
                .request
                .deadline
                .is_none_or(|deadline| deadline > now)
    };
    let foreground = state
        .tickets
        .iter()
        .filter(|(id, ticket)| {
            !is_granted(state, **id)
                && !state.paused.contains(*id)
                && ticket.request.class == WorkClass::Foreground
                && runnable(ticket)
        })
        .map(|(id, ticket)| (*id, ticket.request.deadline))
        .min_by(|(a_id, a_deadline), (b_id, b_deadline)| {
            deadline_key(*a_deadline)
                .cmp(&deadline_key(*b_deadline))
                .then_with(|| a_id.cmp(b_id))
        });
    if let Some((ticket, _)) = foreground {
        return Some(ticket);
    }
    state
        .tickets
        .iter()
        .filter(|(id, ticket)| {
            !is_granted(state, **id)
                && !state.paused.contains(*id)
                && ticket.request.class == WorkClass::Background
                && runnable(ticket)
        })
        .map(|(id, ticket)| {
            let serviced = state
                .background_serviced
                .get(&(ticket.request.resource, ticket.request.worker_id.clone()))
                .copied()
                .unwrap_or(0);
            (*id, serviced, ticket.request.deadline)
        })
        .min_by(
            |(a_id, a_service, a_deadline), (b_id, b_service, b_deadline)| {
                a_service
                    .cmp(b_service)
                    .then_with(|| deadline_key(*a_deadline).cmp(&deadline_key(*b_deadline)))
                    .then_with(|| a_id.cmp(b_id))
            },
        )
        .map(|(ticket, _, _)| ticket)
}

fn deadline_key(deadline: Option<Instant>) -> (u8, Option<Instant>) {
    match deadline {
        Some(deadline) => (0, Some(deadline)),
        None => (1, None),
    }
}

fn ticket_stop_locked(state: &AdmissionState, ticket: TicketId) -> Option<AdmissionStop> {
    if state.stopped {
        return Some(AdmissionStop::DeviceStopped);
    }
    let Some(ticket) = state.tickets.get(&ticket) else {
        return Some(AdmissionStop::Cancelled);
    };
    if ticket.request.cancel.load(Ordering::Acquire) {
        return Some(AdmissionStop::Cancelled);
    }
    if ticket
        .request
        .deadline
        .is_some_and(|deadline| deadline <= Instant::now())
    {
        return Some(AdmissionStop::Deadline);
    }
    None
}

fn work_holder(grant: GrantId) -> String {
    format!("work:{grant}")
}

fn load_holder(worker_id: &str) -> String {
    format!("load:{worker_id}")
}
