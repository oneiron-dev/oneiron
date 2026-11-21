//! Ticket-queue selection, dependency, stop truth, and holder names.

use super::*;

pub(super) fn worker_tickets(state: &AdmissionState, worker_id: &str) -> Vec<TicketId> {
    state
        .tickets
        .iter()
        .filter(|(_, ticket)| ticket.request.worker_id == worker_id)
        .map(|(id, _)| *id)
        .collect()
}

pub(super) fn fresh_cancel(current: &AtomicBool) -> Arc<AtomicBool> {
    Arc::new(AtomicBool::new(current.load(Ordering::Acquire)))
}

pub(super) fn fresh_cancel_changed() -> Arc<Notify> {
    Arc::new(Notify::new())
}

pub(super) fn dependency_reaches(
    state: &AdmissionState,
    parent: TicketId,
    target: TicketId,
) -> bool {
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

pub(super) fn ticket_from(
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

pub(super) fn next_ticket(state: &AdmissionState) -> Option<TicketId> {
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

pub(super) fn ticket_stop_locked(
    state: &AdmissionState,
    ticket: TicketId,
) -> Option<AdmissionStop> {
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

pub(super) fn work_holder(grant: GrantId) -> String {
    format!("work:{grant}")
}
