use super::*;

/// Durable plan and checkpoint namespaces. Neither is an authority carrier.
pub const EMERGENCY_PLAN_META_PREFIX: &[u8] = b"booking:emergency_plan:v1:";
pub const EMERGENCY_ITEM_META_PREFIX: &[u8] = b"booking:emergency_item:v1:";

/// A plan is read back from its immutable persisted row before execution.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EmergencyPlan {
    pub(crate) request: EmergencyRescheduleRequest,
    pub(crate) booking: AffectedBooking,
    pub(crate) proposals: Vec<crate::booking::RankedSlot>,
    pub(crate) planned_at: u64,
    pub(crate) payload: Option<crate::calendar::CalendarInvitePayload>,
    pub(crate) recipient: String,
    pub(crate) organizer: String,
    pub(crate) invite_before: Option<crate::calendar::CalendarPassportValue>,
    pub(crate) content_hash: [u8; 32],
}

impl EmergencyPlan {
    pub fn booking(&self) -> &AffectedBooking {
        &self.booking
    }
    pub fn proposals(&self) -> &[crate::booking::RankedSlot] {
        &self.proposals
    }
    pub fn payload(&self) -> Option<&crate::calendar::CalendarInvitePayload> {
        self.payload.as_ref()
    }
    pub(super) fn hash(&self) -> Result<[u8; 32], BookingError> {
        content_hash(&(
            &self.request,
            &self.booking,
            &self.proposals,
            self.planned_at,
            &self.payload,
            &self.recipient,
            &self.organizer,
            &self.invite_before,
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EmergencyLocalBasis {
    PreStartCancellation,
    EmergencyAtOrAfterStart,
    RequestUpdate,
}

/// Local state is committed with both passports, before the first intent.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EmergencyItem {
    pub(crate) plan: EmergencyPlan,
    pub calendar: CalendarRevision,
    pub basis: EmergencyLocalBasis,
    pub committed_at: u64,
    pub actions: Vec<crate::booking::OpaqueLifecycleToken>,
    pub calendar_delivered: bool,
    pub apology_delivered: bool,
    pub(crate) picked: Option<EmergencyPick>,
}

impl EmergencyItem {
    pub fn picked(&self) -> Option<&EmergencyPick> {
        self.picked.as_ref()
    }
}

/// Failure of one booking does not prevent planning the others.
#[derive(Debug, Clone, PartialEq)]
pub struct EmergencyBatchPlan {
    pub plans: Vec<EmergencyPlan>,
    pub refusals: Vec<(EntityId, String)>,
}

pub(crate) fn item_key(
    request: &EmergencyRescheduleRequest,
    event: EntityId,
) -> Result<Vec<u8>, BookingError> {
    let mut key = EMERGENCY_ITEM_META_PREFIX.to_vec();
    key.extend_from_slice(
        hex_lower(&content_hash(&(
            request_instruction_key(request)?,
            event.to_hex(),
        ))?)
        .as_bytes(),
    );
    Ok(key)
}

fn plan_key(
    request: &EmergencyRescheduleRequest,
    event: EntityId,
) -> Result<Vec<u8>, BookingError> {
    let item = item_key(request, event)?;
    let mut key = EMERGENCY_PLAN_META_PREFIX.to_vec();
    key.extend_from_slice(&item[EMERGENCY_ITEM_META_PREFIX.len()..]);
    Ok(key)
}

pub(crate) fn read_item_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    key: &[u8],
) -> Result<Option<EmergencyItem>, BookingError> {
    read_meta_bytes(vault, txn, key)?
        .map(|raw| serde_json::from_slice(&raw).map_err(storage_failure))
        .transpose()
}

pub(crate) fn write_item_in(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    item: &EmergencyItem,
) -> Result<(), BookingError> {
    put_meta(
        vault,
        txn,
        &item_key(&item.plan.request, item.calendar.event_ref)?,
        &serde_json::to_vec(item).map_err(storage_failure)?,
    )
}

pub(crate) fn verify_plan_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    plan: &EmergencyPlan,
) -> Result<(), BookingError> {
    verify_instruction_in_txn(vault, txn, &plan.request)?;
    let raw = read_meta_bytes(
        vault,
        txn,
        &plan_key(&plan.request, plan.booking.calendar.event_ref)?,
    )?
    .ok_or_else(|| refused("no persisted genuine emergency proposal"))?;
    if raw != serde_json::to_vec(plan).map_err(storage_failure)?
        || plan.hash()? != plan.content_hash
    {
        return Err(refused(
            "emergency plan content conflicts with the persisted proposal",
        ));
    }
    Ok(())
}

/// Uses the landed solver with the saved constraints and exact original hosts.
/// Current routing cannot move this booking to a newly added host.
pub(crate) fn solve_live(
    vault: &Vault,
    booking: &AffectedBooking,
    calendars: &[(EntityId, Vec<crate::calendar::query::CalendarSel>)],
    window: TimeRange,
    now_utc: u64,
) -> Result<crate::booking::SolveResult, BookingError> {
    use crate::booking::{BookingSolver, SlotOracle, SolveRequest, VaultActiveHoldSource};
    let mut config = crate::booking::config::load_event_type_config(
        vault,
        booking.page_ref,
        &booking.event_type,
    )?;
    let owners = &booking.context.owner_refs;
    if owners.is_empty()
        || owners.iter().any(|owner| {
            !config
                .hosts
                .iter()
                .any(|host| host.host_ref.to_hex() == *owner)
        })
    {
        return Err(refused(
            "this booking's original hosts are unavailable in current configuration",
        ));
    }
    config
        .hosts
        .retain(|host| owners.contains(&host.host_ref.to_hex()));
    config.routing = if config.hosts.len() == 1 {
        crate::booking::RoutingMode::Either
    } else {
        crate::booking::RoutingMode::Both
    };
    let holds = VaultActiveHoldSource::new(vault);
    BookingSolver {
        vault,
        page_ref: booking.page_ref,
        calendars_by_host: calendars,
        holds: &holds,
        now_utc,
        synthetic_config: Some(config),
    }
    .solve(&SolveRequest {
        event_type: booking.event_type.clone(),
        window,
        constraint: booking.context.constraint.clone(),
        visitor_tz: booking.context.visitor_tz.clone(),
    })
}

/// Plans every independently usable booking. Existing persisted plans, including
/// cancelled items awaiting an apology retry, are returned without re-solving.
pub fn plan_emergency_reschedule(
    vault: &Vault,
    request: &EmergencyRescheduleRequest,
    calendars: &[(EntityId, Vec<crate::calendar::query::CalendarSel>)],
    now_utc: u64,
) -> Result<EmergencyBatchPlan, BookingError> {
    verify_logged_owner_instruction(vault, request)?;
    let mut batch = EmergencyBatchPlan {
        plans: Vec::new(),
        refusals: Vec::new(),
    };
    let mut saved_events = std::collections::BTreeSet::new();
    {
        let txn = vault.store.env.read_txn().map_err(storage_failure)?;
        verify_instruction_in_txn(vault, &txn, request)?;
        for row in vault
            .store
            .vault_meta
            .prefix_iter(&txn, EMERGENCY_PLAN_META_PREFIX)
            .map_err(storage_failure)?
        {
            let (_, raw) = row.map_err(storage_failure)?;
            let plan: EmergencyPlan = serde_json::from_slice(&raw).map_err(storage_failure)?;
            if plan.request == *request {
                let event = plan.booking.calendar.event_ref;
                saved_events.insert(event);
                verify_plan_in(vault, &txn, &plan)?;
                let item = read_item_in(vault, &txn, &item_key(request, event)?)?;
                if item.as_ref().is_some_and(|item| {
                    item.picked.is_some() || (item.calendar_delivered && item.apology_delivered)
                }) {
                    continue;
                }
                if item.is_none()
                    && (plan.booking.occurrence.start <= now_utc
                        || plan.proposals.iter().any(|slot| slot.start_utc <= now_utc))
                {
                    batch.refusals.push((
                        event,
                        "saved emergency proposals are no longer future".to_owned(),
                    ));
                    continue;
                }
                let expected = item
                    .as_ref()
                    .map_or(&plan.booking.calendar, |item| &item.calendar);
                match crate::booking::lifecycle::emergency_current_revision_in(vault, &txn, event) {
                    Ok(current) if current == *expected => batch.plans.push(plan),
                    Ok(_) => batch
                        .refusals
                        .push((event, "saved emergency plan is superseded".to_owned())),
                    Err(error @ (BookingError::SlotOracle(_) | BookingError::Boundary(_))) => {
                        return Err(error);
                    }
                    Err(error) => batch.refusals.push((event, error.to_string())),
                }
            }
        }
    }
    for booking in enumerate_with_refusals(vault, request, now_utc, &mut batch.refusals)? {
        let event = booking.calendar.event_ref;
        if saved_events.contains(&event) {
            continue;
        }
        match plan_item(vault, request, booking, calendars, now_utc) {
            Ok(plan) => batch.plans.push(plan),
            Err(error @ (BookingError::SlotOracle(_) | BookingError::Boundary(_))) => {
                return Err(error);
            }
            Err(error) => batch.refusals.push((event, error.to_string())),
        }
    }
    batch.plans.sort_by_key(|plan| {
        (
            plan.booking.occurrence.start,
            plan.booking.calendar.event_ref,
        )
    });
    Ok(batch)
}

pub(super) fn plan_item(
    vault: &Vault,
    request: &EmergencyRescheduleRequest,
    booking: AffectedBooking,
    calendars: &[(EntityId, Vec<crate::calendar::query::CalendarSel>)],
    now_utc: u64,
) -> Result<EmergencyPlan, BookingError> {
    use crate::calendar::{CalendarInviteMethod, CalendarInvitePayload};
    booking
        .calendar
        .sequence
        .checked_add(1)
        .ok_or_else(|| refused("booking passport sequence is exhausted"))?;
    let start = request
        .affected_window
        .end
        .checked_add(1)
        .ok_or_else(|| refused("replacement window is exhausted"))?
        .max(now_utc.saturating_add(1));
    let solved = solve_live(
        vault,
        &booking,
        calendars,
        TimeRange {
            start,
            end: start.saturating_add(7 * 86_400),
        },
        now_utc,
    )?;
    let mut proposals = Vec::new();
    for slot in solved.slots {
        if slot.start_utc <= now_utc || slot.start_utc < start || slot.end_utc <= slot.start_utc {
            continue;
        }
        if !proposals.iter().any(|prior: &crate::booking::RankedSlot| {
            prior.start_utc == slot.start_utc && prior.end_utc == slot.end_utc
        }) {
            proposals.push(slot);
        }
        if proposals.len() == 3 {
            break;
        }
    }
    if proposals.len() < 2 {
        return Err(refused(
            "this booking has fewer than two live solver proposals",
        ));
    }
    let (organizer, recipient) = delivery_parties(vault, &booking)?;
    let invite_before = {
        let txn = vault.store.env.read_txn().map_err(storage_failure)?;
        state::invite_head_in(vault, &txn, &booking.calendar)?
    };
    let sequence = state::next_invite_sequence(invite_before.as_ref())?;
    let method = match request.action_policy {
        EmergencyActionPolicy::Cancel => CalendarInviteMethod::Cancel,
        EmergencyActionPolicy::RequestUpdate => CalendarInviteMethod::Request,
    };
    let slot = if method == CalendarInviteMethod::Cancel {
        booking.occurrence
    } else {
        TimeRange {
            start: proposals[0].start_utc,
            end: proposals[0].end_utc,
        }
    };
    // No invitation existed: cancellation is local plus apology, not a fake
    // CANCEL or a synthetic sequence-zero invite. A later pick sends the first REQUEST.
    let ics = if method == CalendarInviteMethod::Cancel && invite_before.is_none() {
        None
    } else {
        Some(
            crate::calendar::ics::emit_imip_ics(&crate::calendar::ics::ImipEmitRequest {
                method,
                uid: booking.calendar.uid.clone(),
                sequence,
                organizer: organizer.clone(),
                attendees: vec![recipient.clone()],
                summary: booking.event_type.0.clone(),
                starts_at_utc: slot.start,
                ends_at_utc: slot.end,
                tz_label: booking.context.visitor_tz.clone(),
                dtstamp_utc: now_utc,
            })
            .map_err(storage_failure)?,
        )
    };
    let mut plan = EmergencyPlan {
        request: request.clone(),
        payload: ics
            .as_ref()
            .map(|ics| {
                Ok::<_, BookingError>(CalendarInvitePayload {
                    method,
                    uid: booking.calendar.uid.clone(),
                    sequence,
                    ics_blob_ref: format!("blob:{}", blob_id(ics)?.to_hex()),
                    recipient: recipient.clone(),
                })
            })
            .transpose()?,
        booking,
        proposals,
        planned_at: now_utc,
        recipient,
        organizer,
        invite_before,
        content_hash: [0; 32],
    };
    plan.content_hash = plan.hash()?;
    booking_writer(vault, |txn| {
        verify_instruction_in_txn(vault, txn, request)?;
        if crate::booking::lifecycle::emergency_current_revision_in(
            vault,
            txn,
            plan.booking.calendar.event_ref,
        )? != plan.booking.calendar
            || state::invite_head_in(vault, txn, &plan.booking.calendar)? != plan.invite_before
        {
            return Err(refused("booking or invitation changed during planning"));
        }
        let key = plan_key(request, plan.booking.calendar.event_ref)?;
        let encoded = serde_json::to_vec(&plan).map_err(storage_failure)?;
        if let Some(prior) = read_meta_bytes(vault, txn, &key)? {
            if prior != encoded {
                return Err(refused(
                    "same emergency revision has conflicting plan content",
                ));
            }
        } else {
            if let Some(ics) = &ics {
                persist_content_in(
                    vault,
                    txn,
                    request,
                    &plan.booking.event_type.0,
                    crate::calendar::CALENDAR_INVITE_MEDIA_TYPE,
                    ics,
                    now_utc,
                )?;
            }
            put_meta(vault, txn, &key, &encoded)?;
        }
        Ok(())
    })?;
    Ok(plan)
}

pub(crate) fn verify_initial_invite_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    plan: &EmergencyPlan,
) -> Result<(), BookingError> {
    if state::invite_head_in(vault, txn, &plan.booking.calendar)? != plan.invite_before {
        return Err(refused(
            "initial invitation changed after emergency planning",
        ));
    }
    Ok(())
}

pub(crate) fn verify_plan_blob(vault: &Vault, plan: &EmergencyPlan) -> Result<(), BookingError> {
    let Some(payload) = &plan.payload else {
        return Ok(());
    };
    let bytes =
        crate::calendar::read_calendar_invite_ics(vault, payload).map_err(storage_failure)?;
    if payload.ics_blob_ref != format!("blob:{}", blob_id(&bytes)?.to_hex()) {
        return Err(refused(
            "emergency ICS content conflicts with its content-addressed plan",
        ));
    }
    Ok(())
}

pub(super) fn blob_id(bytes: &[u8]) -> Result<EntityId, BookingError> {
    let hash = blake3::hash(bytes);
    let mut id = [0; 16];
    id.copy_from_slice(&hash.as_bytes()[..16]);
    EntityId::from_bytes(id).map_err(storage_failure)
}

pub(super) fn delivery_parties(
    vault: &Vault,
    booking: &AffectedBooking,
) -> Result<(String, String), BookingError> {
    let contact = EntityId::from_hex(&booking.context.booker_ref).map_err(storage_failure)?;
    let recipient = crate::booking::invite_grant::booker_identity(vault, &contact)?
        .ok_or_else(|| refused("stored booker contact has no delivery identity"))?;
    if let Some((organizer, bound_recipient)) =
        crate::booking::lifecycle::booking_invite_identity(vault, &booking.calendar.event_ref)?
    {
        if recipient != bound_recipient {
            return Err(refused(
                "stored booker differs from the original invite recipient",
            ));
        }
        return Ok((organizer, recipient));
    }
    // Before the first invite, resolve only a confirmation-bound host, in
    // canonical host order. The initiating Both owner does not select ORGANIZER.
    for host in &booking.context.owner_refs {
        let host = EntityId::from_hex(host).map_err(storage_failure)?;
        if let Some(organizer) = crate::booking::invite_grant::sending_address(vault, host)? {
            return Ok((organizer, recipient));
        }
    }
    Err(refused(
        "bound booking hosts have no active sending identity",
    ))
}
