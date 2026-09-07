//! Proposal-bound follow-up REQUESTs. CAL owns ICS and admission; outbound
//! owns effects. The lifecycle writer owns the revision and this checkpoint.

use super::*;

/// The exact follow-up revision committed by a pick. Delivery retries never
/// rebuild its timestamp, blob, sequence, or intent identity.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EmergencyPick {
    pub proposal_index: usize,
    pub calendar: CalendarRevision,
    pub committed_at: u64,
    pub calendar_delivered: bool,
    pub(crate) payload: crate::calendar::CalendarInvitePayload,
    pub(crate) organizer: String,
    pub(crate) content_hash: [u8; 32],
}

impl EmergencyPick {
    pub fn payload(&self) -> &crate::calendar::CalendarInvitePayload {
        &self.payload
    }

    fn hash(&self, item: &EmergencyItem) -> Result<[u8; 32], BookingError> {
        content_hash(&(
            item.plan.content_hash,
            self.proposal_index,
            &self.calendar,
            self.committed_at,
            &self.payload,
            &self.organizer,
        ))
    }

    fn ics(&self, item: &EmergencyItem) -> Result<Vec<u8>, BookingError> {
        let slot = item
            .plan
            .proposals
            .get(self.proposal_index)
            .ok_or_else(|| refused("missing genuine picked proposal"))?;
        crate::calendar::ics::emit_imip_ics(&crate::calendar::ics::ImipEmitRequest {
            method: crate::calendar::CalendarInviteMethod::Request,
            uid: self.calendar.uid.clone(),
            sequence: self.payload.sequence,
            organizer: self.organizer.clone(),
            attendees: vec![item.plan.recipient.clone()],
            summary: item.plan.booking.event_type.0.clone(),
            starts_at_utc: slot.start_utc,
            ends_at_utc: slot.end_utc,
            tz_label: item.plan.booking.context.visitor_tz.clone(),
            dtstamp_utc: self.committed_at,
        })
        .map_err(storage_failure)
    }
}

pub(super) fn prepare_pick(
    vault: &Vault,
    item: &EmergencyItem,
    proposal_index: usize,
    now_utc: u64,
) -> Result<EmergencyPick, BookingError> {
    if let Some(picked) = &item.picked {
        if picked.proposal_index != proposal_index {
            return Err(refused("this emergency action has already been consumed"));
        }
        return Ok(picked.clone());
    }
    let sequence = item
        .calendar
        .sequence
        .checked_add(1)
        .ok_or_else(|| refused("booking passport sequence is exhausted"))?;
    let organizer = item.plan.organizer.clone();
    let recipient = item.plan.recipient.clone();
    let invite_sequence = item.plan.payload.as_ref().map_or(Ok(0), |payload| {
        payload
            .sequence
            .checked_add(1)
            .ok_or_else(|| refused("calendar invite sequence is exhausted"))
    })?;
    let mut picked = EmergencyPick {
        proposal_index,
        calendar: CalendarRevision {
            sequence,
            ..item.calendar.clone()
        },
        committed_at: now_utc,
        calendar_delivered: false,
        organizer,
        payload: crate::calendar::CalendarInvitePayload {
            method: crate::calendar::CalendarInviteMethod::Request,
            uid: item.calendar.uid.clone(),
            sequence: invite_sequence,
            ics_blob_ref: String::new(),
            recipient,
        },
        content_hash: [0; 32],
    };
    let ics = picked.ics(item)?;
    picked.payload.ics_blob_ref = booking_writer(vault, |txn| {
        verify_plan_in(vault, txn, &item.plan)?;
        verify_pick_invite_in(vault, txn, item)?;
        if crate::booking::lifecycle::emergency_current_revision_in(
            vault,
            txn,
            item.calendar.event_ref,
        )? != item.calendar
        {
            return Err(refused("pick preparation is superseded"));
        }
        persist_content_in(
            vault,
            txn,
            &item.plan.request,
            &item.plan.booking.event_type.0,
            crate::calendar::CALENDAR_INVITE_MEDIA_TYPE,
            &ics,
            now_utc,
        )
    })?;
    picked.content_hash = picked.hash(item)?;
    Ok(picked)
}

pub(crate) fn verify_pick_invite_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    item: &EmergencyItem,
) -> Result<(), BookingError> {
    let head = state::invite_head_in(vault, txn, &item.calendar)?;
    if head.as_ref().map(|head| head.last_sequence)
        != item.plan.payload.as_ref().map(|payload| payload.sequence)
    {
        return Err(refused("invitation changed before the emergency pick"));
    }
    Ok(())
}

pub(crate) fn verify_pick_blob(
    vault: &Vault,
    item: &EmergencyItem,
    picked: &EmergencyPick,
) -> Result<(), BookingError> {
    if picked.calendar.event_ref != item.calendar.event_ref
        || picked.calendar.uid != item.calendar.uid
        || Some(picked.calendar.sequence) != item.calendar.sequence.checked_add(1)
        || picked.payload.uid != picked.calendar.uid
        || Some(picked.payload.sequence)
            != item
                .plan
                .payload
                .as_ref()
                .map_or(Some(0), |payload| payload.sequence.checked_add(1))
        || picked.organizer != item.plan.organizer
        || picked.payload.method != crate::calendar::CalendarInviteMethod::Request
        || picked.payload.recipient != item.plan.recipient
        || picked.hash(item)? != picked.content_hash
    {
        return Err(refused(
            "picked content does not bind this emergency revision",
        ));
    }
    let bytes = crate::calendar::read_calendar_invite_ics(vault, &picked.payload)
        .map_err(storage_failure)?;
    if bytes != picked.ics(item)?
        || picked.payload.ics_blob_ref != format!("blob:{}", blob_id(&bytes)?.to_hex())
    {
        return Err(refused(
            "picked ICS differs from the durable proposal-bound content",
        ));
    }
    Ok(())
}

/// An opaque action selects only its persisted genuine proposal. Success means
/// the home-node revision AND its follow-up REQUEST have completed. A failure
/// after commit resumes the same checkpoint and outbound intent on the next call.
pub fn counterparty_pick(
    vault: &Vault,
    token: &crate::booking::OpaqueLifecycleToken,
    calendars: &[(EntityId, Vec<crate::calendar::query::CalendarSel>)],
    input: &crate::booking::BookingLifecycleConsumerInput,
    sink: &mut impl crate::outbound::OutboundExecutionSink,
) -> Result<CalendarRevision, BookingError> {
    let (snapshot, proposal_index) =
        crate::booking::lifecycle::read_emergency_pick(vault, token, input)?;
    let prepared = prepare_pick(vault, &snapshot, proposal_index, input.now_utc)?;
    let item =
        crate::booking::lifecycle::pick_emergency_item(vault, token, calendars, input, &prepared)?;
    let picked = item
        .picked
        .as_ref()
        .ok_or_else(|| refused("pick checkpoint disappeared"))?;
    if !picked.calendar_delivered {
        verify_pick_blob(vault, &item, picked)?;
        crate::booking::lifecycle::admit_emergency_pick(vault, &item, input)?;
        super::execution::dispatch_item_effect(
            vault,
            &item,
            super::execution::EmergencyEffect::Pick,
            sink,
            input.now_utc,
        )?;
        booking_writer(vault, |txn| {
            verify_plan_in(vault, txn, &item.plan)?;
            if crate::booking::lifecycle::emergency_current_revision_in(
                vault,
                txn,
                item.calendar.event_ref,
            )? != picked.calendar
            {
                return Err(refused("picked delivery checkpoint is superseded"));
            }
            let mut current = read_item_in(
                vault,
                &*txn,
                &item_key(&item.plan.request, item.calendar.event_ref)?,
            )?
            .ok_or_else(|| refused("emergency checkpoint disappeared"))?;
            let saved = current
                .picked
                .as_mut()
                .ok_or_else(|| refused("pick checkpoint disappeared"))?;
            if saved.content_hash != picked.content_hash || current.plan != item.plan {
                return Err(refused("pick checkpoint content conflict"));
            }
            saved.calendar_delivered = true;
            write_item_in(vault, txn, &current)
        })?;
    }
    Ok(picked.calendar.clone())
}
