//! Closed-vault due execution of prep jobs.

use serde::{Deserialize, Serialize};

use super::lens::{PrepLensCopy, render_prep_lens};
use super::pack::{PrepBuildRequest, build_prep_pack};
use super::wake::{PrepEvent, PrepPolicy, PrepWake, prep_fire_at};
use crate::calendar::claims::{
    CalendarStatus, PREDICATE_CALENDAR_ATTENDEE, PREDICATE_CALENDAR_STATUS, decode_attendee_value,
    decode_status_value,
};
use crate::claim::claim_surfaceable;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::lens::GeneratedLens;
use crate::registry::ENTITY_TYPE_EVENT;
use crate::vault::Vault;

/// The closed-vault due payload: small, deterministic, and self-describing.
///
/// Three scalars and nothing else. The raw context stays in the vault and is
/// re-read at execution time, so this payload can sit in a host queue across a
/// vault close without ever becoming stale prose.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrepHomeNodeJob {
    /// Hex id of the EVENT the pack is about.
    pub event_ref: String,
    /// The exact instant the wake was planned for, unix seconds UTC.
    pub scheduled_for: u64,
    /// The wake id the host will report as due.
    pub wake_id: String,
}

impl PrepHomeNodeJob {
    /// Binds one planned wake to the EVENT it was planned for.
    ///
    /// Deterministic: the same EVENT and the same wake always produce the same
    /// payload, so a host that enqueues twice enqueues the same bytes.
    #[must_use]
    pub fn from_wake(event_ref: &EntityId, wake: &PrepWake) -> Self {
        Self {
            event_ref: event_ref.to_hex(),
            scheduled_for: wake.at_utc,
            wake_id: wake.id.clone(),
        }
    }
}

/// Runs one due prep job on the elected home node.
///
/// The host calls this AFTER proving it holds the home-node election. This
/// module owns no part of that proof: it reads no lease, writes no lease, and
/// exposes no second door a due payload could enter through.
///
/// A due wake is not a card. Everything the payload asserts is re-derived from
/// the vault before anything is rendered:
///
/// * the EVENT must still exist, still be an EVENT, and not be a deleted or
///   redirect shell;
/// * it must not have been cancelled — CAL-00's `calendar.status` is the home
///   that law lives in, and a prep pack for a called-off meeting is noise;
/// * it must still be eligible, from live `calendar.attendee` rows;
/// * its T-45 must still be the instant the payload was planned for. An EVENT
///   that moved has a new wake with the same [`prep_wake_id`]; this one is
///   stale and answers `None` rather than rendering against an old time.
///
/// `Ok(None)` therefore covers both "stale" and "now empty", and in both cases
/// the caller emits no lens.
///
/// # Errors
///
/// [`crate::error::Error::InvalidKey`] when `event_ref` is not a hex entity id;
/// storage, claim-body, retrieval, and lens errors propagate unchanged.
pub fn run_due_home_node_prep(
    vault: &Vault,
    job: &PrepHomeNodeJob,
    fired_at: u64,
    policy: PrepPolicy,
    copy: &PrepLensCopy,
) -> Result<Option<GeneratedLens>> {
    let event_ref = EntityId::from_hex(&job.event_ref)?;
    let Some(event) = live_prep_event(vault, event_ref)? else {
        return Ok(None);
    };
    if prep_fire_at(&event, policy) != Some(job.scheduled_for) {
        return Ok(None);
    }
    let request = PrepBuildRequest {
        event,
        fired_at,
        policy,
    };
    let Some(pack) = build_prep_pack(vault, &request)? else {
        return Ok(None);
    };
    render_prep_lens(&pack, copy).map(Some)
}

/// Re-derives the EVENT facts this layer can read for itself at due time.
///
/// `None` means the EVENT is gone, is not an EVENT, is a shell, or has been
/// cancelled. What comes back is deliberately narrower than what a host can
/// supply: the engine models attendees as vendor strings and owns no identity
/// domain, so every live `calendar.attendee` row counts once and campaign,
/// commitment, and opt-in signals stay false. That makes the due-time recheck a
/// NARROWING one — it can retire a job the host already armed, never arm one the
/// host did not. A host with an identity model gets a sharper answer by calling
/// [`build_prep_pack`] with its own [`PrepEvent`].
fn live_prep_event(vault: &Vault, event_ref: EntityId) -> Result<Option<PrepEvent>> {
    let Some(header) = vault.read_entity_header(&event_ref)? else {
        return Ok(None);
    };
    if header.entity_type != ENTITY_TYPE_EVENT || vault.is_deleted_shell(&event_ref)? {
        return Ok(None);
    }
    let facts = live_event_facts(vault, &event_ref)?;
    if facts.cancelled {
        return Ok(None);
    }
    let (start_utc, end_utc) = if header.occurred_start <= header.occurred_end {
        (header.occurred_start, header.occurred_end)
    } else {
        (header.occurred_end, header.occurred_start)
    };
    Ok(Some(PrepEvent {
        event_ref,
        start_utc,
        end_utc,
        attendee_refs: Vec::new(),
        external_attendee_count: facts.attendee_count,
        has_campaign_linkage: false,
        has_commitment_linkage: false,
        internal_meeting_opt_in: false,
    }))
}

/// The two live calendar facts the due-time recheck reads.
struct LiveEventFacts {
    cancelled: bool,
    attendee_count: u32,
}

/// Reads live `calendar.attendee` and `calendar.status` heads on one EVENT.
///
/// Surfaceable heads only, through the ordinary claim door — a gate-pending row
/// is not a fact a card may be built on. Both predicates belong to CAL-00; this
/// layer reads them and writes neither.
fn live_event_facts(vault: &Vault, event_ref: &EntityId) -> Result<LiveEventFacts> {
    let rtxn = vault.store.env.read_txn()?;
    let mut cancelled = false;
    let mut attendee_count = 0_u32;
    for claim_id in vault.claims_for_subject_in_txn(&rtxn, event_ref)? {
        let Some(body) = vault
            .get_claim_in_txn(&rtxn, &claim_id)?
            .filter(claim_surfaceable)
        else {
            continue;
        };
        if body.predicate == PREDICATE_CALENDAR_ATTENDEE {
            // Decoded, not just counted: a row that is not a well-formed
            // attendee line is a claim-body error, never a silent head count.
            decode_attendee_value(&body.value)?;
            attendee_count = attendee_count.saturating_add(1);
        } else if body.predicate == PREDICATE_CALENDAR_STATUS
            && decode_status_value(&body.value)?.status == CalendarStatus::Cancelled
        {
            cancelled = true;
        }
    }
    Ok(LiveEventFacts {
        cancelled,
        attendee_count,
    })
}
