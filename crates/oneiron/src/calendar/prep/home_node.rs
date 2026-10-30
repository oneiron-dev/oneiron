//! Closed-vault due execution of prep jobs.

use serde::{Deserialize, Serialize};

use super::lens::{PrepLensCopy, render_prep_lens};
use super::pack::{PrepBuildRequest, build_prep_pack};
use super::wake::{PrepEvent, PrepPolicy, PrepWake, prep_fire_at};
use crate::calendar::claims::{
    CalendarStatus, PREDICATE_CALENDAR_ATTENDEE, PREDICATE_CALENDAR_PREP_OPT_IN,
    PREDICATE_CALENDAR_STATUS, decode_attendee_value, decode_prep_opt_in_value,
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
///   that moved has a new wake with the same [`prep_wake_id`](crate::calendar::prep_wake_id); this one is
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

/// Re-derives the EVENT facts prep is decided from, as they stand at due time.
///
/// `None` means the EVENT is gone, is not an EVENT, is a shell, or has been
/// cancelled. Otherwise the facts are the vault's own, read live from the
/// EVENT's settled claims ([`live_event_facts`]): which attendees are outside
/// the owner's house, which attendee entities seed the pack, whether a
/// campaign or a commitment links the EVENT, and whether the EVENT's own
/// `calendar.prep_opt_in` opts it in; the vault-wide opt-in is
/// [`PrepPolicy::external_only`].
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
        attendee_refs: facts.attendee_refs,
        external_attendee_count: facts.external_attendee_count,
        has_campaign_linkage: facts.has_campaign_linkage,
        has_commitment_linkage: facts.has_commitment_linkage,
        internal_meeting_opt_in: facts.internal_meeting_opt_in,
    }))
}

/// The live calendar facts the due-time recheck reads.
#[derive(Default)]
struct LiveEventFacts {
    cancelled: bool,
    /// Live attendee entities other than the owner, the pack's extra seeds.
    attendee_refs: Vec<EntityId>,
    /// Attendees who are neither a vault owner nor one of the vault's own
    /// channel identities.
    external_attendee_count: u32,
    has_campaign_linkage: bool,
    has_commitment_linkage: bool,
    /// A settled `calendar.prep_opt_in` on the EVENT says `true`.
    internal_meeting_opt_in: bool,
}

/// Reads the live, surfaceable claims on one EVENT in one snapshot.
///
/// A cancellation is a restriction and counts held or not. Every other fact
/// counts only once its owner's critical confirm is settled — a gate-pending
/// row is not a fact a card may be built on. An attendee is inside the house
/// when it names a vault owner (the embedded owner included) or an address
/// one of the vault's own channel identities holds; every other attendee is
/// external. A campaign or commitment claim on the EVENT is its linkage, and
/// a `calendar.prep_opt_in` saying `true` is its opt-in.
fn live_event_facts(vault: &Vault, event_ref: &EntityId) -> Result<LiveEventFacts> {
    let rtxn = vault.store.env.read_txn()?;
    let mut owners = crate::policy_model::owners_in_txn(vault, &rtxn)?;
    owners.push(crate::vault::embedded_owner_actor_id()?);
    let mut facts = LiveEventFacts::default();
    for claim_id in vault.claims_for_subject_in_txn(&rtxn, event_ref)? {
        let Some(body) = vault
            .get_claim_in_txn(&rtxn, &claim_id)?
            .filter(claim_surfaceable)
        else {
            continue;
        };
        if body.predicate == PREDICATE_CALENDAR_STATUS {
            facts.cancelled |=
                decode_status_value(&body.value)?.status == CalendarStatus::Cancelled;
            continue;
        }
        if !crate::gate::claim_critical_confirm_settled_in_txn(&vault.store, &rtxn, &claim_id)? {
            continue;
        }
        if body.predicate == PREDICATE_CALENDAR_PREP_OPT_IN {
            facts.internal_meeting_opt_in |= decode_prep_opt_in_value(&body.value)?;
            continue;
        }
        if body.predicate == PREDICATE_CALENDAR_ATTENDEE {
            // Decoded, not just counted: a row that is not a well-formed
            // attendee line is a claim-body error, never a silent head count.
            let attendee = decode_attendee_value(&body.value)?;
            let entity = match EntityId::from_hex(&attendee.who) {
                Ok(entity) if live_entity_in_txn(vault, &rtxn, &entity)? => Some(entity),
                _ => None,
            };
            let internal = match entity {
                Some(entity) => owners.contains(&entity),
                None => own_address_in_txn(vault, &rtxn, &attendee.who)?,
            };
            if !internal {
                facts.external_attendee_count = facts.external_attendee_count.saturating_add(1);
                if let Some(entity) = entity
                    && !facts.attendee_refs.contains(&entity)
                {
                    facts.attendee_refs.push(entity);
                }
            }
        }
        facts.has_campaign_linkage |= body.predicate.starts_with("campaign.");
        facts.has_commitment_linkage |= body.predicate.starts_with("commitment.");
    }
    Ok(facts)
}

/// Whether `entity` is a live row: present and no deletion tombstone.
fn live_entity_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>, entity: &EntityId) -> Result<bool> {
    use crate::ports::TombstoneStore;
    Ok(vault.get_entity_type_in_txn(txn, entity)?.is_some()
        && !vault.port_tombstone_is_deleted(txn, entity)?)
}

/// Whether an attendee address is one of the vault's own channel identities:
/// a `mailto:` address, or a bare one, its email assignment held here.
fn own_address_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>, who: &str) -> Result<bool> {
    let who = who.trim();
    let address = match who.get(..7) {
        Some(scheme) if scheme.eq_ignore_ascii_case("mailto:") => &who[7..],
        _ => who,
    };
    if !address.contains('@') {
        return Ok(false);
    }
    Ok(vault
        .channel_identity_by_assignment_in_txn(
            txn,
            crate::channel_identity_provider::EMAIL_CHANNEL,
            address,
        )?
        .is_some())
}
