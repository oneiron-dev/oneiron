//! A remote resource gone: a provider tombstone or a full listing's
//! omission, applied to the one source's passports it concerns.

use super::super::seat::{CalendarConnectorError, CalendarConnectorSeatState};
use super::{SyncCounters, pull_source_record_id};

use crate::calendar::claims::CalendarPassportPresence;
use crate::calendar::ingest::{ConnectorAdmissionSource, ConnectorScreen};
use crate::entity_id::EntityId;
use crate::vault::Vault;

/// What says a remote resource is gone.
#[derive(Clone, Copy)]
pub(super) enum RemovalEvidence {
    /// The provider's own tombstone: an explicit cancellation.
    Tombstone,
    /// A full listing that no longer carries it (fix list row 19192): an
    /// absence, as an omitted feed item is.
    Omission {
        /// Whether it settles a removal report a pull held back
        /// ([`apply_remote_deletion`]): false while a replayed write of the
        /// UID, on any seat of the calendar, read no stored copy.
        settles_held_cancel: bool,
    },
}

/// A remote deletion marks exactly one source's passport absent, once.
///
/// Multi-source law, verbatim: feed-absence cancellation applies ONLY when every
/// live inbound passport for the EVENT reports absence; a single-source absence
/// supersedes only that passport, never the EVENT status. The EVENT is never
/// deleted, CAL-07's outcome predicate is never written, and no delete is bounced
/// back to any provider.
#[expect(
    clippy::too_many_arguments,
    reason = "a removal's evidence and its pull's screen meet the one passport sweep"
)]
pub(super) fn apply_remote_deletion(
    vault: &Vault,
    seat: &CalendarConnectorSeatState,
    provider: &'static str,
    uid: &str,
    evidence: RemovalEvidence,
    screen: ConnectorScreen<'_>,
    now: u64,
    counters: &mut SyncCounters,
) -> Result<(), CalendarConnectorError> {
    let mut absent_count = 0;
    let mut newly_absent = Vec::new();
    let mut held_cancel = false;
    let mut after = None;
    loop {
        let ids = vault.entities_by_type_page(
            crate::registry::ENTITY_TYPE_EVENT,
            after.as_ref(),
            4096,
        )?;
        if ids.is_empty() {
            break;
        }
        for event in &ids {
            let Some((_, value)) = crate::calendar::passport::live_passport_for(
                vault,
                event,
                &seat.config.system,
                uid,
            )?
            else {
                continue;
            };
            held_cancel |= value.deferred_cancel_seen_at.is_some();
            if value.presence == CalendarPassportPresence::Live
                && value.direction.is_inbound_bearing()
            {
                absent_count += 1;
                newly_absent.push((*event, imported_cancellation(vault, *event)?));
            }
        }
        after = ids.last().copied();
    }
    let record = pull_source_record_id(provider, seat, uid);
    let source = ConnectorAdmissionSource {
        record: &record,
        source_version: None,
        screen,
        source: None,
    };
    // A full listing can only leave a gone resource out, never send its
    // tombstone again. So an omission of a resource whose removal a pull of
    // the calendar held back as `deferred_cancel_seen_at` (a cancelled write
    // of the UID was in flight, or the report alone would have concluded the
    // cancel of an EVENT no inbound source carries) settles that report as
    // the tombstone it was, dated by its first sighting: no write is in
    // flight on any seat any more (an omission waits on one), a write that
    // settled dropped the sighting, a copy the listing still carries took the
    // report back, and a refusal that stored nothing, or whose read proved
    // the stored copy another writer's, leaves the host's report. A replay
    // whose read proved nothing leaves it held, since the gone copy may be
    // the engine's own cancelled write
    // (CAL-SEAT-DELETE-OF-WRITTEN-ONLY-EVENT-CANCELS-NOTHING).
    let evidence = match evidence {
        RemovalEvidence::Omission {
            settles_held_cancel: true,
        } if held_cancel => RemovalEvidence::Tombstone,
        evidence => evidence,
    };
    match evidence {
        RemovalEvidence::Tombstone => crate::calendar::ingest::delete_connector_resource(
            vault,
            &seat.config.system,
            source,
            uid,
            now,
        )?,
        RemovalEvidence::Omission { .. } => crate::calendar::ingest::sweep_connector_uids(
            vault,
            &seat.config.system,
            source,
            &std::collections::BTreeSet::from([uid]),
            now,
        )?,
    }
    counters.source_absences += absent_count;
    for (event, was_cancelled) in newly_absent {
        if !was_cancelled && imported_cancellation(vault, event)? {
            counters.status_cancellations += 1;
        }
    }
    Ok(())
}

fn imported_cancellation(vault: &Vault, event: EntityId) -> Result<bool, CalendarConnectorError> {
    use crate::calendar::claims::{
        CalendarStatus, CalendarStatusBasis, PREDICATE_CALENDAR_STATUS, decode_status_value,
    };
    for id in vault.claims_for_subject(&event)? {
        if let Some(body) = vault.get_claim(&id)?
            && body.lifecycle == crate::ClaimLifecycleStatus::Active
            && body.predicate == PREDICATE_CALENDAR_STATUS
        {
            let status = decode_status_value(&body.value)?;
            if status.status == CalendarStatus::Cancelled
                && matches!(
                    status.basis,
                    CalendarStatusBasis::ImportedAbsence | CalendarStatusBasis::ImportedCancel
                )
            {
                return Ok(true);
            }
        }
    }
    Ok(false)
}
