//! The EVENT follows its admitted passport head (FIX
//! PASSPORT-REVISION-REWRITES-EVENT-BEFORE-APPROVAL; ruling
//! PASSPORT-EVENT-REWRITE-INTENT = B, ARCH-0060 :88). Over an admitted head,
//! an import files a feed revision before anything else of its EVENT moves,
//! and a revision that waits for review moves nothing more
//! ([`PollAdmission::file_revision_over_admitted_head`]). The owner's
//! approving write moves the EVENT
//! ([`apply_admitted_passport_revision_in_txn`]), and a rejection leaves it
//! as the head set it.

use super::continuation::enqueue_property_continuation_in_txn;
use super::*;
use crate::calendar::claims::decode_passport_value;
use crate::calendar::ics::parse_ics_feed;
use crate::calendar::passport::admitted_passport_for_in_txn;
use crate::claim::{ClaimBody, ClaimSubject};

impl PollAdmission<'_> {
    /// Files an update verdict's passport revision first when an admitted
    /// passport heads its `(system × UID)`, before anything else of the
    /// EVENT moves (ARCH-0060 :88, ruling PASSPORT-EVENT-REWRITE-INTENT = B:
    /// a pending or rejected proposal never steers the EVENT). A revision
    /// that waits for review writes nothing else at import: the owner's
    /// approval moves the EVENT ([`apply_admitted_passport_revision_in_txn`])
    /// and a rejection leaves it as the head set it. One that landed admitted
    /// moves it now, after the passport, so a pass that fails in between
    /// leaves the EVENT as it was until the source's next revision.
    pub(super) fn file_revision_over_admitted_head(
        &mut self,
        event_ref: EntityId,
        event: &ParsedVEvent,
    ) -> Result<RevisionFiling, CalendarError> {
        let head = {
            let txn = self
                .vault
                .store
                .env
                .read_txn()
                .map_err(crate::Error::from)?;
            admitted_passport_for_in_txn(self.vault, &txn, &event_ref, self.system, &event.uid)?
        };
        if head.is_none() {
            return Ok(RevisionFiling::Owed);
        }
        let next = self.passport_value(event_ref, event, CalendarPassportPresence::Live)?;
        Ok(
            match self.admit_superseding_passport(event_ref, &next, &screen_body(event))? {
                PassportRevision::HeadStaged => RevisionFiling::Waits,
                PassportRevision::HeadClosed | PassportRevision::NoAdmittedHead => {
                    RevisionFiling::Filed
                }
            },
        )
    }

    /// An update's status half: an EVENT the source no longer cancels drops
    /// its absence cancellation, and an explicit cancellation is admitted.
    pub(super) fn apply_feed_status(
        &mut self,
        event_ref: EntityId,
        event: &ParsedVEvent,
    ) -> Result<(), CalendarError> {
        if !event.cancelled {
            self.clear_absence_cancellation(event_ref)?;
        }
        self.apply_imported_cancel(event_ref, event)
    }
}

/// How an update verdict files its passport revision
/// ([`PollAdmission::file_revision_over_admitted_head`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RevisionFiling {
    /// Filed over an admitted head and waiting for review: nothing else of
    /// the EVENT moves at import.
    Waits,
    /// Filed over an admitted head and landed admitted: the EVENT moves now.
    Filed,
    /// No admitted head carries the key, so no authority is kept: the EVENT
    /// moves first and the revision is filed last, so a pass that fails
    /// before it reads the update again.
    Owed,
}

/// Rewrites `event_ref` from the drifted `event` in `txn`: its name and
/// occurrence follow the VEVENT without erasing its origin or
/// extraction/import fields. Imported provenance follows `import_source`
/// (`blob#vN:uid`); a native EVENT with an attached passport remains native.
pub(super) fn rewrite_event_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    system: &str,
    import_source: String,
    event_ref: EntityId,
    event: &ParsedVEvent,
    now: u64,
) -> crate::Result<()> {
    let input = crate::calendar::origin::CalendarEventInput {
        origin: Some(CalendarOrigin::Imported),
        name: event_name(event).to_owned(),
        import_source: Some(import_source),
        external_id: Some(event.uid.clone()),
        ..Default::default()
    };
    // A pack calendar source's EVENT keeps its stamp through drift: its
    // landing marks it born again, rewrites it under its proof and binds it
    // where it was born.
    let landing = crate::mail_pack::calendar_source_landing_in(vault, txn, system)?;
    let birth = landing
        .as_ref()
        .map(|landing| landing.mark_in_txn(vault, txn, &event_ref))
        .transpose()?;
    vault.update_calendar_import_in_txn(
        txn,
        event_ref,
        &input,
        event_occurrence(event),
        now,
        birth,
    )?;
    match &landing {
        Some(landing) => landing.bind_in_txn(vault, txn, &event_ref),
        None => Ok(()),
    }
}

/// The EVENT's stored occurrence from the parsed times. An unanchored event
/// uses the existing undated sentinel, never the poll instant.
pub(super) fn event_occurrence(event: &ParsedVEvent) -> TimeRange {
    match (event.starts_at_utc, event.ends_at_utc) {
        (Some(start), Some(end)) => TimeRange {
            start,
            end: end.max(start),
        },
        (Some(start), None) => TimeRange { start, end: start },
        (None, _) => TimeRange { start: 0, end: 0 },
    }
}

/// Applies the approved passport revision `id` to its EVENT in `txn`, the
/// approving write that just made it the admitted head of its
/// `(system × UID)` (the deferred supersession's completion).
///
/// The revision's VEVENT is read again from the archived version it was
/// filed from: the passport's own source, else the version its evidence
/// cites. The EVENT's name and occurrence move here, as an import's rewrite
/// moves them, unless the master EVENT carries a live booking, which moved
/// through its booking at import. Its property claims and its status follow
/// through a queued property continuation in revision mode, under the
/// screen and gate an import crosses; an installed feed's consent settles
/// them as it settles a continuation's. An outbound-only or absent passport,
/// a version no longer stored and a VEVENT with other content move nothing:
/// the passport is the head all the same.
pub(crate) fn apply_admitted_passport_revision_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    body: &ClaimBody,
    now: u64,
) -> crate::Result<()> {
    if body.predicate != PREDICATE_CALENDAR_PASSPORT {
        return Ok(());
    }
    let ClaimSubject::Entity(event_ref) = body.subject else {
        return Ok(());
    };
    let passport = decode_passport_value(&body.value)?;
    if !passport.direction.is_inbound_bearing()
        || passport.presence != CalendarPassportPresence::Live
    {
        return Ok(());
    }
    let Some(cited) = cited_blob_ref(body, &passport.uid) else {
        return Ok(());
    };
    let source_version = passport
        .source
        .map_or_else(|| cited.to_owned(), CalendarPassportSource::blob_ref);
    let Some(bytes) = read_version_in_txn(vault, txn, &source_version)? else {
        tracing::warn!(
            claim = %id.to_hex(),
            "an approved passport revision's source version is gone; its EVENT stays as it was"
        );
        return Ok(());
    };
    let Ok(feed) = parse_ics_feed(&bytes) else {
        tracing::warn!(
            claim = %id.to_hex(),
            "an approved passport revision's source version does not parse; its EVENT stays as it was"
        );
        return Ok(());
    };
    let Some(event) = feed
        .events
        .iter()
        .find(|event| event.uid == passport.uid && event.content_hash == passport.content_hash)
    else {
        return Ok(());
    };
    if vault.get_entity_type_in_txn(txn, &event_ref)? != Some(ENTITY_TYPE_EVENT) {
        return Ok(());
    }
    // As the import moves it: a master EVENT with a live booking moved
    // through its booking, and a cancellation is never a booking move.
    let booking_moved = event.properties.recurrence_id_utc.is_none()
        && !event.cancelled
        && crate::booking::lifecycle::carries_live_booking_in(vault, txn, &event_ref).map_err(
            |error| crate::Error::Refused(format!("calendar booking read failed: {error}")),
        )?;
    if !booking_moved {
        rewrite_event_in_txn(
            vault,
            txn,
            &passport.system,
            format!("{cited}:{}", passport.uid),
            event_ref,
            event,
            now,
        )?;
    }
    let payload = IcsPropertyContinuationPayload {
        system: passport.system.clone(),
        blob_ref: cited.to_owned(),
        source_version,
        event_ref: event_ref.to_hex(),
        uid: passport.uid.clone(),
        recurrence_id_utc: event.properties.recurrence_id_utc,
        admitted_revision: true,
    };
    enqueue_property_continuation_in_txn(vault, txn, &payload, "admitted_revision", now)
}

/// The archived source a passport claim cites: its evidence's
/// `source_record_id` (`blob#vN:uid`) without the `:uid`.
fn cited_blob_ref<'a>(body: &'a ClaimBody, uid: &str) -> Option<&'a str> {
    let evidence = body.evidence.as_ref()?;
    map_field(
        evidence,
        crate::write_envelope::WRITE_ENVELOPE_EVIDENCE_CANDIDATE_KEY,
    )
    .and_then(|candidate| map_field(candidate, "source_record_id"))
    .and_then(rmpv::Value::as_str)
    .and_then(|record| record.strip_suffix(uid)?.strip_suffix(':'))
}

fn map_field<'a>(value: &'a rmpv::Value, name: &str) -> Option<&'a rmpv::Value> {
    value
        .as_map()?
        .iter()
        .find_map(|(key, value)| (key.as_str() == Some(name)).then_some(value))
}

/// The bytes of the archived version an `artifact#vN` reference names, read
/// in `txn`; `None` for any other shape or a version no longer stored.
fn read_version_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    blob_ref: &str,
) -> crate::Result<Option<Vec<u8>>> {
    let Some((hex, version)) = blob_ref.split_once("#v") else {
        return Ok(None);
    };
    let (Ok(artifact_id), Ok(version)) = (EntityId::from_hex(hex), version.parse::<u64>()) else {
        return Ok(None);
    };
    vault.read_blob_artifact_version_in_txn(txn, &artifact_id, version)
}
