//! Diff-to-claim admission path and its test module.

use super::poll::IcsFeedPollConfig;
use super::{derive_entity_id, ingest};
use crate::calendar::CalendarError;
use crate::calendar::claims::{
    CalendarOrigin, CalendarPassportDirection, CalendarPassportPresence, CalendarPassportValue,
    CalendarStatus, CalendarStatusBasis, CalendarTimeKind, PREDICATE_CALENDAR_ORIGIN,
    PREDICATE_CALENDAR_PASSPORT, PREDICATE_CALENDAR_STATUS, PREDICATE_CALENDAR_TIME_KIND,
    decode_status_value, decode_time_kind_value,
};
use crate::calendar::ics::ParsedVEvent;
use crate::calendar::passport::{
    PassportDecision, all_live_inbound_passports_absent, classify_passport, index_passport_uid,
    live_passports_for_event, supersede_calendar_passport,
};
use crate::calendar::safeguard::{CalendarBodyScreener, CalendarInboundBody, screen_then_claim};
use crate::claim::ClaimLifecycleStatus;
use crate::entity_id::EntityId;
use crate::ingest::{
    ICS_FEED_SOURCE_ID, ImportedEvidenceAdmission, ImportedEvidenceEntityResolution,
};
use crate::registry::{ENTITY_TYPE_EVENT, ENTITY_TYPE_MACHINE};
use crate::temporal::TimeRange;
use crate::vault::Vault;
use crate::write_envelope::WriteActor;

#[cfg(test)]
use super::fetch::{IcsFeedFetcher, IcsFetchResponse};
#[cfg(test)]
use super::poll::run_ics_feed_poll;

/// Id-derivation domain for the adapter's import actor MACHINE entity.
const ICS_IMPORT_ACTOR_ID_DOMAIN: &[u8] = b"oneiron:calendar-ics-import-actor:v1";

/// Per-poll admission context: everything the claim-writing steps share.
pub(super) struct PollAdmission<'a> {
    pub(crate) vault: &'a Vault,
    pub(crate) screener: Option<&'a dyn CalendarBodyScreener>,
    pub(crate) safeguard_enabled: bool,
    pub(crate) config: &'a IcsFeedPollConfig,
    pub(crate) now: u64,
    pub(crate) blob_ref: &'a str,
    pub(crate) verdict_fold: VerdictFold,
}

impl PollAdmission<'_> {
    /// Applies one completely parsed feed: per-VEVENT diff + admission.
    pub(super) fn apply_feed(
        &mut self,
        feed: &super::ics::ParsedIcsFeed,
    ) -> Result<(), CalendarError> {
        for event in &feed.events {
            self.apply_event(event)?;
        }
        Ok(())
    }

    fn apply_event(&mut self, event: &ParsedVEvent) -> Result<(), CalendarError> {
        let decision = classify_passport(
            self.vault,
            &self.config.system,
            &event.uid,
            event.sequence,
            event.content_hash,
        )?;
        match decision {
            PassportDecision::CreateEvent => {
                let event_ref = self.mint_event(event)?;
                index_passport_uid(self.vault, &event.uid, &event_ref)?;
                self.admit_origin(event_ref, event)?;
                self.admit_time_kind(event_ref, event)?;
                self.admit_fresh_passport(event_ref, event)?;
                self.apply_imported_cancel(event_ref, event)?;
            }
            PassportDecision::AttachToExisting { event_ref } => {
                self.admit_fresh_passport(event_ref, event)?;
                self.apply_imported_cancel(event_ref, event)?;
            }
            PassportDecision::SkipUnchanged { .. } => {}
            PassportDecision::UpdateExisting { event_ref } => {
                // The update verdict moves the EVENT, not just the passport
                // head: occurred and name follow the drifted VEVENT, and
                // `calendar.time` re-mints when its value moved.
                self.rewrite_event(event_ref, event)?;
                self.admit_time_kind(event_ref, event)?;
                let next = self.passport_value(event, CalendarPassportPresence::Live);
                let body = screen_body(event);
                self.admit_superseding_passport(event_ref, &next, &body)?;
                self.apply_imported_cancel(event_ref, event)?;
            }
            PassportDecision::MarkSourceAbsent { .. } => {
                // Constructed only by the absence sweep, never by per-event
                // classification.
            }
        }
        Ok(())
    }

    /// The absence half of the diff: every live inbound passport this system
    /// reported before, whose UID a COMPLETE feed just omitted, flips to
    /// absent — only that passport, never the EVENT. Cancellation derives
    /// afterwards, and only when every live inbound passport reports absence.
    pub(super) fn sweep_absent_sources(
        &mut self,
        feed: &super::ics::ParsedIcsFeed,
    ) -> Result<(), CalendarError> {
        let present_uids: std::collections::BTreeSet<&str> =
            feed.events.iter().map(|event| event.uid.as_str()).collect();
        for event_ref in list_event_ids(self.vault)? {
            let passports = live_passports_for_event(self.vault, &event_ref)?;
            if !passports
                .iter()
                .any(|(_, value)| value.system == self.config.system)
            {
                continue;
            }
            for (_, value) in &passports {
                let reports = value.system == self.config.system
                    && value.direction.is_inbound_bearing()
                    && value.presence == CalendarPassportPresence::Live
                    && !present_uids.contains(value.uid.as_str());
                if !reports {
                    continue;
                }
                let mut absent = value.clone();
                absent.presence = CalendarPassportPresence::Absent;
                absent.last_seen_at = self.now;
                // Absence carries no inbound content, so the screen body is
                // empty — but the admission still crosses the hook and cites
                // the complete feed that proved the omission.
                self.admit_superseding_passport(
                    event_ref,
                    &absent,
                    &CalendarInboundBody::default(),
                )?;
            }
            if all_live_inbound_passports_absent(self.vault, &event_ref)? {
                self.admit_absence_cancellation(event_ref)?;
            }
        }
        Ok(())
    }

    /// Mints the EVENT entity: structural write only, occurred from the
    /// parsed times, `name` from SUMMARY with a UID fallback.
    fn mint_event(&self, event: &ParsedVEvent) -> Result<EntityId, CalendarError> {
        let event_ref = EntityId::now();
        let occurred = self.event_occurred(event);
        let body = encode_event_body(event_name(event))?;
        self.vault
            .put_entity(&event_ref, ENTITY_TYPE_EVENT, occurred, self.now, &body)?;
        Ok(event_ref)
    }

    /// Re-mints the EVENT's structural row from a drifted VEVENT: the id is
    /// stable, occurred and `name` follow the new head. Without this the
    /// update verdict would move only the passport while the event kept
    /// stale content — the drift detector's whole point.
    fn rewrite_event(
        &self,
        event_ref: EntityId,
        event: &ParsedVEvent,
    ) -> Result<(), CalendarError> {
        let occurred = self.event_occurred(event);
        let body = encode_event_body(event_name(event))?;
        self.vault
            .put_entity(&event_ref, ENTITY_TYPE_EVENT, occurred, self.now, &body)?;
        Ok(())
    }

    /// The EVENT's stored occurrence from the parsed times: `now` when the
    /// feed expressed no convertible time.
    fn event_occurred(&self, event: &ParsedVEvent) -> TimeRange {
        match (event.starts_at_utc, event.ends_at_utc) {
            (Some(start), Some(end)) => TimeRange {
                start,
                end: end.max(start),
            },
            (Some(start), None) => TimeRange { start, end: start },
            (None, _) => TimeRange {
                start: self.now,
                end: self.now,
            },
        }
    }

    fn admit_origin(
        &mut self,
        event_ref: EntityId,
        event: &ParsedVEvent,
    ) -> Result<(), CalendarError> {
        let body = screen_body(event);
        let source_record_id = self.source_record_id(event);
        self.admit_screened(
            event_ref,
            &body,
            &source_record_id,
            PREDICATE_CALENDAR_ORIGIN,
            rmpv::Value::from(CalendarOrigin::Imported.as_str()),
        )?;
        Ok(())
    }

    /// Admits the event's `calendar.time` kind claim, superseding the prior
    /// live claim when the value moved and skipping when the live claim
    /// already carries the exact value — the same one-live-claim discipline
    /// as [`Self::admit_status_if_changed`].
    fn admit_time_kind(
        &mut self,
        event_ref: EntityId,
        event: &ParsedVEvent,
    ) -> Result<(), CalendarError> {
        let mut prior_live: Option<EntityId> = None;
        for claim_id in self.vault.claims_for_subject(&event_ref)? {
            let Some(claim) = self.vault.get_claim(&claim_id)? else {
                continue;
            };
            if claim.predicate != PREDICATE_CALENDAR_TIME_KIND
                || claim.lifecycle != ClaimLifecycleStatus::Active
            {
                continue;
            }
            let current = decode_time_kind_value(&claim.value)
                .map_err(|_| ingest("stored time claim did not decode"))?;
            if current.kind == CalendarTimeKind::Absolute
                && current.busy_transparency == event.busy_transparency
            {
                return Ok(());
            }
            prior_live = Some(claim_id);
        }
        let value = rmpv::Value::Map(vec![
            (
                rmpv::Value::from("kind"),
                rmpv::Value::from(CalendarTimeKind::Absolute.as_str()),
            ),
            (
                rmpv::Value::from("busy_transparency"),
                rmpv::Value::from(event.busy_transparency.as_str()),
            ),
        ]);
        let body = screen_body(event);
        let source_record_id = self.source_record_id(event);
        let new_id = self.admit_screened(
            event_ref,
            &body,
            &source_record_id,
            PREDICATE_CALENDAR_TIME_KIND,
            value,
        )?;
        if let Some(old_id) = prior_live {
            self.vault.supersede_claim(&new_id, &old_id, self.now)?;
        }
        Ok(())
    }

    /// Screens and admits the next passport head for `(system × UID)` —
    /// through the same hook + Gate door a fresh admission crosses — then
    /// supersedes exactly the scoped live claim. Supersessions carry the
    /// archived complete feed's provenance (`blob#vN:uid`), never a bare UID.
    fn admit_superseding_passport(
        &mut self,
        event_ref: EntityId,
        next: &CalendarPassportValue,
        body: &CalendarInboundBody,
    ) -> Result<(), CalendarError> {
        let source_record_id = format!("{}:{}", self.blob_ref, next.uid);
        let new_id = self.admit_screened(
            event_ref,
            body,
            &source_record_id,
            PREDICATE_CALENDAR_PASSPORT,
            super::passport::encode_passport_value(next),
        )?;
        supersede_calendar_passport(
            self.vault,
            event_ref,
            &next.system,
            &next.uid,
            &new_id,
            self.now,
        )
    }

    fn admit_fresh_passport(
        &mut self,
        event_ref: EntityId,
        event: &ParsedVEvent,
    ) -> Result<(), CalendarError> {
        let value = self.passport_value(event, CalendarPassportPresence::Live);
        let body = screen_body(event);
        let source_record_id = self.source_record_id(event);
        self.admit_screened(
            event_ref,
            &body,
            &source_record_id,
            PREDICATE_CALENDAR_PASSPORT,
            super::passport::encode_passport_value(&value),
        )?;
        Ok(())
    }

    /// Explicit `STATUS:CANCELLED` in the feed: write `calendar.status`
    /// cancelled with basis `imported_cancel`, unless a live claim already
    /// says exactly that. Never writes `confirmed` — resurrection is not a
    /// v1 basis.
    fn apply_imported_cancel(
        &mut self,
        event_ref: EntityId,
        event: &ParsedVEvent,
    ) -> Result<(), CalendarError> {
        if !event.cancelled {
            return Ok(());
        }
        let body = screen_body(event);
        let source_record_id = self.source_record_id(event);
        self.admit_status_if_changed(
            event_ref,
            &body,
            &source_record_id,
            CalendarStatus::Cancelled,
            CalendarStatusBasis::ImportedCancel,
        )
    }

    /// The multi-source law's conclusion: every live inbound passport
    /// reports absence, so the EVENT reads cancelled with basis
    /// `imported_absence`. The EVENT row is never deleted and CAL-07's
    /// outcome predicate is never written here. The screen body is empty:
    /// absence carries no inbound content to screen.
    fn admit_absence_cancellation(&mut self, event_ref: EntityId) -> Result<(), CalendarError> {
        self.admit_status_if_changed(
            event_ref,
            &CalendarInboundBody::default(),
            "feed-absence",
            CalendarStatus::Cancelled,
            CalendarStatusBasis::ImportedAbsence,
        )
    }

    /// Admits one `calendar.status` claim, superseding the prior live status
    /// claim, and skips when the live claim already carries the exact value.
    fn admit_status_if_changed(
        &mut self,
        event_ref: EntityId,
        body: &CalendarInboundBody,
        source_record_id: &str,
        status: CalendarStatus,
        basis: CalendarStatusBasis,
    ) -> Result<(), CalendarError> {
        let mut prior_live: Option<EntityId> = None;
        for claim_id in self.vault.claims_for_subject(&event_ref)? {
            let Some(claim) = self.vault.get_claim(&claim_id)? else {
                continue;
            };
            if claim.predicate != PREDICATE_CALENDAR_STATUS
                || claim.lifecycle != ClaimLifecycleStatus::Active
            {
                continue;
            }
            let current = decode_status_value(&claim.value)
                .map_err(|_| ingest("stored status claim did not decode"))?;
            if current.status == status && current.basis == basis {
                return Ok(());
            }
            prior_live = Some(claim_id);
        }
        let value = rmpv::Value::Map(vec![
            (
                rmpv::Value::from("status"),
                rmpv::Value::from(status.as_str()),
            ),
            (
                rmpv::Value::from("basis"),
                rmpv::Value::from(basis.as_str()),
            ),
            (
                rmpv::Value::from("recorded_at"),
                rmpv::Value::from(self.now),
            ),
        ]);
        let new_id = self.admit_screened(
            event_ref,
            body,
            source_record_id,
            PREDICATE_CALENDAR_STATUS,
            value,
        )?;
        if let Some(old_id) = prior_live {
            self.vault.supersede_claim(&new_id, &old_id, self.now)?;
        }
        Ok(())
    }

    /// The one admission door: CAL-09's hook runs immediately before the
    /// imported-evidence admission, and the admission executes from the
    /// typed `CalendarAdmissionRequest` — never from a zero-argument closure
    /// that could not see the verdict. The verdict is folded into the feed
    /// cursor as the run's admission-metadata witness.
    fn admit_screened(
        &mut self,
        event_ref: EntityId,
        body: &CalendarInboundBody,
        source_record_id: &str,
        predicate: &str,
        value: rmpv::Value,
    ) -> Result<EntityId, CalendarError> {
        let screened = screen_then_claim(self.safeguard_enabled, self.screener, body, |request| {
            let token = verdict_token(&request.verdict);
            let admitted = admit_calendar_import_claim(
                self.vault,
                &event_ref,
                predicate,
                value,
                source_record_id,
                self.now,
            );
            Ok((admitted, token))
        })?;
        let (admitted, token) = screened.value;
        self.verdict_fold.record(token);
        Ok(admitted?)
    }

    fn passport_value(
        &self,
        event: &ParsedVEvent,
        presence: CalendarPassportPresence,
    ) -> CalendarPassportValue {
        CalendarPassportValue {
            system: self.config.system.clone(),
            uid: event.uid.clone(),
            last_sequence: event.sequence,
            content_hash: event.content_hash,
            direction: CalendarPassportDirection::Inbound,
            last_seen_at: self.now,
            presence,
        }
    }

    /// The provenance ref admitted claims carry: the archived feed version
    /// plus the event's UID, so every semantic candidate points back at the
    /// raw bytes it was parsed from.
    fn source_record_id(&self, event: &ParsedVEvent) -> String {
        format!("{}:{}", self.blob_ref, event.uid)
    }
}

/// The CAL-09 screen body for one VEVENT: its description plus any ATTACH
/// values as attachment text, exactly as the source expressed them.
fn screen_body(event: &ParsedVEvent) -> CalendarInboundBody {
    CalendarInboundBody {
        description: event.description.clone().unwrap_or_default(),
        attachment_text: Vec::new(),
    }
}

/// The EVENT's display name: SUMMARY, with a UID fallback.
fn event_name(event: &ParsedVEvent) -> &str {
    event
        .summary
        .as_deref()
        .filter(|summary| !summary.is_empty())
        .unwrap_or(event.uid.as_str())
}

/// The EVENT body row: a MessagePack map carrying only the name.
fn encode_event_body(name: &str) -> Result<Vec<u8>, CalendarError> {
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &rmpv::Value::Map(vec![(rmpv::Value::from("name"), rmpv::Value::from(name))]),
    )
    .map_err(|_| ingest("event body did not encode"))?;
    Ok(body)
}

/// Admits one typed-value claim through the Gate-backed imported-evidence
/// door and returns the new claim id. The write actor is the adapter's own
/// MACHINE entity, ensured on first use.
pub(in crate::calendar) fn admit_calendar_import_claim(
    vault: &Vault,
    event_ref: &EntityId,
    predicate: &str,
    value: rmpv::Value,
    source_record_id: &str,
    recorded_at: u64,
) -> crate::Result<EntityId> {
    let actor = ensure_ics_import_actor(vault, recorded_at)?;
    let claim_id = EntityId::now();
    let admission = ImportedEvidenceAdmission::proposed(
        ICS_FEED_SOURCE_ID,
        claim_id,
        ImportedEvidenceEntityResolution::subject(*event_ref),
        WriteActor::new(actor, crate::edge::EdgeActorClass::System),
        TimeRange {
            start: recorded_at,
            end: recorded_at,
        },
        recorded_at,
    );
    crate::ingest::admit_imported_evidence_claim_typed(
        vault,
        predicate,
        value,
        source_record_id,
        &admission,
    )?;
    Ok(claim_id)
}

/// The adapter's write actor: one deterministic MACHINE entity, minted on
/// first use. Imported claims attribute to it as `EdgeActorClass::System`.
pub fn ics_import_actor_id() -> crate::Result<EntityId> {
    derive_entity_id(ICS_IMPORT_ACTOR_ID_DOMAIN, &[])
}

pub(super) fn ensure_ics_import_actor(vault: &Vault, now: u64) -> crate::Result<EntityId> {
    let id = ics_import_actor_id()?;
    if vault.get_entity_type(&id)? != Some(ENTITY_TYPE_MACHINE) {
        let mut body = Vec::new();
        rmpv::encode::write_value(
            &mut body,
            &rmpv::Value::Map(vec![(
                rmpv::Value::from("name"),
                rmpv::Value::from("calendar ICS feed importer"),
            )]),
        )
        .map_err(|_| crate::Error::InvariantViolation("actor body did not encode"))?;
        vault.put_entity(
            &id,
            ENTITY_TYPE_MACHINE,
            TimeRange {
                start: now,
                end: now,
            },
            now,
            &body,
        )?;
    }
    Ok(id)
}

fn list_event_ids(vault: &Vault) -> Result<Vec<EntityId>, CalendarError> {
    let rtxn = vault.store.env.read_txn().map_err(crate::Error::from)?;
    let mut ids = Vec::new();
    for entry in vault
        .store
        .type_index
        .prefix_iter(&rtxn, &[ENTITY_TYPE_EVENT])?
    {
        let (key, _) = entry?;
        ids.push(crate::vault::entity_id_from_type_index_key(&key)?);
    }
    Ok(ids)
}

/// Compact fold of the run's screen verdicts, persisted on the cursor as the
/// admission-metadata witness: the worst verdict class seen this run.
#[derive(Default)]
pub(super) struct VerdictFold {
    token: Option<&'static str>,
}

impl VerdictFold {
    pub(crate) fn record(&mut self, token: &'static str) {
        let rank = |token: &str| match token {
            "flagged" => 3,
            "indeterminate" => 2,
            "clear" => 1,
            _ => 0,
        };
        if self.token.is_none_or(|current| rank(token) > rank(current)) {
            self.token = Some(token);
        }
    }

    pub(crate) fn token(&self) -> &'static str {
        self.token.unwrap_or("skipped")
    }
}

fn verdict_token(verdict: &super::safeguard::CalendarScreenVerdict) -> &'static str {
    match verdict {
        super::safeguard::CalendarScreenVerdict::Skipped => "skipped",
        super::safeguard::CalendarScreenVerdict::Clear => "clear",
        super::safeguard::CalendarScreenVerdict::Flagged { .. } => "flagged",
        super::safeguard::CalendarScreenVerdict::Indeterminate { .. } => "indeterminate",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::calendar::test_support::open_calendar_vault;

    /// A one-body fetcher: every fetch returns a complete feed.
    struct BodyFetcher {
        body: Vec<u8>,
    }

    impl IcsFeedFetcher for BodyFetcher {
        fn fetch(
            &self,
            _secret_ref: &str,
            _if_none_match: Option<&str>,
        ) -> Result<IcsFetchResponse, CalendarError> {
            Ok(IcsFetchResponse::Complete {
                etag: None,
                body: self.body.clone(),
            })
        }
    }

    fn one_event_feed(dtstart: &str, dtend: &str) -> Vec<u8> {
        format!(
            "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//oneiron//test//EN\r\n\
             BEGIN:VEVENT\r\nUID:uid-oc@x\r\nDTSTAMP:20260805T100000Z\r\n\
             DTSTART:{dtstart}\r\nDTEND:{dtend}\r\nSEQUENCE:1\r\nSUMMARY:standup\r\n\
             END:VEVENT\r\nEND:VCALENDAR\r\n"
        )
        .into_bytes()
    }

    fn test_config() -> IcsFeedPollConfig {
        IcsFeedPollConfig {
            secret_ref: "ics-feed:work".to_owned(),
            system: "work".to_owned(),
            cadence_min_seconds: 300,
            cadence_max_seconds: 900,
        }
    }

    /// VERDICT-FIX (semantic-update-not-applied): a same-SEQUENCE content
    /// drift moves the EVENT's stored occurrence, not just the passport head.
    /// The header read is crate-internal, so this half of the oracle lives
    /// here; the name/transparency half lives in the adapter oracle.
    #[test]
    fn update_existing_rewrites_the_event_occurrence() {
        let (_dir, vault) = open_calendar_vault();
        let config = test_config();
        let first = BodyFetcher {
            body: one_event_feed("20260806T140000Z", "20260806T150000Z"),
        };
        run_ics_feed_poll(&vault, &first, &config, 1_800_000_000, 7).expect("create poll");
        let event = crate::calendar::passport::resolve_event_by_uid(&vault, "uid-oc@x")
            .expect("resolve")
            .expect("event minted");
        let before = vault
            .read_entity_header(&event)
            .expect("header")
            .expect("event exists");
        assert_eq!(before.occurred_start, 1_786_024_800);
        assert_eq!(before.occurred_end, 1_786_028_400);

        let drifted = BodyFetcher {
            body: one_event_feed("20260807T090000Z", "20260807T093000Z"),
        };
        run_ics_feed_poll(&vault, &drifted, &config, 1_800_000_100, 7).expect("drift poll");
        let after = vault
            .read_entity_header(&event)
            .expect("header")
            .expect("event exists");
        assert_eq!(
            (after.occurred_start, after.occurred_end),
            (1_786_093_200, 1_786_095_000),
            "a drifted DTSTART/DTEND re-mints the EVENT occurrence"
        );
    }
}
