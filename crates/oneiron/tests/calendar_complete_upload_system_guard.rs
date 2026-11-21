//! FIX CALENDAR-COMPLETE-IMPORT-SWEEPS-OTHER-SOURCES: an owner's complete
//! ICS upload marks absent every live inbound passport of its system whose
//! UID the file lacks, and cancels each EVENT no live source reports any more.
//! So the upload never runs under a system another installed source imports
//! under, and no feed, seat or upload takes a pack calendar source's system.
//!
//! - An upload under the system of a CalDAV seat is refused; one under
//!   another system applies.
//! - An upload under the system of an installed ICS feed is refused; once the
//!   owner uninstalls the feed, the retired system is open to an upload.
//! - An upload, a seat install and a feed install under a `mail_pack:` system
//!   are refused: only pack calendar sources take one.
//! - CAL-PASSPORT-STORES-NO-SYSTEM-IDENTITY: an upload system the claim door
//!   stored as a custody handle of a record that holds that one value reads
//!   as its name: a second complete upload under it marks absent the
//!   passport it leaves out, and the owner moves an occurrence of a series
//!   uploaded under it (with the same move under a system in clear beside it).
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test calendar_complete_upload_system_guard`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::authority::MachineRole;
use oneiron::calendar::CalendarError;
use oneiron::calendar::claims::{
    CalendarPassportPresence, CalendarPassportValue, CalendarStatus, PREDICATE_CALENDAR_STATUS,
};
use oneiron::calendar::ingest::door::{
    CalendarIcsImportReceipt, CalendarIcsImportRequest, CalendarInstanceMoveRequest,
    import_ics_as_owner, move_instance_as_owner,
};
use oneiron::calendar::ingest::feed_door::{
    self as feed, CalendarIcsFeedConsent, CalendarIcsFeedRequest, CalendarIcsFeedReviewDecision,
    CalendarIcsFeedReviewRequest, CalendarIcsPollResult,
};
use oneiron::calendar::ingest::{IcsFeedFetcher, IcsFeedPollConfig, IcsFetchResponse};
use oneiron::calendar::passport::{live_passports_for_event, resolve_event_by_uid};
use oneiron::claim::ClaimApprovalStatus;
use oneiron::consent::AuthenticatedOwner;
use oneiron::mail_pack::{
    ICS_CALENDAR_CONNECTOR_EFFECTOR, MailCalendarFeed, MailCalendarRead, MailCalendarWire,
    MailProvider, MailSourceConnectRequest, MailSourceKind, MailSourceStatus, MailSyncSource,
    install_mail_calendar_pack_embedded,
};
use oneiron::memory::hook_regen_doors::PackPutOutcome;
use oneiron::memory::{
    BlobArtifactInput, BlobVersionAppendOutcome, ClaimProposalReviewRequest, ClaimSettleDecision,
    ClaimSettleRequest, Memory,
};
use oneiron::registry::ENTITY_TYPE_EVENT;
use oneiron::secret_custody::{CustodyTier, SECRET_SCOPE_READ, SecretBinding};
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingCaller};
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::{ClaimLifecycleStatus, EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use serde_json::{Value, json};

const FEED: &str = "calendar.ics_feed";
const SEAT: &str = "calendar.connector_seat";
/// The refusal an upload gets under the system of an installed feed or seat.
const HELD: &str = "imports under this system";
/// The refusal for a system with the pack calendar prefix.
const PACK: &str = "names a pack calendar source";
/// A system with the pack calendar prefix.
const PACK_SYSTEM: &str = "mail_pack:00000000000000000000000000000000";
/// 2026-03-02 09:00 UTC.
const NOW: u64 = 1_772_442_000;
/// The UID in the one-VEVENT test calendar below.
const ICS_UID: &str = "export-1@example.test";
/// One complete VCALENDAR with one VEVENT.
const ICS: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//oneiron//test//EN\r\n\
BEGIN:VEVENT\r\nUID:export-1@example.test\r\nDTSTAMP:20260302T070000Z\r\n\
DTSTART:20260302T100000Z\r\nDTEND:20260302T110000Z\r\nSEQUENCE:0\r\n\
SUMMARY:Planning\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    owner: EntityId,
    proof: AuthenticatedOwner,
}

impl Fixture {
    fn open() -> Self {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut config = VaultConfig::device();
        config.dimensions = 4;
        config.embedding_model = None;
        let vault = Vault::open(dir.path(), config).expect("seeded vault");
        vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
        oneiron::test_support::provision_engine_machines(&vault);
        let (owner, proof) = embedded_owner(&vault).expect("authenticated embedded owner");
        Self {
            _dir: dir,
            vault,
            owner,
            proof,
        }
    }

    fn memory(&self) -> Memory<'_> {
        self.vault.memory(self.owner, EdgeActorClass::Human)
    }

    /// The owner sets the `key` item `item` to `value`; `None` clears it.
    fn set(
        &self,
        key: &str,
        item: &str,
        value: Option<Value>,
    ) -> Result<SetSettingOutcome, String> {
        let mut change = SetSetting::vault_value(key, Value::Null);
        change.item = Some(item.to_owned());
        change.value = value;
        self.vault
            .set_setting(SettingCaller::Owner(&self.proof), change)
            .map_err(|error| error.to_string())
    }

    /// The owner installs an ICS feed polling under `system`.
    fn install_feed(&self, system: &str) -> Result<SetSettingOutcome, String> {
        self.set(
            FEED,
            system,
            Some(json!({
                "secret_ref": format!("ics-feed:{system}"),
                "system": system,
                "cadence_min_seconds": 300,
                "cadence_max_seconds": 900,
            })),
        )
    }

    /// The owner installs the CalDAV seat `seat_ref` importing under `system`.
    fn install_seat(&self, seat_ref: &str, system: &str) -> Result<SetSettingOutcome, String> {
        self.set(
            SEAT,
            seat_ref,
            Some(json!({
                "config": {
                    "seat_ref": seat_ref,
                    "secret_ref": format!("caldav:{seat_ref}"),
                    "system": system,
                    "calendar_ref": "personal",
                    "cadence_jitter_min_seconds": 300,
                    "cadence_jitter_max_seconds": 900,
                },
                "endpoint": "https://dav.example.test/",
            })),
        )
    }

    /// The owner uploads [`ICS`] as a complete feed under `system`.
    fn upload(&self, system: &str) -> Result<(), String> {
        self.upload_ics(system, ICS).map(|_| ())
    }

    /// The owner puts `body` as an upload's bytes: its artifact and version.
    fn put_ics(&self, body: &str) -> (String, u64) {
        let memory = self.memory();
        let artifact = memory
            .put_blob_artifact(&BlobArtifactInput {
                id: None,
                name: "export.ics".to_owned(),
                media_type: "text/calendar".to_owned(),
                occurred_at: NOW,
                learned_at: None,
            })
            .expect("the upload's artifact");
        let BlobVersionAppendOutcome::Landed(version) = memory
            .append_blob_version(&artifact.id_hex, body.as_bytes(), None, NOW, None)
            .expect("the upload's bytes")
        else {
            panic!("an owner upload lands at once");
        };
        (artifact.id_hex, version.version)
    }

    /// The owner uploads `body` as a complete feed under `system`.
    fn upload_ics(&self, system: &str, body: &str) -> Result<CalendarIcsImportReceipt, String> {
        let (source_blob_ref, source_version) = self.put_ics(body);
        import_ics_as_owner(
            &self.memory(),
            &self.proof,
            &CalendarIcsImportRequest {
                system: system.to_owned(),
                source_blob_ref,
                source_version,
            },
            None,
        )
        .map_err(|error| error.to_string())
    }

    /// The owner approves every claim an upload proposed on `event`: an
    /// upload files its claims pending review, and the move door amends an
    /// occurrence of an admitted series only.
    fn approve_proposed_claims(&self, event: &EntityId) {
        let memory = self.memory();
        for id in self
            .vault
            .claims_for_subject(event)
            .expect("read the EVENT's claims")
        {
            let Some(claim) = self.vault.get_claim(&id).expect("read the claim") else {
                continue;
            };
            if claim.lifecycle != ClaimLifecycleStatus::Active
                || claim.approval != ClaimApprovalStatus::Proposed
            {
                continue;
            }
            let claim_ref = id.to_hex();
            let review = memory
                .claim_review_as_owner(
                    &self.proof,
                    &ClaimProposalReviewRequest {
                        claim_ref: claim_ref.clone(),
                        grant_ref: None,
                    },
                )
                .expect("FIXTURE: the owner reviews the upload's claim");
            memory
                .claim_settle_as_owner(
                    &self.proof,
                    &ClaimSettleRequest {
                        claim_ref,
                        review_id: review.review_id,
                        decision: ClaimSettleDecision::Approve,
                        grant_ref: None,
                    },
                )
                .expect("FIXTURE: the owner approves the upload's claim");
        }
    }

    /// The owner uploads [`SERIES_ICS`] under `system` and approves its
    /// claims: the series master EVENT.
    fn upload_admitted_series(&self, system: &str) -> EntityId {
        self.upload_ics(system, SERIES_ICS)
            .expect("FIXTURE: the owner's series upload lands");
        let master = resolve_event_by_uid(&self.vault, SERIES_UID)
            .expect("resolve the series UID")
            .expect("FIXTURE: the series UID resolves to its master EVENT");
        self.approve_proposed_claims(&master);
        master
    }

    /// The owner moves the series' second occurrence to [`MOVED_START`]
    /// through the move door under `system`, with [`MOVED_ICS`] as its
    /// source.
    fn move_second_occurrence(&self, system: &str) -> Result<CalendarIcsImportReceipt, String> {
        let (source_blob_ref, source_version) = self.put_ics(MOVED_ICS);
        move_instance_as_owner(
            &self.memory(),
            &self.proof,
            &CalendarInstanceMoveRequest {
                system: system.to_owned(),
                source_blob_ref,
                source_version,
                uid: SERIES_UID.to_owned(),
                original_start_utc: SECOND_OCCURRENCE,
                start_utc: MOVED_START,
                end_utc: MOVED_END,
            },
            None,
        )
        .map_err(|error| error.to_string())
    }
}

/// The UID of [`SERIES_ICS`].
const SERIES_UID: &str = "standup-1@example.test";
/// A daily series of five from 2026-03-02 10:00 UTC.
const SERIES_ICS: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//oneiron//test//EN\r\n\
BEGIN:VEVENT\r\nUID:standup-1@example.test\r\nDTSTAMP:20260302T070000Z\r\n\
DTSTART:20260302T100000Z\r\nDTEND:20260302T110000Z\r\nRRULE:FREQ=DAILY;COUNT=5\r\n\
SEQUENCE:0\r\nSUMMARY:Standup\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
/// 2026-03-03 10:00 UTC: the series' second occurrence.
const SECOND_OCCURRENCE: u64 = 1_772_532_000;
/// 2026-03-03 12:00 UTC: where the owner moves the second occurrence.
const MOVED_START: u64 = 1_772_539_200;
/// 2026-03-03 13:00 UTC.
const MOVED_END: u64 = 1_772_542_800;
/// The series' second occurrence detached at [`MOVED_START`]..[`MOVED_END`].
const MOVED_ICS: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//oneiron//test//EN\r\n\
BEGIN:VEVENT\r\nUID:standup-1@example.test\r\nDTSTAMP:20260302T080000Z\r\n\
RECURRENCE-ID:20260303T100000Z\r\nDTSTART:20260303T120000Z\r\nDTEND:20260303T130000Z\r\n\
SEQUENCE:1\r\nSUMMARY:Standup\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";

fn applied(outcome: Result<SetSettingOutcome, String>, what: &str) {
    match outcome {
        Ok(SetSettingOutcome::Applied { .. }) => {}
        other => panic!("{what} applies: {other:?}"),
    }
}

fn refused<T: std::fmt::Debug>(outcome: Result<T, String>, reason: &str, what: &str) {
    match outcome {
        Err(error) => assert!(error.contains(reason), "{what}: {error}"),
        Ok(outcome) => panic!("{what} is refused, but it gave {outcome:?}"),
    }
}

#[test]
fn a_complete_upload_never_runs_under_the_system_of_a_seat() {
    let fx = Fixture::open();
    applied(fx.install_seat("work", "shared"), "the seat install");

    refused(
        fx.upload("shared"),
        HELD,
        "an upload on the seat's system, whose sweep would cancel the seat's events",
    );

    fx.upload("export")
        .expect("an upload under another system applies");
}

#[test]
fn a_complete_upload_never_runs_under_the_system_of_an_installed_feed() {
    let fx = Fixture::open();
    applied(fx.install_feed("shared"), "the feed install");

    refused(
        fx.upload("shared"),
        HELD,
        "an upload on the feed's system, whose sweep would cancel the feed's events",
    );

    applied(fx.set(FEED, "shared", None), "the owner's uninstall");
    fx.upload("shared")
        .expect("an upload on a retired feed system, which no poll sweeps again, applies");
}

#[test]
fn no_upload_seat_or_feed_takes_a_pack_calendar_system() {
    let fx = Fixture::open();

    refused(
        fx.install_seat("work", PACK_SYSTEM),
        PACK,
        "a seat on a pack calendar system",
    );
    refused(
        fx.install_feed(PACK_SYSTEM),
        PACK,
        "a feed on a pack calendar system",
    );
    refused(
        fx.upload(PACK_SYSTEM),
        PACK,
        "an upload on a pack calendar system",
    );
}

const EMPTY_ICS: &str =
    "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//oneiron//test//EN\r\nEND:VCALENDAR\r\n";

struct CompleteFeed<'a> {
    body: &'a str,
    etag: &'a str,
}

impl IcsFeedFetcher for CompleteFeed<'_> {
    fn fetch(
        &self,
        _secret_ref: &str,
        _if_none_match: Option<&str>,
    ) -> Result<IcsFetchResponse, CalendarError> {
        Ok(IcsFetchResponse::Complete {
            etag: Some(self.etag.to_owned()),
            body: self.body.as_bytes().to_vec(),
        })
    }
}

fn poll_feed(
    fx: &Fixture,
    config: &IcsFeedPollConfig,
    body: &str,
    etag: &str,
) -> CalendarIcsPollResult {
    feed::run_installed_poll(
        &fx.memory(),
        &fx.proof,
        &CompleteFeed { body, etag },
        None,
        config,
        EntityId::now().to_hex(),
    )
    .expect("FIXTURE: the installed feed runs a complete poll")
    .result
}

fn sole_passport(vault: &Vault, event: &EntityId) -> CalendarPassportValue {
    let mut passports = live_passports_for_event(vault, event).expect("read the EVENT's passports");
    assert_eq!(
        passports.len(),
        1,
        "FIXTURE: the EVENT has one passport head: {passports:?}"
    );
    passports.pop().expect("the one passport").1
}

fn has_cancelled_status(vault: &Vault, event: &EntityId) -> bool {
    vault
        .claims_for_subject(event)
        .expect("read the EVENT's claims")
        .into_iter()
        .filter_map(|id| vault.get_claim(&id).expect("read the claim"))
        .filter(|claim| {
            claim.predicate == PREDICATE_CALENDAR_STATUS
                && claim.lifecycle == ClaimLifecycleStatus::Active
        })
        .any(|claim| {
            let fields = claim.value.as_map().expect("a status is a map");
            fields.iter().any(|(key, value)| {
                key.as_str() == Some("status")
                    && value.as_str() == Some(CalendarStatus::Cancelled.as_str())
            })
        })
}

// blind review round 1 of #10312: a custody rotation must not let a feed sweep another source.
#[test]
fn a_feed_poll_never_sweeps_an_upload_passport_whose_system_record_rotated_to_the_feed() {
    const UPLOAD_SYSTEM: &str = "owner-calendar-export";
    const FEED_SYSTEM: &str = "installed-calendar-feed";
    const SYSTEM_RECORD: &str = "rotated-calendar-system";

    let fx = Fixture::open();
    fx.vault
        .register_test_secret(SYSTEM_RECORD, UPLOAD_SYSTEM.as_bytes(), Vec::new(), NOW)
        .expect("FIXTURE: custody registers the upload system");
    fx.upload(UPLOAD_SYSTEM)
        .expect("FIXTURE: the owner's complete upload lands");
    let event = resolve_event_by_uid(&fx.vault, ICS_UID)
        .expect("resolve the upload's UID")
        .expect("FIXTURE: the upload's UID resolves to its EVENT");
    let uploaded = sole_passport(&fx.vault, &event);
    assert!(
        uploaded.system != UPLOAD_SYSTEM && uploaded.system.contains("[secret sc"),
        "FIXTURE: the upload passport stored the system as a custody handle: {uploaded:?}"
    );

    let installed = fx.install_feed(FEED_SYSTEM).expect("install the feed");
    assert!(
        matches!(installed, SetSettingOutcome::Applied { .. }),
        "FIXTURE: the owner installs the feed"
    );
    let config = IcsFeedPollConfig {
        secret_ref: format!("ics-feed:{FEED_SYSTEM}"),
        system: FEED_SYSTEM.to_owned(),
        cadence_min_seconds: 300,
        cadence_max_seconds: 900,
    };
    let first_body = ICS.replace(ICS_UID, "feed-only@example.test");
    let first = poll_feed(&fx, &config, &first_body, "v1");
    assert!(
        matches!(first, CalendarIcsPollResult::AwaitingReview { .. }),
        "FIXTURE: the first poll opens the feed's review: {first:?}"
    );
    let status = feed::status(
        &fx.memory(),
        &fx.proof,
        &CalendarIcsFeedRequest {
            system: FEED_SYSTEM.to_owned(),
        },
    )
    .expect("read feed status")
    .expect("FIXTURE: the feed is installed");
    let CalendarIcsFeedConsent::AwaitingReview { review_ref, .. } = status.consent else {
        panic!("FIXTURE: the installed feed has an open review");
    };
    let consent = feed::review(
        &fx.memory(),
        &fx.proof,
        &CalendarIcsFeedReviewRequest {
            system: FEED_SYSTEM.to_owned(),
            review_ref,
            decision: CalendarIcsFeedReviewDecision::Approve,
        },
    )
    .expect("approve the feed's first poll");
    assert!(
        matches!(consent, CalendarIcsFeedConsent::Granted { .. }),
        "FIXTURE: the feed holds standing consent: {consent:?}"
    );

    let rotated = fx
        .vault
        .rotate_secret_as_owner(&fx.proof, SYSTEM_RECORD, FEED_SYSTEM.as_bytes(), NOW + 1)
        .expect("FIXTURE: the owner rotates the upload system record to the feed system");
    assert_eq!(
        (rotated.from_generation, rotated.to_generation),
        (0, 1),
        "FIXTURE: the same custody record now has a second value"
    );
    let before = sole_passport(&fx.vault, &event);
    assert_eq!(
        before.system, uploaded.system,
        "FIXTURE: the rotation leaves the stored passport handle in place"
    );
    assert!(
        before.uid == ICS_UID && before.direction.is_inbound_bearing(),
        "FIXTURE: the upload is the EVENT's sole inbound passport: {before:?}"
    );
    assert_eq!(
        before.presence,
        CalendarPassportPresence::Live,
        "FIXTURE: the upload passport starts live"
    );
    assert!(
        !has_cancelled_status(&fx.vault, &event),
        "FIXTURE: the uploaded EVENT starts uncancelled"
    );

    let completed = poll_feed(&fx, &config, EMPTY_ICS, "v2");
    assert!(
        matches!(completed, CalendarIcsPollResult::Reenqueued { .. }),
        "FIXTURE: the feed completes its empty listing: {completed:?}"
    );
    assert_eq!(
        sole_passport(&fx.vault, &event).presence,
        CalendarPassportPresence::Live,
        "the feed's empty listing cannot mark the upload passport absent"
    );
    assert!(
        !has_cancelled_status(&fx.vault, &event),
        "the feed's empty listing cannot cancel the uploaded EVENT"
    );
}

struct CompletePackFeed;

impl MailCalendarWire for CompletePackFeed {
    fn pull(
        &self,
        _source: &MailSyncSource,
        _cursor: Option<&str>,
    ) -> oneiron::Result<MailCalendarRead> {
        Ok(MailCalendarRead::Feed(MailCalendarFeed {
            ics: ICS.as_bytes().to_vec(),
            next_cursor: None,
        }))
    }
}

// blind review round 1 of #10312: a complete pack listing must keep its carried masked UID live.
#[test]
fn a_pack_source_keeps_a_masked_uid_live_when_its_complete_listing_carries_it() {
    const CREDENTIAL: &str = "pack-ics-credential";
    let dir = tempfile::tempdir().expect("FIXTURE: a fresh vault directory");
    let mut config = VaultConfig::device();
    config.dimensions = 4;
    config.embedding_model = None;
    let vault = Vault::open_owned(dir.path(), config).expect("FIXTURE: an owned vault");
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("FIXTURE: the install has its serving profile");
    let (owner, _) = embedded_owner(&vault).expect("FIXTURE: the authenticated embedded owner");
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let pack = install_mail_calendar_pack_embedded(&memory).expect("install the pack");
    assert_eq!(
        pack.outcome,
        PackPutOutcome::Installed,
        "FIXTURE: the owner installs the pack"
    );

    vault
        .register_test_secret(
            CREDENTIAL,
            b"https://pack-calendar.example.test/calendar.ics",
            vec![SecretBinding {
                effector: ICS_CALENDAR_CONNECTOR_EFFECTOR.to_owned(),
                tier_ceiling: CustodyTier::T0Doored,
                scopes: vec![SECRET_SCOPE_READ.to_owned()],
            }],
            NOW,
        )
        .expect("FIXTURE: custody holds the owner's ICS credential");
    let connected = memory
        .mail_sources_connect(&MailSourceConnectRequest {
            provider: MailProvider::Ics,
            kind: MailSourceKind::Calendar,
            address: "pack-calendar".to_owned(),
            provider_account: "pack-calendar".to_owned(),
            custody_ref: CREDENTIAL.to_owned(),
            members: Vec::new(),
            for_person: None,
            channel_identity_ref: None,
            copy: None,
            on_provider_delete: None,
            calendar_details: None,
        })
        .expect("FIXTURE: the owner connects an ICS calendar source");
    assert_eq!(
        connected.source.status,
        MailSourceStatus::Active,
        "FIXTURE: the pack calendar source is active"
    );
    let source = EntityId::from_hex(&connected.source.source_ref).expect("FIXTURE: the source id");
    vault
        .register_test_secret("pack-masked-uid", ICS_UID.as_bytes(), Vec::new(), NOW)
        .expect("FIXTURE: custody holds the VEVENT's UID before it is pulled");

    let first = vault
        .mail_calendar_sync_step(source, &CompletePackFeed, 1)
        .expect("FIXTURE: the first pack calendar pull succeeds");
    assert!(
        first.copy_done && first.landed == 1,
        "FIXTURE: the first pull finishes a listing carrying one VEVENT: {first:?}"
    );
    let events = vault
        .entities_by_type(ENTITY_TYPE_EVENT)
        .expect("read the EVENT ids");
    assert_eq!(events.len(), 1, "FIXTURE: the first pull mints one EVENT");
    let event = events[0];
    let passport = sole_passport(&vault, &event);
    assert!(
        passport.system == format!("mail_pack:{}", source.to_hex())
            && passport.direction.is_inbound_bearing(),
        "FIXTURE: the EVENT has the pack source's inbound passport: {passport:?}"
    );
    assert!(
        passport.uid != ICS_UID && passport.uid.contains("[secret sc"),
        "FIXTURE: the passport stored the carried UID as a custody handle: {passport:?}"
    );
    assert_eq!(
        passport.presence,
        CalendarPassportPresence::Live,
        "the first complete pack listing cannot sweep the masked UID it carries"
    );

    let second = vault
        .mail_calendar_sync_step(source, &CompletePackFeed, 1)
        .expect("FIXTURE: the second pack calendar pull succeeds");
    assert!(
        second.copy_done && second.landed == 1,
        "FIXTURE: the second pull finishes the same listing: {second:?}"
    );
    assert_eq!(
        sole_passport(&vault, &event).presence,
        CalendarPassportPresence::Live,
        "the same complete pack listing still cannot sweep its carried masked UID"
    );
}

/// The receipt of a move of the series' second occurrence names that one
/// detached instance.
fn moved_the_second_occurrence(receipt: &CalendarIcsImportReceipt) -> bool {
    matches!(
        receipt.events.as_slice(),
        [event] if event.uid == SERIES_UID && event.original_start_utc == Some(SECOND_OCCURRENCE)
    )
}

// CAL-PASSPORT-STORES-NO-SYSTEM-IDENTITY: a complete upload sweeps its own masked passport.
#[test]
fn a_complete_upload_marks_absent_the_masked_passport_of_its_own_system_it_leaves_out() {
    const UPLOAD_SYSTEM: &str = "owner-calendar-export";
    const NEXT_UID: &str = "export-2@example.test";

    let fx = Fixture::open();
    fx.vault
        .register_test_secret(
            "calendar-export-system",
            UPLOAD_SYSTEM.as_bytes(),
            Vec::new(),
            NOW,
        )
        .expect("FIXTURE: custody registers the upload system");
    fx.upload(UPLOAD_SYSTEM)
        .expect("FIXTURE: the owner's first complete upload lands");
    let first = resolve_event_by_uid(&fx.vault, ICS_UID)
        .expect("resolve the first upload's UID")
        .expect("FIXTURE: the first upload's UID resolves to its EVENT");
    let uploaded = sole_passport(&fx.vault, &first);
    assert!(
        uploaded.system != UPLOAD_SYSTEM && uploaded.system.contains("[secret sc"),
        "FIXTURE: the upload passport stored the system as a custody handle: {uploaded:?}"
    );
    assert!(
        uploaded.presence == CalendarPassportPresence::Live
            && uploaded.direction.is_inbound_bearing(),
        "FIXTURE: the upload passport starts live and inbound: {uploaded:?}"
    );

    fx.upload_ics(UPLOAD_SYSTEM, &ICS.replace(ICS_UID, NEXT_UID))
        .expect("FIXTURE: the owner's second complete upload lands");
    let next = resolve_event_by_uid(&fx.vault, NEXT_UID)
        .expect("resolve the second upload's UID")
        .expect("FIXTURE: the second upload's UID resolves to its EVENT");
    assert_eq!(
        sole_passport(&fx.vault, &next).presence,
        CalendarPassportPresence::Live,
        "FIXTURE: the second upload's own passport is live"
    );
    assert_eq!(
        sole_passport(&fx.vault, &first).presence,
        CalendarPassportPresence::Absent,
        "a second complete upload under the masked system marks absent the passport it leaves out"
    );
    assert!(
        has_cancelled_status(&fx.vault, &first),
        "the EVENT no live source reports any more is cancelled"
    );
}

// CAL-PASSPORT-STORES-NO-SYSTEM-IDENTITY: the move door finds a series' masked upload passport.
#[test]
fn the_owner_moves_an_occurrence_of_a_series_uploaded_under_a_masked_system() {
    const UPLOAD_SYSTEM: &str = "owner-standup-export";

    let fx = Fixture::open();
    fx.vault
        .register_test_secret(
            "standup-export-system",
            UPLOAD_SYSTEM.as_bytes(),
            Vec::new(),
            NOW,
        )
        .expect("FIXTURE: custody registers the upload system");
    let master = fx.upload_admitted_series(UPLOAD_SYSTEM);
    let passport = sole_passport(&fx.vault, &master);
    assert!(
        passport.system != UPLOAD_SYSTEM && passport.system.contains("[secret sc"),
        "FIXTURE: the series passport stored the system as a custody handle: {passport:?}"
    );

    let moved = fx.move_second_occurrence(UPLOAD_SYSTEM);
    assert!(
        moved.as_ref().is_ok_and(moved_the_second_occurrence),
        "the owner moves an occurrence of a series whose upload system is masked: {moved:?}"
    );
}

// Control for the test above: the same move under an upload system in clear.
#[test]
fn the_owner_moves_an_occurrence_of_a_series_uploaded_under_a_system_in_clear() {
    const UPLOAD_SYSTEM: &str = "owner-standup-export";

    let fx = Fixture::open();
    let master = fx.upload_admitted_series(UPLOAD_SYSTEM);
    assert_eq!(
        sole_passport(&fx.vault, &master).system,
        UPLOAD_SYSTEM,
        "FIXTURE: the series passport stored the system in clear"
    );

    let moved = fx.move_second_occurrence(UPLOAD_SYSTEM);
    assert!(
        moved.as_ref().is_ok_and(moved_the_second_occurrence),
        "FIXTURE: the owner moves an occurrence of a series uploaded in clear: {moved:?}"
    );
}
