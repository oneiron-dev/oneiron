//! CAL-02-FEED-CONSENT = A (Engine ruling 12:04, Sun 15 Nov): one import
//! consent per installed ICS feed.
//!
//! The first completed poll of an installed feed opens one review of its
//! imported claims and polls no more. The owner approves or declines that
//! review whole, with one consent receipt. An approval is the feed's standing
//! consent: a later poll's claims land Approved, still `Imported`. Another
//! feed in the same vault keeps its own review. A provider reset pauses the
//! feed and leaves its consent as it is.
//!
//! The first poll's property continuations (an event past one admission
//! pass) read that poll's archived version, so their claims join its review
//! and move it. A continuation of another source's admission under the
//! feed's system (a CalDAV connector's pull) never settles under the feed's
//! consent (Astra review T2, Sun 15 Nov 13:50).
//!
//! Every poll runs through the installed-feed door (`feed_door`), as the
//! host's queued-poll worker and the `calendar.ics.poll` verb do, on a seeded
//! vault whose gate holds each imported claim for consent.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test calendar_ics_feed_consent`.
#![cfg(oneiron_test_support)]

use std::sync::{Arc, Mutex};

use oneiron::attempt_queue::{
    AttemptQueue, AttemptRecord, ClaimAttempt, ClaimOutcome, CompleteAttempt,
};
use oneiron::blob_artifact::{BlobArtifactBody, BlobVersionProvenance};
use oneiron::calendar::CalendarError;
use oneiron::calendar::claims::PREDICATE_CALENDAR_ORIGIN;
use oneiron::calendar::ingest::feed_door::{
    self as feed, CalendarIcsFeedConfigureRequest, CalendarIcsFeedConsent, CalendarIcsFeedRequest,
    CalendarIcsFeedReviewDecision, CalendarIcsFeedReviewRequest, CalendarIcsPollResult,
};
use oneiron::calendar::ingest::{
    ICS_PROPERTY_CONTINUATION_ATTEMPT_KIND, IcsFeedFetcher, IcsFeedPollConfig, IcsFetchResponse,
    IcsPropertyContinuationPayload,
};
use oneiron::calendar::passport::resolve_event_by_uid;
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::Memory;
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimSource, EdgeActorClass, EntityId, TimeRange, Vault,
    VaultConfig, WriteActor,
};
use oneiron_keystore::MemoryKeystore;

/// Whom the tests claim queued continuations as.
const LEASE_OWNER: &str = "calendar-ics-feed-consent-test";

/// One admission pass admits at most 500 property claims of an event
/// (`CALENDAR_PROPERTY_ADMISSIONS_PER_PASS`); one attendee more queues a
/// property continuation.
const ATTENDEES_PAST_ONE_PASS: usize = 501;

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    owner: EntityId,
    proof: AuthenticatedOwner,
}

impl Fixture {
    /// A seeded vault (the shipped policy manifest holds each imported
    /// claim), rooted, its engine machines enrolled, and its owner.
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

    fn install(&self, system: &str) -> IcsFeedPollConfig {
        let config = IcsFeedPollConfig {
            secret_ref: format!("ics-feed:{system}"),
            system: system.to_owned(),
            cadence_min_seconds: 300,
            cadence_max_seconds: 900,
        };
        feed::configure(
            &self.memory(),
            &self.proof,
            &CalendarIcsFeedConfigureRequest {
                config: config.clone(),
            },
        )
        .expect("install the feed");
        config
    }

    fn poll(
        &self,
        config: &IcsFeedPollConfig,
        response: IcsFetchResponse,
    ) -> Result<CalendarIcsPollResult, String> {
        let fetcher = StubFetcher::with([response]);
        feed::run_installed_poll(
            &self.memory(),
            &self.proof,
            &fetcher,
            None,
            config,
            EntityId::now().to_hex(),
        )
        .map(|completion| completion.result)
        .map_err(|error| error.to_string())
    }

    fn consent(&self, system: &str) -> CalendarIcsFeedConsent {
        feed::status(
            &self.memory(),
            &self.proof,
            &CalendarIcsFeedRequest {
                system: system.to_owned(),
            },
        )
        .expect("feed status")
        .expect("installed feed")
        .consent
    }

    fn review(
        &self,
        system: &str,
        review_ref: &str,
        decision: CalendarIcsFeedReviewDecision,
    ) -> Result<CalendarIcsFeedConsent, String> {
        feed::review(
            &self.memory(),
            &self.proof,
            &CalendarIcsFeedReviewRequest {
                system: system.to_owned(),
                review_ref: review_ref.to_owned(),
                decision,
            },
        )
        .map_err(|error| error.to_string())
    }

    /// The imported claims on the EVENT `uid` names: every claim but its
    /// projector-written `calendar.origin`.
    fn imported_claims(&self, uid: &str) -> Vec<(EntityId, ClaimBody)> {
        let event = resolve_event_by_uid(&self.vault, uid)
            .expect("resolve uid")
            .expect("event for uid");
        let claims: Vec<_> = self
            .vault
            .claims_for_subject(&event)
            .expect("claims for subject")
            .into_iter()
            .map(|id| {
                let body = self
                    .vault
                    .get_claim(&id)
                    .expect("get claim")
                    .expect("claim");
                (id, body)
            })
            .filter(|(_, body)| body.predicate != PREDICATE_CALENDAR_ORIGIN)
            .collect();
        assert!(!claims.is_empty(), "the feed imported claims about {uid}");
        claims
    }

    /// The next due property continuation, claimed as the host's worker
    /// claims it: its attempt and the payload it reads.
    fn claim_continuation(&self) -> Option<(AttemptRecord, IcsPropertyContinuationPayload)> {
        let claimed = AttemptQueue::new(&self.vault)
            .claim_kind(
                ICS_PROPERTY_CONTINUATION_ATTEMPT_KIND,
                ClaimAttempt {
                    lease_owner: LEASE_OWNER.to_owned(),
                    now: self.vault.now_recorded_at(),
                },
            )
            .expect("claim a property continuation");
        let ClaimOutcome::Claimed(attempt) = claimed else {
            return None;
        };
        let payload = serde_json::from_slice(&attempt.payload).expect("continuation payload");
        Some((attempt, payload))
    }

    /// Runs `payload` through the installed-feed door, as the host's worker
    /// does, and completes `attempt`.
    fn run_continuation(&self, attempt: &AttemptRecord, payload: &IcsPropertyContinuationPayload) {
        feed::run_installed_continuation(&self.memory(), &self.proof, None, payload)
            .expect("run the property continuation");
        AttemptQueue::new(&self.vault)
            .complete(CompleteAttempt {
                id: attempt.id,
                lease_owner: LEASE_OWNER.to_owned(),
                attempt_count: attempt.attempt_count,
                now: self.vault.now_recorded_at(),
            })
            .expect("complete the property continuation");
    }

    /// Archives `body` as the first version of a new artifact, as another
    /// source's pull archives what it read; answers its `artifact#vN` ref.
    fn archive_elsewhere(&self, body: &[u8]) -> String {
        let artifact = EntityId::now();
        let now = self.vault.now_recorded_at();
        let at = TimeRange {
            start: now,
            end: now,
        };
        self.vault
            .put_blob_artifact(
                &artifact,
                &BlobArtifactBody::new("caldav-pull:work", "text/calendar"),
                at,
                now,
            )
            .expect("another source's artifact");
        let version = self
            .vault
            .append_blob_artifact_version(
                &artifact,
                body,
                &BlobVersionProvenance::AgentRun {
                    run_ref: "caldav-pull:work".to_owned(),
                },
                WriteActor::new(self.owner, EdgeActorClass::Human),
                at,
                now,
            )
            .expect("another source's archived version");
        format!("{}#v{}", artifact.to_hex(), version.version)
    }
}

/// A scripted fetcher: replays queued responses; a fetch with none queued
/// fails, so a held feed that fetched anyway shows.
struct StubFetcher {
    responses: Mutex<std::collections::VecDeque<IcsFetchResponse>>,
}

impl StubFetcher {
    fn with(responses: impl IntoIterator<Item = IcsFetchResponse>) -> Self {
        Self {
            responses: Mutex::new(responses.into_iter().collect()),
        }
    }
}

impl IcsFeedFetcher for StubFetcher {
    fn fetch(
        &self,
        _secret_ref: &str,
        _if_none_match: Option<&str>,
    ) -> Result<IcsFetchResponse, CalendarError> {
        self.responses
            .lock()
            .expect("responses")
            .pop_front()
            .ok_or_else(|| CalendarError::IcsFetch {
                reason: "stub fetcher has no queued response".to_owned(),
            })
    }
}

/// A complete VCALENDAR body holding one VEVENT per UID.
fn complete(uids: &[&str], etag: &str) -> IcsFetchResponse {
    let mut out = String::from("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//oneiron//test//EN\r\n");
    for uid in uids {
        out.push_str("BEGIN:VEVENT\r\n");
        out.push_str(&format!("UID:{uid}\r\n"));
        out.push_str("DTSTAMP:20260805T100000Z\r\n");
        out.push_str("DTSTART:20260806T140000Z\r\n");
        out.push_str("DTEND:20260806T150000Z\r\n");
        out.push_str("SEQUENCE:1\r\n");
        out.push_str("SUMMARY:standup\r\n");
        out.push_str("END:VEVENT\r\n");
    }
    out.push_str("END:VCALENDAR\r\n");
    IcsFetchResponse::Complete {
        etag: Some(etag.to_owned()),
        body: out.into_bytes(),
    }
}

/// A VCALENDAR body holding one VEVENT `uid` with `attendees` distinct
/// attendees.
fn calendar_with_attendees(uid: &str, attendees: usize) -> Vec<u8> {
    let mut out = String::from("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//oneiron//test//EN\r\n");
    out.push_str("BEGIN:VEVENT\r\n");
    out.push_str(&format!("UID:{uid}\r\n"));
    out.push_str("DTSTAMP:20260805T100000Z\r\n");
    out.push_str("DTSTART:20260806T140000Z\r\n");
    out.push_str("DTEND:20260806T150000Z\r\n");
    out.push_str("SEQUENCE:1\r\n");
    out.push_str("SUMMARY:all hands\r\n");
    for n in 0..attendees {
        out.push_str(&format!("ATTENDEE:mailto:guest-{n}@example.com\r\n"));
    }
    out.push_str("END:VEVENT\r\n");
    out.push_str("END:VCALENDAR\r\n");
    out.into_bytes()
}

fn assert_all(claims: &[(EntityId, ClaimBody)], approval: ClaimApprovalStatus, why: &str) {
    for (id, body) in claims {
        assert_eq!(
            body.approval, approval,
            "{why}: claim {id:?} ({})",
            body.predicate
        );
        assert_eq!(
            body.source,
            Some(ClaimSource::Imported),
            "{why}: claim {id:?} keeps the imported tier"
        );
    }
}

fn open_review(consent: CalendarIcsFeedConsent) -> (u32, String) {
    match consent {
        CalendarIcsFeedConsent::AwaitingReview { claims, review_ref } => (claims, review_ref),
        other => panic!("expected an open review, got {other:?}"),
    }
}

#[test]
fn first_poll_opens_one_review_and_holds_the_feed_until_the_owner_decides() {
    let f = Fixture::open();
    let work = f.install("work");
    assert_eq!(f.consent("work"), CalendarIcsFeedConsent::AwaitingFirstPoll);

    let result = f
        .poll(&work, complete(&["uid-1@work"], "v1"))
        .expect("first poll");
    let claims = f.imported_claims("uid-1@work");
    assert_all(
        &claims,
        ClaimApprovalStatus::Proposed,
        "the first poll's claims wait on the review",
    );
    let (count, _) = open_review(f.consent("work"));
    assert_eq!(
        result,
        CalendarIcsPollResult::AwaitingReview { claims: count },
        "the first poll ends the chain on the review"
    );
    assert_eq!(
        count as usize,
        claims.len(),
        "the review holds every claim the first poll imported"
    );
    assert!(
        feed::poll_waits_on_owner(&f.vault, &work).expect("hold"),
        "the host completes the feed's queued poll unpolled"
    );
    // The hold refuses before any fetch: the stub's queued response stays
    // unread, and a fetch would have answered with the poll's result.
    let refused = f
        .poll(&work, complete(&["uid-1@work"], "v1"))
        .expect_err("a held feed does not poll");
    assert!(
        refused.contains("waits on the owner's review"),
        "refused as held, got: {refused}"
    );
}

#[test]
fn approval_is_one_receipt_and_the_standing_consent_for_later_polls() {
    let f = Fixture::open();
    let work = f.install("work");
    f.poll(&work, complete(&["uid-1@work"], "v1"))
        .expect("first poll");
    let (_, review_ref) = open_review(f.consent("work"));

    let decided = f
        .review("work", &review_ref, CalendarIcsFeedReviewDecision::Approve)
        .expect("the owner approves the review");
    let CalendarIcsFeedConsent::Granted { receipt, .. } = &decided else {
        panic!("expected the standing consent, got {decided:?}");
    };
    assert!(
        !receipt.is_empty(),
        "the approval names its consent receipt"
    );
    assert_eq!(f.consent("work"), decided);
    assert_all(
        &f.imported_claims("uid-1@work"),
        ClaimApprovalStatus::Approved,
        "the approval lands every reviewed claim",
    );
    assert!(
        !feed::poll_waits_on_owner(&f.vault, &work).expect("hold"),
        "the approved feed polls again"
    );
    assert!(
        f.review("work", &review_ref, CalendarIcsFeedReviewDecision::Approve)
            .is_err(),
        "a decided review is not decided twice"
    );

    let result = f
        .poll(&work, complete(&["uid-1@work", "uid-2@work"], "v2"))
        .expect("a poll under the standing consent");
    assert!(
        matches!(result, CalendarIcsPollResult::Reenqueued { .. }),
        "the chain runs on, got {result:?}"
    );
    assert_all(
        &f.imported_claims("uid-2@work"),
        ClaimApprovalStatus::Approved,
        "a later poll's new event lands under the standing consent",
    );
}

#[test]
fn another_feed_keeps_its_own_review_and_its_decline_ends_it() {
    let f = Fixture::open();
    let work = f.install("work");
    f.poll(&work, complete(&["uid-1@work"], "v1"))
        .expect("work's first poll");
    let (_, work_ref) = open_review(f.consent("work"));
    f.review("work", &work_ref, CalendarIcsFeedReviewDecision::Approve)
        .expect("approve work");

    let home = f.install("home");
    let result = f
        .poll(&home, complete(&["uid-1@home"], "h1"))
        .expect("home's first poll");
    assert!(
        matches!(result, CalendarIcsPollResult::AwaitingReview { .. }),
        "work's consent does not cover home, got {result:?}"
    );
    assert_all(
        &f.imported_claims("uid-1@home"),
        ClaimApprovalStatus::Proposed,
        "home's claims wait on home's own review",
    );

    let (_, home_ref) = open_review(f.consent("home"));
    assert!(
        f.review(
            "home",
            "0".repeat(64).as_str(),
            CalendarIcsFeedReviewDecision::Decline
        )
        .is_err(),
        "a decision on a review that is not the open one refuses"
    );
    let decided = f
        .review("home", &home_ref, CalendarIcsFeedReviewDecision::Decline)
        .expect("the owner declines home");
    assert!(
        matches!(decided, CalendarIcsFeedConsent::Declined { .. }),
        "got {decided:?}"
    );
    for (id, body) in f.imported_claims("uid-1@home") {
        assert_eq!(
            body.approval,
            ClaimApprovalStatus::Rejected,
            "the decline rejects every reviewed claim: {id:?} ({})",
            body.predicate
        );
    }
    assert!(
        feed::poll_waits_on_owner(&f.vault, &home).expect("hold"),
        "a declined feed polls no more"
    );
    assert!(
        f.poll(&home, complete(&["uid-1@home"], "h2")).is_err(),
        "a declined feed's poll refuses"
    );
    assert!(
        matches!(f.consent("work"), CalendarIcsFeedConsent::Granted { .. }),
        "home's decline leaves work's consent"
    );
}

#[test]
fn provider_reset_pauses_the_feed_and_keeps_its_consent() {
    let f = Fixture::open();
    let work = f.install("work");
    f.poll(&work, complete(&["uid-1@work"], "v1"))
        .expect("first poll");
    let (_, review_ref) = open_review(f.consent("work"));
    let granted = f
        .review("work", &review_ref, CalendarIcsFeedReviewDecision::Approve)
        .expect("approve");

    let result = f
        .poll(&work, IcsFetchResponse::CredentialReset)
        .expect("a provider reset pauses loudly");
    assert!(
        matches!(result, CalendarIcsPollResult::PausedNeedsInput { .. }),
        "got {result:?}"
    );
    assert_eq!(f.consent("work"), granted, "the pause keeps the consent");
    assert_all(
        &f.imported_claims("uid-1@work"),
        ClaimApprovalStatus::Approved,
        "the pause cancels nothing it approved",
    );
}

#[test]
fn first_poll_continuation_joins_its_review_and_moves_it() {
    let f = Fixture::open();
    let work = f.install("work");
    f.poll(
        &work,
        IcsFetchResponse::Complete {
            etag: Some("v1".to_owned()),
            body: calendar_with_attendees("all-hands@work", ATTENDEES_PAST_ONE_PASS),
        },
    )
    .expect("first poll");
    let (before, first_ref) = open_review(f.consent("work"));

    let (attempt, payload) = f
        .claim_continuation()
        .expect("the first poll queued a property continuation");
    f.run_continuation(&attempt, &payload);
    let (after, moved_ref) = open_review(f.consent("work"));
    assert!(
        after > before,
        "the continuation's claims join the review: {before} -> {after}"
    );
    assert_ne!(moved_ref, first_ref, "joining them moves the review");

    let refused = f
        .review("work", &first_ref, CalendarIcsFeedReviewDecision::Approve)
        .expect_err("a decision on the earlier review refuses");
    assert!(
        refused.contains("moved"),
        "refused as moved, got: {refused}"
    );
    f.review("work", &moved_ref, CalendarIcsFeedReviewDecision::Approve)
        .expect("approve the whole review");
    let claims = f.imported_claims("all-hands@work");
    assert_eq!(
        claims.len(),
        after as usize,
        "the review held every claim the poll and its continuation imported"
    );
    assert_all(
        &claims,
        ClaimApprovalStatus::Approved,
        "the one approval settles the continuation's claims too",
    );
}

#[test]
fn another_source_under_the_feed_system_never_settles_under_its_consent() {
    let f = Fixture::open();
    let work = f.install("work");
    let body = calendar_with_attendees("all-hands@work", ATTENDEES_PAST_ONE_PASS);
    f.poll(
        &work,
        IcsFetchResponse::Complete {
            etag: Some("v1".to_owned()),
            body: body.clone(),
        },
    )
    .expect("first poll");
    let (attempt, payload) = f
        .claim_continuation()
        .expect("the first poll queued a property continuation");
    let (_, review_ref) = open_review(f.consent("work"));
    f.review("work", &review_ref, CalendarIcsFeedReviewDecision::Approve)
        .expect("approve: the feed's standing consent");

    // Another source under the same system (a CalDAV connector's pull) holds
    // the same event, archived in its own artifact: its continuation passes
    // the passport check, and must not take the feed's consent.
    let elsewhere = f.archive_elsewhere(&body);
    let other = IcsPropertyContinuationPayload {
        blob_ref: elsewhere.clone(),
        source_version: elsewhere,
        ..payload
    };
    f.run_continuation(&attempt, &other);
    let claims = f.imported_claims("all-hands@work");
    let waiting: Vec<_> = claims
        .iter()
        .filter(|(_, body)| body.approval == ClaimApprovalStatus::Proposed)
        .collect();
    assert_eq!(
        waiting.len(),
        1,
        "the other source's one claim waits on its own consent"
    );
    assert!(
        claims
            .iter()
            .filter(|(_, body)| body.approval != ClaimApprovalStatus::Proposed)
            .all(|(_, body)| body.approval == ClaimApprovalStatus::Approved),
        "every other claim landed under the review's approval"
    );
}
