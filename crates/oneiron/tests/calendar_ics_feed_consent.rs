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
//! Every poll runs through the installed-feed door (`feed_door`), as the
//! host's queued-poll worker and the `calendar.ics.poll` verb do, on a seeded
//! vault whose gate holds each imported claim for consent.

use std::sync::{Arc, Mutex};

use oneiron::calendar::CalendarError;
use oneiron::calendar::claims::PREDICATE_CALENDAR_ORIGIN;
use oneiron::calendar::ingest::feed_door::{
    self as feed, CalendarIcsFeedConfigureRequest, CalendarIcsFeedConsent, CalendarIcsFeedRequest,
    CalendarIcsFeedReviewDecision, CalendarIcsFeedReviewRequest, CalendarIcsPollResult,
};
use oneiron::calendar::ingest::{IcsFeedFetcher, IcsFeedPollConfig, IcsFetchResponse};
use oneiron::calendar::passport::resolve_event_by_uid;
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::Memory;
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimSource, EdgeActorClass, EntityId, Vault, VaultConfig,
};
use oneiron_keystore::MemoryKeystore;

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
    // The stub has no response queued: a fetch would fail with its text.
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
