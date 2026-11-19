//! Probe for FIX ICS-FEED-TURN-GREEN-POLL-GATE-PENDING (scratch branch, no PR).
//!
//! `calendar_ics_feed_uninstall_waits_for_poll` failed on #9278's head: the
//! granted feed's second poll returned "gate write rejected: outcome=pending,
//! reasons=[gate.pending.actor_ceiling, gate.pending.source_trust]". That
//! test combines three things: the inbound screen dial on with a screener,
//! a complete body that omits the owner-approved uid-1, and an uninstall on
//! a second thread. Each test here takes one of them, single-threaded, and
//! the last one settles each claim the failing poll left waiting alone, so
//! its message names the claim whose settlement the gate refuses.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test calendar_ics_feed_absence_under_consent`.
#![cfg(oneiron_test_support)]

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use oneiron::calendar::claims::PREDICATE_CALENDAR_ORIGIN;
use oneiron::calendar::ingest::feed_door::{
    self as feed, CalendarIcsFeedConsent, CalendarIcsFeedRequest, CalendarIcsFeedReviewDecision,
    CalendarIcsFeedReviewRequest, CalendarIcsPollResult,
};
use oneiron::calendar::ingest::{IcsFeedFetcher, IcsFeedPollConfig, IcsFetchResponse};
use oneiron::calendar::passport::resolve_event_by_uid;
use oneiron::calendar::{
    CALENDAR_SAFEGUARD_CONFIG_KEY, CalendarBodyScreener, CalendarError, CalendarInboundBody,
    CalendarScreenVerdict,
};
use oneiron::claim::ClaimLifecycleStatus;
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::{
    ClaimProposalReviewRequest, ClaimSettleDecision, ClaimSettleRequest, KeyValuePut, Memory,
};
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingCaller};
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::{ClaimApprovalStatus, EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;

const FEED: &str = "calendar.ics_feed";

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

    fn install(&self, system: &str) -> IcsFeedPollConfig {
        let config = IcsFeedPollConfig {
            secret_ref: format!("ics-feed:{system}"),
            system: system.to_owned(),
            cadence_min_seconds: 300,
            cadence_max_seconds: 900,
        };
        let outcome = self
            .vault
            .set_setting(
                SettingCaller::Owner(&self.proof),
                SetSetting {
                    item: Some(system.to_owned()),
                    value: Some(serde_json::to_value(&config).expect("feed config as JSON")),
                    ..SetSetting::vault_value(FEED, serde_json::Value::Null)
                },
            )
            .expect("the owner's feed change");
        assert!(
            matches!(outcome, SetSettingOutcome::Applied { .. }),
            "the owner's install applies: {outcome:?}"
        );
        config
    }

    fn poll(
        &self,
        config: &IcsFeedPollConfig,
        response: IcsFetchResponse,
        screener: Option<&dyn CalendarBodyScreener>,
    ) -> Result<CalendarIcsPollResult, String> {
        feed::run_installed_poll(
            &self.memory(),
            &self.proof,
            &StubFetcher::with([response]),
            screener,
            config,
            EntityId::now().to_hex(),
        )
        .map(|completion| completion.result)
        .map_err(|error| error.to_string())
    }

    /// Installs `system`, polls `uid` once and approves the review.
    fn granted_feed(&self, system: &str, uid: &str) -> IcsFeedPollConfig {
        let config = self.install(system);
        self.poll(&config, body(&[(uid, 1, "standup")], "v1"), None)
            .expect("first poll");
        let Some(CalendarIcsFeedConsent::AwaitingReview { review_ref, .. }) = feed::status(
            &self.memory(),
            &self.proof,
            &CalendarIcsFeedRequest {
                system: system.to_owned(),
            },
        )
        .expect("feed status")
        .map(|row| row.consent) else {
            panic!("the first poll opens the feed's review");
        };
        let decided = feed::review(
            &self.memory(),
            &self.proof,
            &CalendarIcsFeedReviewRequest {
                system: system.to_owned(),
                review_ref,
                decision: CalendarIcsFeedReviewDecision::Approve,
            },
        )
        .expect("the owner approves the review");
        assert!(
            matches!(decided, CalendarIcsFeedConsent::Granted { .. }),
            "the approval is the feed's standing consent: {decided:?}"
        );
        config
    }

    fn screen_on(&self) {
        let (namespace, key) = CALENDAR_SAFEGUARD_CONFIG_KEY
            .rsplit_once('.')
            .expect("a dotted dial key");
        let mut on = serde_json::Map::new();
        on.insert(key.to_owned(), serde_json::Value::Bool(true));
        self.memory()
            .key_value_put(&KeyValuePut {
                namespace: namespace.split('.').map(str::to_owned).collect(),
                key: key.to_owned(),
                value: serde_json::Value::Object(on),
                request_id: "safeguard-dial-on".to_owned(),
                source: "user_stated".to_owned(),
            })
            .expect("the owner's keyed value commits");
    }

    /// Every claim on the EVENT `uid` names but its `calendar.origin`:
    /// `(id, predicate, approval, lifecycle)`.
    fn claims(
        &self,
        uid: &str,
    ) -> Vec<(EntityId, String, ClaimApprovalStatus, ClaimLifecycleStatus)> {
        let event = resolve_event_by_uid(&self.vault, uid)
            .expect("resolve uid")
            .expect("event for uid");
        self.vault
            .claims_for_subject(&event)
            .expect("claims for subject")
            .into_iter()
            .map(|id| {
                let body = self
                    .vault
                    .get_claim(&id)
                    .expect("get claim")
                    .expect("claim");
                (id, body.predicate, body.approval, body.lifecycle)
            })
            .filter(|(_, predicate, _, _)| predicate != PREDICATE_CALENDAR_ORIGIN)
            .collect()
    }

    /// The owner reviews and approves the proposal `id` alone.
    fn settle_alone(&self, id: EntityId) -> Result<String, String> {
        let memory = self.memory();
        let review = memory
            .claim_review_as_owner(
                &self.proof,
                &ClaimProposalReviewRequest {
                    claim_ref: id.to_hex(),
                    grant_ref: None,
                },
            )
            .map_err(|error| format!("review: {error:?}"))?;
        let settled = memory
            .claim_settle_as_owner(
                &self.proof,
                &ClaimSettleRequest {
                    claim_ref: id.to_hex(),
                    review_id: review.review_id,
                    decision: ClaimSettleDecision::Approve,
                    grant_ref: None,
                },
            )
            .map_err(|error| format!("settle: {error:?}"))?;
        Ok(format!("{:?}", settled.verdict))
    }
}

/// Screens every body clear; its `name()` is the trait default.
struct ClearScreener;

impl CalendarBodyScreener for ClearScreener {
    fn screen(&self, _body: &CalendarInboundBody) -> oneiron::Result<CalendarScreenVerdict> {
        Ok(CalendarScreenVerdict::Clear)
    }
}

struct StubFetcher {
    responses: Mutex<VecDeque<IcsFetchResponse>>,
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

/// A complete VCALENDAR body: one VEVENT per `(uid, sequence, summary)`.
fn body(events: &[(&str, u32, &str)], etag: &str) -> IcsFetchResponse {
    let mut out = String::from("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//oneiron//test//EN\r\n");
    for (uid, sequence, summary) in events {
        out.push_str("BEGIN:VEVENT\r\n");
        out.push_str(&format!("UID:{uid}\r\n"));
        out.push_str("DTSTAMP:20260805T100000Z\r\n");
        out.push_str("DTSTART:20260806T140000Z\r\n");
        out.push_str("DTEND:20260806T150000Z\r\n");
        out.push_str(&format!("SEQUENCE:{sequence}\r\n"));
        out.push_str(&format!("SUMMARY:{summary}\r\n"));
        out.push_str("END:VEVENT\r\n");
    }
    out.push_str("END:VCALENDAR\r\n");
    IcsFetchResponse::Complete {
        etag: Some(etag.to_owned()),
        body: out.into_bytes(),
    }
}

fn assert_settles(polled: &Result<CalendarIcsPollResult, String>, what: &str) {
    assert!(
        matches!(polled, Ok(CalendarIcsPollResult::Reenqueued { .. })),
        "{what}: {polled:?}"
    );
}

#[test]
fn omission_alone_settles() {
    let f = Fixture::open();
    let work = f.granted_feed("work", "uid-1@work");
    let polled = f.poll(&work, body(&[("uid-2@work", 1, "review")], "v2"), None);
    assert_settles(&polled, "(b) the owner-approved uid-1 left out, no screen");
}

#[test]
fn revision_alone_settles() {
    let f = Fixture::open();
    let work = f.granted_feed("work", "uid-1@work");
    let polled = f.poll(
        &work,
        body(&[("uid-1@work", 2, "standup moved")], "v2"),
        None,
    );
    assert_settles(&polled, "the owner-approved uid-1 revised, no screen");
}

#[test]
fn screen_on_alone_settles() {
    let f = Fixture::open();
    let work = f.granted_feed("work", "uid-1@work");
    f.screen_on();
    let polled = f.poll(
        &work,
        body(
            &[("uid-1@work", 1, "standup"), ("uid-2@work", 1, "review")],
            "v2",
        ),
        Some(&ClearScreener as &dyn CalendarBodyScreener),
    );
    assert_settles(&polled, "(a) the screen on, uid-1 kept");
}

#[test]
fn screen_on_with_omission_settles() {
    let f = Fixture::open();
    let work = f.granted_feed("work", "uid-1@work");
    f.screen_on();
    let polled = f.poll(
        &work,
        body(&[("uid-2@work", 1, "review")], "v2"),
        Some(&ClearScreener as &dyn CalendarBodyScreener),
    );
    assert_settles(&polled, "(a)+(b) the screen on, uid-1 left out");
}

#[test]
fn each_claim_an_omission_poll_left_waiting_settles_alone() {
    let f = Fixture::open();
    let work = f.granted_feed("work", "uid-1@work");
    let polled = f.poll(&work, body(&[("uid-2@work", 1, "review")], "v2"), None);
    let before = f.claims("uid-1@work");
    let mut lines = Vec::new();
    let mut refused = 0;
    for (id, predicate, approval, lifecycle) in &before {
        if *approval != ClaimApprovalStatus::Proposed || *lifecycle != ClaimLifecycleStatus::Active
        {
            continue;
        }
        let settled = f.settle_alone(*id);
        if settled.is_err() {
            refused += 1;
        }
        lines.push(format!("{predicate} {}: {settled:?}", id.to_hex()));
    }
    let after = f.claims("uid-1@work");
    assert_eq!(
        refused,
        0,
        "poll: {polled:?}\nuid-1 claims after the poll: {before:?}\nsettled alone:\n{}\nafter: {after:?}",
        lines.join("\n")
    );
}
