//! ICS-FEED-UNINSTALL-SHAPE = B (Engine ruling 18:27, Mon 16 Nov), on
//! CAL-02-FEED-CONSENT = A ("uninstalling or killing the feed ends it"): the
//! owner uninstalls an ICS feed by clearing its `calendar.ics_feed` item.
//!
//! The clear ends the feed's standing consent, so no later poll settles under
//! it, not even one whose fetch was out when the owner cleared the feed. It
//! cancels the feed's pending polls (a paused one too, with its pause
//! exception), keeps the claims the feed imported, and retires the system: a
//! new install there is refused. A clear by a caller that is not the owner is
//! refused and uninstalls nothing.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test calendar_ics_feed_uninstall`.
#![cfg(oneiron_test_support)]

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use oneiron::attempt_queue::{AttemptQueue, AttemptRecord, AttemptState, EnqueueOutcome};
use oneiron::calendar::CalendarError;
use oneiron::calendar::claims::PREDICATE_CALENDAR_ORIGIN;
use oneiron::calendar::ingest::feed_door::{
    self as feed, CalendarIcsFeedConsent, CalendarIcsFeedRequest, CalendarIcsFeedReviewDecision,
    CalendarIcsFeedReviewRequest, CalendarIcsPollResult,
};
use oneiron::calendar::ingest::{
    IcsFeedFetcher, IcsFeedPollConfig, IcsFetchResponse, enqueue_ics_feed_poll,
    ics_feed_cursor_snapshot, ics_feed_pause_exceptions,
};
use oneiron::calendar::passport::resolve_event_by_uid;
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::Memory;
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingCaller};
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimSource, EdgeActorClass, EntityId, Vault, VaultConfig,
};
use oneiron_keystore::MemoryKeystore;

const FEED: &str = "calendar.ics_feed";

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

    /// The owner's install of `system`, as the `calendar.ics_feed` setting.
    fn try_install(&self, system: &str) -> Result<IcsFeedPollConfig, String> {
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
                    ..SetSetting::vault_value(
                        FEED,
                        serde_json::to_value(&config).expect("feed config as JSON"),
                    )
                },
            )
            .map_err(|error| error.to_string())?;
        assert!(
            matches!(outcome, SetSettingOutcome::Applied { .. }),
            "the owner's install applies: {outcome:?}"
        );
        Ok(config)
    }

    fn install(&self, system: &str) -> IcsFeedPollConfig {
        self.try_install(system).expect("install the feed")
    }

    /// `caller` clears the `calendar.ics_feed` item `system`.
    fn clear_as(
        &self,
        caller: SettingCaller<'_>,
        system: &str,
    ) -> Result<SetSettingOutcome, String> {
        self.vault
            .set_setting(
                caller,
                SetSetting {
                    item: Some(system.to_owned()),
                    value: None,
                    ..SetSetting::vault_value(FEED, serde_json::Value::Null)
                },
            )
            .map_err(|error| error.to_string())
    }

    /// The owner uninstalls `system`.
    fn uninstall(&self, system: &str) {
        let outcome = self
            .clear_as(SettingCaller::Owner(&self.proof), system)
            .expect("the owner's clear uninstalls the feed");
        assert!(
            matches!(outcome, SetSettingOutcome::Applied { .. }),
            "the owner's clear applies: {outcome:?}"
        );
    }

    fn poll_with(
        &self,
        config: &IcsFeedPollConfig,
        fetcher: &dyn IcsFeedFetcher,
    ) -> Result<CalendarIcsPollResult, String> {
        feed::run_installed_poll(
            &self.memory(),
            &self.proof,
            fetcher,
            None,
            config,
            EntityId::now().to_hex(),
        )
        .map(|completion| completion.result)
        .map_err(|error| error.to_string())
    }

    fn poll(
        &self,
        config: &IcsFeedPollConfig,
        response: IcsFetchResponse,
    ) -> Result<CalendarIcsPollResult, String> {
        self.poll_with(config, &StubFetcher::with([response]))
    }

    fn installed(&self, system: &str) -> bool {
        feed::status(
            &self.memory(),
            &self.proof,
            &CalendarIcsFeedRequest {
                system: system.to_owned(),
            },
        )
        .expect("feed status")
        .is_some()
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

    /// Installs `system`, polls `uid` once and approves the review: the feed
    /// holds its standing consent.
    fn granted_feed(&self, system: &str, uid: &str) -> IcsFeedPollConfig {
        let config = self.install(system);
        self.poll(&config, complete(&[uid], "v1"))
            .expect("first poll");
        let CalendarIcsFeedConsent::AwaitingReview { review_ref, .. } = self.consent(system) else {
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

    /// The feed's pending poll row: the chain the approval started.
    fn pending_poll(&self, config: &IcsFeedPollConfig) -> AttemptRecord {
        match enqueue_ics_feed_poll(&self.vault, config.clone(), self.vault.now_recorded_at())
            .expect("read the feed's chain")
        {
            EnqueueOutcome::Existing(record) => record,
            other => panic!("expected the feed's pending poll, got {other:?}"),
        }
    }

    fn attempt_state(&self, record: &AttemptRecord) -> AttemptState {
        AttemptQueue::new(&self.vault)
            .get(record.id)
            .expect("read the attempt")
            .expect("the attempt row")
            .state
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

    fn has_event(&self, uid: &str) -> bool {
        resolve_event_by_uid(&self.vault, uid)
            .expect("resolve uid")
            .is_some()
    }
}

/// A scripted fetcher: replays queued responses; a fetch with none queued
/// fails.
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

/// A fetcher whose fetch is out while the owner uninstalls the feed: the
/// owner's clear commits before the provider's answer returns.
struct UninstallingFetcher<'a> {
    vault: &'a Vault,
    proof: &'a AuthenticatedOwner,
    system: String,
    response: Mutex<Option<IcsFetchResponse>>,
}

impl IcsFeedFetcher for UninstallingFetcher<'_> {
    fn fetch(
        &self,
        _secret_ref: &str,
        _if_none_match: Option<&str>,
    ) -> Result<IcsFetchResponse, CalendarError> {
        let outcome = self
            .vault
            .set_setting(
                SettingCaller::Owner(self.proof),
                SetSetting {
                    item: Some(self.system.clone()),
                    value: None,
                    ..SetSetting::vault_value(FEED, serde_json::Value::Null)
                },
            )
            .expect("the owner's clear lands while the fetch is out");
        assert!(
            matches!(outcome, SetSettingOutcome::Applied { .. }),
            "the owner's clear applies: {outcome:?}"
        );
        self.response
            .lock()
            .expect("response")
            .take()
            .ok_or_else(|| CalendarError::IcsFetch {
                reason: "the feed was fetched twice".to_owned(),
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

fn assert_approved_imports(claims: &[(EntityId, ClaimBody)], why: &str) {
    for (id, body) in claims {
        assert_eq!(
            body.approval,
            ClaimApprovalStatus::Approved,
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

#[test]
fn clearing_the_feed_setting_uninstalls_the_feed_and_ends_its_consent() {
    let f = Fixture::open();
    let work = f.granted_feed("work", "uid-1@work");
    let pending = f.pending_poll(&work);
    let waiting = f.attempt_state(&pending);
    assert!(
        matches!(waiting, AttemptState::Queued | AttemptState::Scheduled),
        "the approval's chain waits to run: {waiting:?}"
    );
    assert!(
        ics_feed_cursor_snapshot(&f.vault, &work)
            .expect("cursor read")
            .is_some(),
        "the first poll wrote the feed's cursor"
    );

    // An agent the owner never granted the setting verb cannot uninstall it.
    let refused = f.clear_as(SettingCaller::Agent(EntityId::now()), "work");
    assert!(
        refused.is_err(),
        "a clear by a caller that is not the owner is refused: {refused:?}"
    );
    assert!(f.installed("work"), "the refused clear uninstalled nothing");
    assert_eq!(
        f.attempt_state(&pending),
        waiting,
        "the refused clear cancelled nothing"
    );

    f.uninstall("work");
    assert!(!f.installed("work"), "the clear uninstalled the feed");
    assert_eq!(
        f.attempt_state(&pending),
        AttemptState::Cancelled,
        "the clear cancelled the feed's pending poll"
    );
    assert!(
        ics_feed_cursor_snapshot(&f.vault, &work)
            .expect("cursor read")
            .is_none(),
        "the clear deleted the feed's cursor"
    );

    // The next poll does not settle under the ended consent: it is refused
    // before any admission, and the body it fetched imports nothing.
    let next = f
        .poll(&work, complete(&["uid-1@work", "uid-2@work"], "v2"))
        .expect_err("an uninstalled feed does not poll");
    assert!(
        next.contains("not installed"),
        "refused as uninstalled, got: {next}"
    );
    assert!(
        !f.has_event("uid-2@work"),
        "no claim of the refused poll was admitted"
    );
    assert_approved_imports(
        &f.imported_claims("uid-1@work"),
        "the uninstall keeps the claims the feed imported",
    );

    let again = f.try_install("work").expect_err("the system stays retired");
    assert!(
        again.contains("earlier feed"),
        "refused as a used system, got: {again}"
    );
    f.install("work-2");
    assert_eq!(
        f.consent("work-2"),
        CalendarIcsFeedConsent::AwaitingFirstPoll,
        "a feed on a new system starts with no consent"
    );
}

#[test]
fn a_poll_whose_fetch_was_out_when_the_owner_uninstalled_settles_nothing() {
    let f = Fixture::open();
    let work = f.granted_feed("work", "uid-1@work");

    let fetcher = UninstallingFetcher {
        vault: &f.vault,
        proof: &f.proof,
        system: "work".to_owned(),
        response: Mutex::new(Some(complete(&["uid-1@work", "uid-2@work"], "v2"))),
    };
    let late = f
        .poll_with(&work, &fetcher)
        .expect_err("the poll reads the feed uninstalled under its turn");
    assert!(
        late.contains("not installed"),
        "refused as uninstalled, got: {late}"
    );
    assert!(
        !f.installed("work"),
        "the owner's clear uninstalled the feed"
    );
    assert!(
        !f.has_event("uid-2@work"),
        "the late poll admitted nothing under the ended consent"
    );
    assert!(
        ics_feed_cursor_snapshot(&f.vault, &work)
            .expect("cursor read")
            .is_none(),
        "the late poll wrote no cursor back"
    );
    assert_approved_imports(
        &f.imported_claims("uid-1@work"),
        "the uninstall keeps the claims the feed imported",
    );
}

#[test]
fn uninstalling_a_paused_feed_cancels_its_paused_poll_and_its_pause_exception() {
    let f = Fixture::open();
    let work = f.granted_feed("work", "uid-1@work");
    let pending = f.pending_poll(&work);

    let paused = f
        .poll(&work, IcsFetchResponse::CredentialReset)
        .expect("a provider reset pauses loudly");
    assert!(
        matches!(paused, CalendarIcsPollResult::PausedNeedsInput { .. }),
        "got {paused:?}"
    );
    assert_eq!(
        f.attempt_state(&pending),
        AttemptState::Paused,
        "the reset paused the feed's pending poll"
    );
    let systems = |f: &Fixture| -> Vec<String> {
        ics_feed_pause_exceptions(&f.vault)
            .expect("pause exceptions")
            .into_iter()
            .map(|exception| exception.system)
            .collect()
    };
    assert_eq!(systems(&f), vec!["work".to_owned()]);

    f.uninstall("work");
    assert_eq!(
        f.attempt_state(&pending),
        AttemptState::Cancelled,
        "the clear cancelled the paused poll"
    );
    assert!(
        systems(&f).is_empty(),
        "the uninstalled feed's pause exception is gone"
    );
}
