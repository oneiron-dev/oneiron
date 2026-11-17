//! An owner's uninstall of an ICS feed (clearing its `calendar.ics_feed` item,
//! ICS-FEED-UNINSTALL-SHAPE = B) waits for a running poll's admission (blind
//! review of #9278, P1 at poll.rs:428). A poll checks under the calendar
//! admission turn that its feed is still installed, then admits the body in
//! several writes and settles them under the feed's consent last. A clear that
//! committed between that check and the settle would end the consent after the
//! poll had written claims it can no longer settle. So the clear takes the
//! same turn before its write opens: it lands before the check (the poll then
//! writes nothing, as `calendar_ics_feed_uninstall` shows) or after the poll's
//! last write, which settles under the consent the clear then ends.
//!
//! The fixture screener runs inside the admission: it lets a second thread
//! clear the feed and waits [`CLEAR_WAIT`] for that clear to commit.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test calendar_ics_feed_uninstall_waits_for_poll`.
#![cfg(oneiron_test_support)]

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::time::Duration;

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
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::{KeyValuePut, Memory};
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingCaller};
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::{ClaimApprovalStatus, ClaimSource, EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;

const FEED: &str = "calendar.ics_feed";

/// How long the screener waits for the clear to commit inside the admission.
/// A clear that takes no turn commits in milliseconds.
const CLEAR_WAIT: Duration = Duration::from_secs(2);

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

    /// The owner's `calendar.ics_feed` change at the item `system`.
    fn set_feed(&self, system: &str, value: Option<serde_json::Value>) -> SetSettingOutcome {
        self.vault
            .set_setting(
                SettingCaller::Owner(&self.proof),
                SetSetting {
                    item: Some(system.to_owned()),
                    value,
                    ..SetSetting::vault_value(FEED, serde_json::Value::Null)
                },
            )
            .expect("the owner's feed change")
    }

    /// The owner installs `system`.
    fn install(&self, system: &str) -> IcsFeedPollConfig {
        let config = IcsFeedPollConfig {
            secret_ref: format!("ics-feed:{system}"),
            system: system.to_owned(),
            cadence_min_seconds: 300,
            cadence_max_seconds: 900,
        };
        let outcome = self.set_feed(
            system,
            Some(serde_json::to_value(&config).expect("feed config as JSON")),
        );
        assert!(
            matches!(outcome, SetSettingOutcome::Applied { .. }),
            "the owner's install applies: {outcome:?}"
        );
        config
    }

    /// The owner uninstalls `system`.
    fn uninstall(&self, system: &str) {
        let outcome = self.set_feed(system, None);
        assert!(
            matches!(outcome, SetSettingOutcome::Applied { .. }),
            "the owner's clear applies: {outcome:?}"
        );
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

    fn feed_row(&self, system: &str) -> Option<feed::CalendarIcsFeedStatus> {
        feed::status(
            &self.memory(),
            &self.proof,
            &CalendarIcsFeedRequest {
                system: system.to_owned(),
            },
        )
        .expect("feed status")
    }

    /// Installs `system`, polls `uid` once and approves the review: the feed
    /// holds its standing consent.
    fn granted_feed(&self, system: &str, uid: &str) -> IcsFeedPollConfig {
        let config = self.install(system);
        self.poll(&config, complete(&[uid], "v1"), None)
            .expect("first poll");
        let Some(CalendarIcsFeedConsent::AwaitingReview { review_ref, .. }) =
            self.feed_row(system).map(|row| row.consent)
        else {
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

    /// The owner turns the inbound screen on, so each admission calls the
    /// poll's screener.
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

    /// The imported claims on the EVENT `uid` names, each with its approval
    /// and source: every claim but its projector-written `calendar.origin`.
    fn imported_claims(&self, uid: &str) -> Vec<(ClaimApprovalStatus, Option<ClaimSource>)> {
        let event = resolve_event_by_uid(&self.vault, uid)
            .expect("resolve uid")
            .expect("event for uid");
        let claims: Vec<_> = self
            .vault
            .claims_for_subject(&event)
            .expect("claims for subject")
            .into_iter()
            .map(|id| {
                self.vault
                    .get_claim(&id)
                    .expect("get claim")
                    .expect("claim")
            })
            .filter(|body| body.predicate != PREDICATE_CALENDAR_ORIGIN)
            .map(|body| (body.approval, body.source))
            .collect();
        assert!(!claims.is_empty(), "the feed imported claims about {uid}");
        claims
    }
}

/// A screener that, on its first call, lets the clear thread go and waits
/// [`CLEAR_WAIT`] for its clear to commit; every body screens clear.
struct ClearingScreener {
    go: Mutex<Option<Sender<()>>>,
    cleared: Mutex<Receiver<()>>,
    calls: AtomicUsize,
    cleared_inside_admission: AtomicBool,
}

impl CalendarBodyScreener for ClearingScreener {
    fn screen(&self, _body: &CalendarInboundBody) -> oneiron::Result<CalendarScreenVerdict> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if let Some(go) = self.go.lock().expect("go").take() {
            go.send(()).expect("the clear thread waits for the screen");
            let committed = self
                .cleared
                .lock()
                .expect("cleared")
                .recv_timeout(CLEAR_WAIT)
                .is_ok();
            self.cleared_inside_admission
                .store(committed, Ordering::SeqCst);
        }
        Ok(CalendarScreenVerdict::Clear)
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

#[test]
fn an_uninstall_during_a_poll_admission_lands_after_its_last_write() {
    let f = Fixture::open();
    let work = f.granted_feed("work", "uid-1@work");
    f.screen_on();

    let (go, go_wait) = channel::<()>();
    let (cleared, cleared_wait) = channel::<()>();
    let screener = ClearingScreener {
        go: Mutex::new(Some(go)),
        cleared: Mutex::new(cleared_wait),
        calls: AtomicUsize::new(0),
        cleared_inside_admission: AtomicBool::new(false),
    };
    // The complete poll omits uid-1 (its sweep writes the absence) and admits
    // uid-2 (its screen runs inside the admission).
    let polled = std::thread::scope(|scope| {
        let owner = &f;
        scope.spawn(move || {
            if go_wait.recv().is_err() {
                return; // the screener never ran; the poll's asserts say why
            }
            owner.uninstall("work");
            let _ = cleared.send(());
        });
        let polled = f.poll(
            &work,
            complete(&["uid-2@work"], "v2"),
            Some(&screener as &dyn CalendarBodyScreener),
        );
        // A poll that never screened lets the clear thread end.
        drop(screener.go.lock().expect("go").take());
        polled
    });

    assert!(
        screener.calls.load(Ordering::SeqCst) > 0,
        "the poll screened uid-2 inside its admission"
    );
    assert!(
        !screener.cleared_inside_admission.load(Ordering::SeqCst),
        "the owner's clear waited for the poll's admission: it committed while the poll's \
         screener ran inside it"
    );
    let polled = polled.expect("the poll settles under the consent it was let through with");
    assert!(
        matches!(polled, CalendarIcsPollResult::Reenqueued { .. }),
        "the granted feed's poll settles and re-enqueues: {polled:?}"
    );
    assert!(
        f.feed_row("work").is_none(),
        "the clear landed once the poll's admission ended"
    );
    for (approval, source) in f.imported_claims("uid-2@work") {
        assert_eq!(
            approval,
            ClaimApprovalStatus::Approved,
            "the poll's import settled before the clear, and the clear kept it"
        );
        assert_eq!(
            source,
            Some(ClaimSource::Imported),
            "uid-2 keeps the imported tier"
        );
    }
}
