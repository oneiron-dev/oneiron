//! Probe 2 for FIX ICS-FEED-TURN-GREEN-POLL-GATE-PENDING (scratch branch, no PR).
//!
//! `calendar_ics_feed_uninstall_waits_for_poll` failed on #9278's head: the
//! granted feed's second poll returned "gate write rejected: outcome=pending,
//! reasons=[gate.pending.actor_ceiling, gate.pending.source_trust]". Probe 1
//! (`calendar_ics_feed_absence_under_consent`) showed that the screen dial on
//! with a body that omits the owner-approved uid-1 settles by itself. The
//! failing test differs from that passing case in three ways: its uid-2 has
//! uid-1's SUMMARY and times, its screener waits two seconds inside the
//! admission, and an uninstall on a second thread waits on the admission
//! turn meanwhile. Each test here keeps a subset of the three.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test calendar_ics_feed_turn_probe`.
#![cfg(oneiron_test_support)]

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use oneiron::calendar::ingest::feed_door::{
    self as feed, CalendarIcsFeedConsent, CalendarIcsFeedRequest, CalendarIcsFeedReviewDecision,
    CalendarIcsFeedReviewRequest, CalendarIcsPollResult,
};
use oneiron::calendar::ingest::{IcsFeedFetcher, IcsFeedPollConfig, IcsFetchResponse};
use oneiron::calendar::{
    CALENDAR_SAFEGUARD_CONFIG_KEY, CalendarBodyScreener, CalendarError, CalendarInboundBody,
    CalendarScreenVerdict,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::{KeyValuePut, Memory};
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingCaller};
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;

const FEED: &str = "calendar.ics_feed";

/// The failing test's wait inside the screen.
const CLEAR_WAIT: Duration = Duration::from_secs(2);

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

    /// Installs `system`, polls uid-1 ("standup") once and approves the
    /// review: the feed holds its standing consent.
    fn granted_feed(&self, system: &str) -> IcsFeedPollConfig {
        let config = self.install(system);
        self.poll(&config, body(&[("uid-1@work", "standup")], "v1"), None)
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
}

/// Screens every body clear at once.
struct ClearScreener;

impl CalendarBodyScreener for ClearScreener {
    fn screen(&self, _body: &CalendarInboundBody) -> oneiron::Result<CalendarScreenVerdict> {
        Ok(CalendarScreenVerdict::Clear)
    }
}

/// Waits [`CLEAR_WAIT`] on its first call, as the failing test's screener
/// does when no clear commits; every body screens clear.
struct SlowScreener {
    calls: AtomicUsize,
}

impl CalendarBodyScreener for SlowScreener {
    fn screen(&self, _body: &CalendarInboundBody) -> oneiron::Result<CalendarScreenVerdict> {
        if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
            std::thread::sleep(CLEAR_WAIT);
        }
        Ok(CalendarScreenVerdict::Clear)
    }
}

/// The failing test's screener: on its first call it lets the clear thread
/// go and waits [`CLEAR_WAIT`] for its clear to commit.
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

/// A complete VCALENDAR body: one VEVENT per `(uid, summary)`, each at the
/// failing test's one time.
fn body(events: &[(&str, &str)], etag: &str) -> IcsFetchResponse {
    let mut out = String::from("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//oneiron//test//EN\r\n");
    for (uid, summary) in events {
        out.push_str("BEGIN:VEVENT\r\n");
        out.push_str(&format!("UID:{uid}\r\n"));
        out.push_str("DTSTAMP:20260805T100000Z\r\n");
        out.push_str("DTSTART:20260806T140000Z\r\n");
        out.push_str("DTEND:20260806T150000Z\r\n");
        out.push_str("SEQUENCE:1\r\n");
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

/// The failing test's poll with its uninstall thread, uid-2 named `summary`.
fn poll_with_blocked_clear(summary: &str) -> (Result<CalendarIcsPollResult, String>, bool) {
    let f = Fixture::open();
    let work = f.granted_feed("work");
    f.screen_on();
    let (go, go_wait) = channel::<()>();
    let (cleared, cleared_wait) = channel::<()>();
    let screener = ClearingScreener {
        go: Mutex::new(Some(go)),
        cleared: Mutex::new(cleared_wait),
        calls: AtomicUsize::new(0),
        cleared_inside_admission: AtomicBool::new(false),
    };
    let polled = std::thread::scope(|scope| {
        let owner = &f;
        scope.spawn(move || {
            if go_wait.recv().is_err() {
                return;
            }
            owner.uninstall("work");
            let _ = cleared.send(());
        });
        let polled = f.poll(
            &work,
            body(&[("uid-2@work", summary)], "v2"),
            Some(&screener as &dyn CalendarBodyScreener),
        );
        drop(screener.go.lock().expect("go").take());
        polled
    });
    (
        polled,
        screener.cleared_inside_admission.load(Ordering::SeqCst),
    )
}

#[test]
fn same_summary_alone_settles() {
    let f = Fixture::open();
    let work = f.granted_feed("work");
    f.screen_on();
    let polled = f.poll(
        &work,
        body(&[("uid-2@work", "standup")], "v2"),
        Some(&ClearScreener as &dyn CalendarBodyScreener),
    );
    assert_settles(
        &polled,
        "uid-2 with uid-1's summary and times, no wait, no clear",
    );
}

#[test]
fn slow_screen_alone_settles() {
    let f = Fixture::open();
    let work = f.granted_feed("work");
    f.screen_on();
    let screener = SlowScreener {
        calls: AtomicUsize::new(0),
    };
    let polled = f.poll(
        &work,
        body(&[("uid-2@work", "review")], "v2"),
        Some(&screener as &dyn CalendarBodyScreener),
    );
    assert_settles(&polled, "a 2 s screen, uid-2 its own summary, no clear");
}

#[test]
fn slow_screen_with_same_summary_settles() {
    let f = Fixture::open();
    let work = f.granted_feed("work");
    f.screen_on();
    let screener = SlowScreener {
        calls: AtomicUsize::new(0),
    };
    let polled = f.poll(
        &work,
        body(&[("uid-2@work", "standup")], "v2"),
        Some(&screener as &dyn CalendarBodyScreener),
    );
    assert_settles(
        &polled,
        "a 2 s screen, uid-2 with uid-1's summary, no clear",
    );
}

#[test]
fn blocked_clear_with_own_summary_settles() {
    let (polled, cleared_inside) = poll_with_blocked_clear("review");
    assert_settles(
        &polled,
        &format!("the uninstall thread, uid-2 its own summary (cleared inside: {cleared_inside})"),
    );
}

#[test]
fn blocked_clear_with_same_summary_settles() {
    let (polled, cleared_inside) = poll_with_blocked_clear("standup");
    assert_settles(
        &polled,
        &format!(
            "the uninstall thread, uid-2 with uid-1's summary: the failing test's own case \
             (cleared inside: {cleared_inside})"
        ),
    );
}
