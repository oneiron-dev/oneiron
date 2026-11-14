//! Census L2-17 PR 1 (MAIL-GOOGLE = A, ARCH-0027 #mail-drive): one import
//! step of a Gmail mailbox spends within Gmail's per-user quota. The change
//! feed may take the whole 6,000-unit minute, the copy three quarters of it;
//! downloads stop before the 2,500 MB day; a rate-limit answer rests the
//! source a minute. A step out of quota ends as a pause, not a failure, and
//! a resting source makes no provider call and is not due.
//!
//! Review round 1 (REVIEW-7782): a step stopped part-way through a
//! change-feed page goes on after the changes it applied, and a step of a
//! source another step is under way on keeps that step's rest.
//!
//! The provider is a fake Gmail wire that declares Gmail's quota and logs
//! each call; the units are counted from that log at Gmail's costs.
//!
//! Public paths only:
//! `cargo test --locked -p oneiron --all-features --test mail_gmail_quota`.

#[path = "mail_gmail_quota/fixture.rs"]
mod fixture;

use std::cell::{Cell, RefCell};
use std::collections::BTreeSet;
use std::sync::mpsc;
use std::time::Duration;

use fixture::{Mailbox, OWNER_ADDRESS, TestResult, now};
use oneiron::mail_pack::source::active_sources;
use oneiron::mail_pack::{
    GMAIL_MAIL_QUOTA, MAIL_WIRE_RATE_LIMITED, MailAttachmentRef, MailCall, MailCallCosts, MailFull,
    MailHeaders, MailHistoryChange, MailHistoryPage, MailHistoryRead, MailIdPage, MailListQuery,
    MailMessageRef, MailProviderWire, MailQuota, MailSyncBudget, MailSyncSource,
};

/// The messages one listing page names, as Gmail's wire lists them.
const PAGE_SIZE: u32 = 100;
/// The share of the minute the copy may spend: 75% of Gmail's 6,000.
const COPY_UNITS: u64 = 4_500;

/// A fake Gmail mailbox of `messages` messages, newest first, behind
/// Gmail's quota (or `quota`), logging each call it answers.
struct GmailFake {
    quota: MailQuota,
    messages: u32,
    /// When the newest message was received.
    newest_at: u64,
    /// The bytes each whole-message read answers.
    full_bytes: u64,
    /// Whether the next header read answers Gmail's rate limit.
    rate_limit_next_headers: Cell<bool>,
    /// The messages still in spam.
    spam: RefCell<BTreeSet<u32>>,
    /// The changes the change feed's one page reports.
    feed: RefCell<Vec<MailHistoryChange>>,
    /// Holds each change-feed read until the test lets it go.
    gate: Option<HistoryGate>,
    calls: RefCell<Vec<MailCall>>,
    /// The message each header read named, in order.
    headers_read: RefCell<Vec<String>>,
    read: Cell<u64>,
}

/// A change-feed read held until the test lets it go: it says it began,
/// waits, then answers (Gmail's rate limit, or an empty page).
struct HistoryGate {
    began: mpsc::Sender<()>,
    go: mpsc::Receiver<()>,
    rate_limited: bool,
}

impl GmailFake {
    fn new(messages: u32, quota: MailQuota, full_bytes: u64) -> Self {
        Self {
            quota,
            messages,
            newest_at: now(),
            full_bytes,
            rate_limit_next_headers: Cell::new(false),
            spam: RefCell::new(BTreeSet::new()),
            feed: RefCell::new(Vec::new()),
            gate: None,
            calls: RefCell::new(Vec::new()),
            headers_read: RefCell::new(Vec::new()),
            read: Cell::new(0),
        }
    }

    /// An empty mailbox whose change-feed reads `gate` holds.
    fn gated(gate: HistoryGate) -> Self {
        Self {
            gate: Some(gate),
            ..Self::new(0, GMAIL_MAIL_QUOTA, 10_000)
        }
    }

    fn headers_read(&self) -> Vec<String> {
        self.headers_read.borrow().clone()
    }

    fn log(&self, call: MailCall) {
        self.calls.borrow_mut().push(call);
    }

    fn calls(&self) -> Vec<MailCall> {
        self.calls.borrow().clone()
    }

    /// The index `provider_id` names.
    fn index(provider_id: &str) -> Option<u32> {
        provider_id.strip_prefix('m')?.parse().ok()
    }

    fn headers_of(&self, index: u32) -> MailHeaders {
        let received_at = self.newest_at - u64::from(index) * 60;
        MailHeaders {
            provider_id: format!("m{index:04}"),
            thread_id: Some(format!("t{index:04}")),
            rfc_message_id: Some(format!("<m{index:04}@example.com>")),
            in_reply_to: None,
            references: Vec::new(),
            from: Some("yuki@example.com".to_owned()),
            to: vec![OWNER_ADDRESS.to_owned()],
            cc: Vec::new(),
            reply_to: Vec::new(),
            subject: Some(format!("Note {index}")),
            date: Some(received_at),
            received_at,
            labels: vec![if self.spam.borrow().contains(&index) {
                "SPAM".to_owned()
            } else {
                "INBOX".to_owned()
            }],
            sent_by_mailbox: false,
            trash_or_spam: self.spam.borrow().contains(&index),
            draft: false,
        }
    }
}

impl MailProviderWire for GmailFake {
    fn current_anchor(&self, _source: &MailSyncSource) -> oneiron::Result<String> {
        self.log(MailCall::Anchor);
        Ok("100".to_owned())
    }

    fn list_page(
        &self,
        _source: &MailSyncSource,
        _query: &MailListQuery,
        page: Option<&str>,
    ) -> oneiron::Result<MailIdPage> {
        self.log(MailCall::ListPage);
        let start: u32 = page.and_then(|page| page.parse().ok()).unwrap_or(0);
        let end = (start + PAGE_SIZE).min(self.messages);
        Ok(MailIdPage {
            messages: (start..end)
                .map(|index| MailMessageRef {
                    provider_id: format!("m{index:04}"),
                    thread_id: Some(format!("t{index:04}")),
                })
                .collect(),
            next_page: (end < self.messages).then(|| end.to_string()),
        })
    }

    fn headers(
        &self,
        _source: &MailSyncSource,
        provider_id: &str,
    ) -> oneiron::Result<Option<MailHeaders>> {
        self.log(MailCall::Headers);
        self.headers_read.borrow_mut().push(provider_id.to_owned());
        if self.rate_limit_next_headers.replace(false) {
            return Err(oneiron::Error::InvalidConfig(
                MAIL_WIRE_RATE_LIMITED.to_owned(),
            ));
        }
        Ok(Self::index(provider_id).map(|index| self.headers_of(index)))
    }

    fn full(
        &self,
        _source: &MailSyncSource,
        provider_id: &str,
    ) -> oneiron::Result<Option<MailFull>> {
        self.log(MailCall::Full);
        self.read.set(self.read.get() + self.full_bytes);
        Ok(Self::index(provider_id).map(|index| MailFull {
            headers: self.headers_of(index),
            body_text: Some(format!("The body of note {index}.")),
            attachments: Vec::new(),
            content_digest: None,
        }))
    }

    fn history(
        &self,
        _source: &MailSyncSource,
        anchor: &str,
        _page: Option<&str>,
    ) -> oneiron::Result<MailHistoryRead> {
        self.log(MailCall::History);
        if let Some(gate) = &self.gate {
            let _began = gate.began.send(());
            let _go = gate.go.recv_timeout(Duration::from_secs(30));
            if gate.rate_limited {
                return Err(oneiron::Error::InvalidConfig(
                    MAIL_WIRE_RATE_LIMITED.to_owned(),
                ));
            }
        }
        let changes = self.feed.borrow().clone();
        Ok(MailHistoryRead::Page(MailHistoryPage {
            // Once the page is applied the source stands past it.
            anchor: if changes.is_empty() {
                anchor.to_owned()
            } else {
                "200".to_owned()
            },
            changes,
            next_page: None,
        }))
    }

    fn attachment(
        &self,
        _source: &MailSyncSource,
        _provider_id: &str,
        _attachment: &MailAttachmentRef,
    ) -> oneiron::Result<Option<Vec<u8>>> {
        self.log(MailCall::Attachment);
        Ok(None)
    }

    fn quota(&self) -> Option<MailQuota> {
        Some(self.quota)
    }

    fn bytes_read(&self) -> u64 {
        self.read.get()
    }
}

/// The message ids `indexes` name.
fn ids(indexes: std::ops::Range<u32>) -> Vec<String> {
    indexes.map(|index| format!("m{index:04}")).collect()
}

/// The units `calls` cost at `costs`.
fn units(calls: &[MailCall], costs: &MailCallCosts) -> u64 {
    calls.iter().map(|call| u64::from(costs.of(*call))).sum()
}

/// Whether `call` reads the change feed (or its anchor).
fn live(call: MailCall) -> bool {
    matches!(call, MailCall::Anchor | MailCall::History)
}

#[test]
fn one_default_step_spends_at_most_the_minute_and_reports_the_pause() -> TestResult {
    let mailbox = Mailbox::connect()?;
    let wire = GmailFake::new(300, GMAIL_MAIL_QUOTA, 10_000);
    let before = now();
    let report = mailbox.step(&wire, MailSyncBudget::default())?;
    let calls = wire.calls();
    let costs = GMAIL_MAIL_QUOTA.costs;
    let copy: Vec<MailCall> = calls.iter().copied().filter(|call| !live(*call)).collect();
    // Main's default step reads 2 listing pages, 200 headers and 50 bodies:
    // about 7,010 units, past the minute.
    assert!(
        units(&copy, &costs) <= COPY_UNITS,
        "the copy spends at most three quarters of the minute: {} units in {} calls",
        units(&copy, &costs),
        copy.len()
    );
    assert!(
        units(&calls, &costs) <= u64::from(GMAIL_MAIL_QUOTA.units_per_minute),
        "the step spends at most the minute: {} units",
        units(&calls, &costs)
    );
    assert!(
        report.landed > 0,
        "the step lands what fits before it pauses: {report:?}"
    );
    let until = report
        .quota_paused_until
        .ok_or("a step that ran out of its minute reports its pause")?;
    assert!(
        until > before && until <= now() + 60,
        "the pause ends when the minute window opens again: {until} (step began {before})"
    );
    Ok(())
}

#[test]
fn a_paused_source_makes_no_provider_call_until_its_window_opens() -> TestResult {
    let mailbox = Mailbox::connect()?;
    let wire = GmailFake::new(300, GMAIL_MAIL_QUOTA, 10_000);
    assert!(mailbox.due()?, "a connected source is due before any step");
    let first = mailbox.step(&wire, MailSyncBudget::default())?;
    let until = first
        .quota_paused_until
        .ok_or("the first step spends the minute and pauses")?;
    let made = wire.calls().len();

    assert!(
        !mailbox.due()?,
        "a resting source is not due for the host's next pass"
    );
    assert!(
        active_sources(&mailbox.vault)?
            .iter()
            .any(|(source, _)| *source == mailbox.source),
        "it is still Active: it rests, it is not paused by its person"
    );
    let second = mailbox.step(&wire, MailSyncBudget::default())?;
    assert_eq!(
        wire.calls().len(),
        made,
        "a step of a resting source makes no provider call"
    );
    assert_eq!(
        second.quota_paused_until,
        Some(until),
        "it answers the same rest: {second:?}"
    );
    let status = mailbox.status()?;
    assert_eq!(status.quota_paused_until, Some(until), "{status:?}");
    assert_eq!(
        status.last_error, None,
        "a pause is not the source's failure"
    );
    Ok(())
}

#[test]
fn downloads_stop_at_the_daily_byte_cap() -> TestResult {
    let mailbox = Mailbox::connect()?;
    // No unit cost, so only the day's bytes bind; each body is 30 MB.
    let quota = MailQuota {
        costs: MailCallCosts::default(),
        ..GMAIL_MAIL_QUOTA
    };
    let full_bytes = 30_000_000;
    let wire = GmailFake::new(300, quota, full_bytes);
    let budget = MailSyncBudget {
        history_pages: 10,
        list_pages: 3,
        bodies: 500,
        attachments: 10,
    };
    let before = now();
    let report = mailbox.step(&wire, budget)?;
    let bodies = wire
        .calls()
        .iter()
        .filter(|call| **call == MailCall::Full)
        .count();
    // Main reads all 300 bodies: 9,000 MB.
    assert!(
        wire.bytes_read() <= quota.bytes_per_day,
        "the step never reads past the day's cap: {} bytes in {bodies} bodies",
        wire.bytes_read()
    );
    assert!(
        wire.bytes_read() + quota.largest_answer_bytes + full_bytes > quota.bytes_per_day,
        "it stops only when the day has no room for one more answer: {} bytes",
        wire.bytes_read()
    );
    let until = report
        .quota_paused_until
        .ok_or("a step that spent the day's bytes reports its pause")?;
    assert!(
        until >= before + 86_400 && until <= now() + 86_400,
        "it rests until the day window opens again: {until} (step began {before})"
    );
    Ok(())
}

#[test]
fn a_rate_limit_answer_pauses_the_source_without_an_error() -> TestResult {
    let mailbox = Mailbox::connect()?;
    let wire = GmailFake::new(300, GMAIL_MAIL_QUOTA, 10_000);
    wire.rate_limit_next_headers.set(true);
    let before = now();
    // Main ends this step with the provider's error.
    let report = mailbox.step(&wire, MailSyncBudget::default())?;
    assert_eq!(
        wire.calls(),
        vec![
            MailCall::Anchor,
            MailCall::History,
            MailCall::ListPage,
            MailCall::Headers
        ],
        "no call follows the rate-limit answer"
    );
    let until = report
        .quota_paused_until
        .ok_or("a rate-limited step reports its pause")?;
    assert!(
        until >= before + 60 && until <= now() + 60,
        "the source rests a minute: {until} (step began {before})"
    );
    let status = mailbox.status()?;
    assert_eq!(
        status.last_error, None,
        "the provider's rate limit is not the source's failure: {status:?}"
    );
    assert_eq!(status.quota_paused_until, Some(until), "{status:?}");
    assert!(!mailbox.due()?, "the resting source is not due");
    Ok(())
}

/// REVIEW-7782 P1 importer.rs:757: one change-feed page names more
/// messages still in spam than a minute's units read. Main's step pauses
/// before it keeps the page, so every later step reads the same messages
/// again and never reaches the inbox message after them.
#[test]
fn a_step_paused_mid_page_goes_on_after_the_changes_it_applied() -> TestResult {
    let mailbox = Mailbox::connect()?;
    // A minute of 100 units: the anchor (1), a history page (2) and four
    // metadata reads (80) fit; a fifth does not.
    let quota = MailQuota {
        units_per_minute: 100,
        ..GMAIL_MAIL_QUOTA
    };
    let wire = GmailFake::new(0, quota, 10_000);
    // Six messages still in spam, then one in the inbox, on one page.
    wire.spam.borrow_mut().extend(0..6);
    wire.feed.borrow_mut().extend((0..7).map(|index| {
        MailHistoryChange::Added(MailMessageRef {
            provider_id: format!("m{index:04}"),
            thread_id: Some(format!("t{index:04}")),
        })
    }));
    let first = mailbox.step(&wire, MailSyncBudget::default())?;
    let until = first
        .quota_paused_until
        .ok_or("the page outruns the minute and the step pauses")?;
    let read_first = wire.headers_read();
    assert_eq!(read_first, ids(0..4), "the first step reads four messages");

    // The minute window opens again.
    std::thread::sleep(Duration::from_secs(until.saturating_sub(now()) + 1));
    let second = mailbox.step(&wire, MailSyncBudget::default())?;
    let read_second = wire.headers_read().split_off(read_first.len());
    assert_eq!(
        read_second,
        ids(4..7),
        "the next step goes on after the four messages the first read: {second:?}"
    );
    assert_eq!(
        second.landed, 1,
        "the inbox message after them lands: {second:?}"
    );
    Ok(())
}

/// REVIEW-7782 P1 importer.rs:785: the owner's step starts while the host's
/// step of the same source is under way; the host's step is answered
/// Gmail's rate limit and rests the source. On main the owner's step, begun
/// from the windows before that rest, ends after it and writes its own over
/// it, so the next step calls Gmail inside the rest.
#[test]
fn a_concurrent_step_keeps_the_rest_a_rate_limit_answer_set() -> TestResult {
    let mailbox = Mailbox::connect()?;
    let (first_began, first_begins) = mpsc::channel();
    let (first_go, first_goes) = mpsc::channel();
    let (second_began, second_begins) = mpsc::channel();
    let (second_go, second_goes) = mpsc::channel();
    let mailbox = &mailbox;
    std::thread::scope(|scope| -> TestResult {
        let first = scope.spawn(move || {
            let wire = GmailFake::gated(HistoryGate {
                began: first_began,
                go: first_goes,
                rate_limited: true,
            });
            mailbox
                .step(&wire, MailSyncBudget::default())
                .map_err(|error| error.to_string())
        });
        first_begins.recv_timeout(Duration::from_secs(60))?;
        let second = scope.spawn(move || {
            let wire = GmailFake::gated(HistoryGate {
                began: second_began,
                go: second_goes,
                rate_limited: false,
            });
            let report = mailbox
                .step(&wire, MailSyncBudget::default())
                .map_err(|error| error.to_string());
            (report, wire.calls())
        });
        // On main the second step reads the feed while the first is under
        // way; here it waits for the first to end.
        let _second_began = second_begins.recv_timeout(Duration::from_secs(3));
        first_go.send(())?;
        let first = first.join().map_err(|_| "the first step panicked")??;
        let _second_go = second_go.send(());
        let (second, second_calls) = second.join().map_err(|_| "the second step panicked")?;
        let second = second?;

        let until = first
            .quota_paused_until
            .ok_or("the rate-limited step rests the source")?;
        assert_eq!(
            second_calls,
            Vec::<MailCall>::new(),
            "the second step makes no provider call while the source rests: {second:?}"
        );
        let status = mailbox.status()?;
        assert_eq!(
            status.quota_paused_until,
            Some(until),
            "the rest the first step set stands after the second ends: {status:?}"
        );
        assert!(!mailbox.due()?, "the resting source is not due");
        Ok(())
    })
}
