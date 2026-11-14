//! Review round 1 of census L2-17 PR 1 (REVIEW-7782 P1 quota.rs:310): a
//! Gmail import step charges every request before it is made, the requests
//! one call makes past its first included. Gmail reads a text part it keeps
//! apart by its own request, and a label change in its change feed names the
//! labels it changed, not where the message stands now, so the message is
//! read again. Main charges each call once: a whole-message read with two
//! parts kept apart spends 100 units while the meter counts 60, and Gmail's
//! wire reads each relabeled message inside its history call, uncharged.
//!
//! The provider is a fake Gmail wire that reads each part kept apart through
//! the charge the step gives it, as Gmail's wire does, checks its credential
//! before its first request as Gmail's does, and logs each request it makes;
//! the units are counted from that log at Gmail's costs.
//!
//! Public paths only:
//! `cargo test --locked -p oneiron --all-features --test mail_gmail_quota_requests`.

#[path = "mail_gmail_quota/fixture.rs"]
mod fixture;

use std::cell::{Cell, RefCell};

use fixture::{Mailbox, OWNER_ADDRESS, TestResult, now};
use oneiron::mail_pack::{
    GMAIL_MAIL_QUOTA, MailAttachmentRef, MailCall, MailFull, MailHeaders, MailHistoryChange,
    MailHistoryPage, MailHistoryRead, MailIdPage, MailListQuery, MailMessageRef, MailProviderWire,
    MailQuota, MailSyncBudget, MailSyncSource,
};

/// The units Gmail gives one user a minute.
const MINUTE_UNITS: u64 = 6_000;
/// The share of the minute the copy may spend: 75% of it.
const COPY_UNITS: u64 = 4_500;
/// The messages one listing page names.
const PAGE_SIZE: u32 = 100;
/// The text parts Gmail keeps apart in each message.
const APART_PARTS: usize = 2;

/// A fake Gmail mailbox of `messages` messages, newest first, each with two
/// text parts kept apart, whose change feed reports `relabeled` label
/// changes; it logs each request it makes.
struct PartsFake {
    messages: u32,
    relabeled: u32,
    /// When the newest message was received.
    newest_at: u64,
    /// Whether the credential check before the first request was made.
    checked: Cell<bool>,
    requests: RefCell<Vec<MailCall>>,
}

impl PartsFake {
    fn new(messages: u32, relabeled: u32) -> Self {
        Self {
            messages,
            relabeled,
            newest_at: now(),
            checked: Cell::new(false),
            requests: RefCell::new(Vec::new()),
        }
    }

    /// Logs one request, and before the first the credential check, which
    /// reads the profile (the anchor's own request needs no other).
    fn request(&self, call: MailCall) {
        if !self.checked.replace(true) && call != MailCall::Anchor {
            self.requests.borrow_mut().push(MailCall::Anchor);
        }
        self.requests.borrow_mut().push(call);
    }

    fn requests(&self) -> Vec<MailCall> {
        self.requests.borrow().clone()
    }

    fn count(&self, call: MailCall) -> usize {
        self.requests
            .borrow()
            .iter()
            .filter(|made| **made == call)
            .count()
    }

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
            labels: vec!["INBOX".to_owned()],
            sent_by_mailbox: false,
            trash_or_spam: false,
            draft: false,
        }
    }
}

impl MailProviderWire for PartsFake {
    fn current_anchor(&self, _source: &MailSyncSource) -> oneiron::Result<String> {
        self.request(MailCall::Anchor);
        Ok("100".to_owned())
    }

    fn list_page(
        &self,
        _source: &MailSyncSource,
        _query: &MailListQuery,
        page: Option<&str>,
    ) -> oneiron::Result<MailIdPage> {
        self.request(MailCall::ListPage);
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
        self.request(MailCall::Headers);
        Ok(Self::index(provider_id).map(|index| self.headers_of(index)))
    }

    fn full(
        &self,
        source: &MailSyncSource,
        provider_id: &str,
    ) -> oneiron::Result<Option<MailFull>> {
        self.full_charging(source, provider_id, &|_| Ok(()))
    }

    fn full_charging(
        &self,
        _source: &MailSyncSource,
        provider_id: &str,
        charge: &dyn Fn(MailCall) -> oneiron::Result<()>,
    ) -> oneiron::Result<Option<MailFull>> {
        self.request(MailCall::Full);
        let Some(index) = Self::index(provider_id) else {
            return Ok(None);
        };
        // Each part kept apart is its own request, charged before it is
        // made.
        let mut parts = Vec::new();
        for part in 0..APART_PARTS {
            charge(MailCall::Attachment)?;
            self.request(MailCall::Attachment);
            parts.push(format!("Part {part} of note {index}."));
        }
        Ok(Some(MailFull {
            headers: self.headers_of(index),
            body_text: Some(parts.join("\n")),
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
        self.request(MailCall::History);
        Ok(MailHistoryRead::Page(MailHistoryPage {
            changes: (0..self.relabeled)
                .map(|index| MailHistoryChange::Relabeled {
                    provider_id: format!("m{index:04}"),
                })
                .collect(),
            next_page: None,
            anchor: if self.relabeled == 0 {
                anchor.to_owned()
            } else {
                "200".to_owned()
            },
        }))
    }

    fn attachment(
        &self,
        _source: &MailSyncSource,
        _provider_id: &str,
        _attachment: &MailAttachmentRef,
    ) -> oneiron::Result<Option<Vec<u8>>> {
        self.request(MailCall::Attachment);
        Ok(None)
    }

    fn quota(&self) -> Option<MailQuota> {
        Some(GMAIL_MAIL_QUOTA)
    }
}

/// The units `requests` cost at Gmail's costs.
fn units(requests: &[MailCall]) -> u64 {
    requests
        .iter()
        .map(|call| u64::from(GMAIL_MAIL_QUOTA.costs.of(*call)))
        .sum()
}

/// The reviewer's case: whole-message reads with two text parts kept apart
/// each. Main admits each read at 60 units and spends 100, so a minute of
/// body reads runs past Gmail's quota before the meter's own ceiling.
#[test]
fn text_parts_kept_apart_are_charged_before_each_is_read() -> TestResult {
    let mailbox = Mailbox::connect()?;
    let wire = PartsFake::new(60, 0);
    let budget = MailSyncBudget {
        history_pages: 1,
        list_pages: 10,
        bodies: 500,
        attachments: 0,
    };
    let report = mailbox.step(&wire, budget)?;
    let requests = wire.requests();
    let copy: Vec<MailCall> = requests
        .iter()
        .copied()
        .filter(|call| !matches!(call, MailCall::Anchor | MailCall::History))
        .collect();
    assert!(
        wire.count(MailCall::Attachment) > 0,
        "the step reads bodies with their parts: {requests:?}"
    );
    assert!(
        units(&copy) <= COPY_UNITS,
        "the copy spends at most three quarters of the minute, parts included: {} units in \
         {} requests",
        units(&copy),
        copy.len()
    );
    assert!(
        units(&requests) <= MINUTE_UNITS,
        "the step spends at most the minute: {} units",
        units(&requests)
    );
    assert!(
        report.quota_paused_until.is_some(),
        "the step stops where the next request does not fit: {report:?}"
    );
    Ok(())
}

/// A change-feed page of more label changes than a minute reads: each
/// relabeled message is read as one charged request, and one never copied
/// lands from that read.
#[test]
fn each_relabeled_message_is_read_as_one_charged_request() -> TestResult {
    let mailbox = Mailbox::connect()?;
    let wire = PartsFake::new(0, 400);
    let report = mailbox.step(&wire, MailSyncBudget::default())?;
    let requests = wire.requests();
    assert!(
        units(&requests) <= MINUTE_UNITS,
        "the step spends at most the minute: {} units in {} requests",
        units(&requests),
        requests.len()
    );
    let reads = wire.count(MailCall::Headers);
    assert!(
        reads > 0 && reads < 400,
        "the step reads relabeled messages until the minute is spent: {reads} reads"
    );
    assert_eq!(
        report.landed, reads as u64,
        "each message out of trash and spam never copied lands from its one read: {report:?}"
    );
    assert!(
        report.quota_paused_until.is_some(),
        "the step pauses where the next read does not fit: {report:?}"
    );
    Ok(())
}
