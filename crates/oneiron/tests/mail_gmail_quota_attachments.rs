//! Review round 1 of census L2-17 PR 1 (REVIEW-7782 P1 quota.rs:310), the
//! attachment fetch: a Gmail import step charges each request an opened
//! attachment's fetch makes as what it is, before it is made. Gmail fetches
//! an attachment it keeps apart by its id, and reads the whole message for
//! one that rides inline in its part. The reviewed head charges every fetch
//! as one attachment read, 20 units, while an inline one's read spends 60.
//!
//! The provider is a fake Gmail wire with one message whose attachments all
//! ride inline: it reads the whole message for each through the charge the
//! step gives it, as Gmail's wire does, and logs each request it makes; the
//! units are counted from that log at Gmail's costs.
//!
//! Public paths only:
//! `cargo test --locked -p oneiron --all-features --test mail_gmail_quota_attachments`.

#[path = "mail_gmail_quota/fixture.rs"]
mod fixture;

use std::cell::{Cell, RefCell};

use fixture::{Mailbox, OWNER_ADDRESS, TestResult, now};
use oneiron::EdgeActorClass;
use oneiron::mail_pack::{
    GMAIL_MAIL_QUOTA, MailAttachmentOpenRequest, MailAttachmentRef, MailAttachmentState, MailCall,
    MailFull, MailHeaders, MailHistoryPage, MailHistoryRead, MailIdPage, MailInboxRequest,
    MailListQuery, MailMessageRef, MailProviderWire, MailQuota, MailSyncBudget, MailSyncSource,
};

/// The units Gmail gives one user a minute.
const MINUTE_UNITS: u64 = 6_000;
/// The inline attachments of the one message: a whole-message read for
/// each spends more than the minute.
const INLINE_ATTACHMENTS: u32 = 120;
/// The one message's provider id.
const MESSAGE_ID: &str = "m0000";

/// The MIME part id of inline attachment `index`.
fn part_id(index: u32) -> String {
    format!("1.{index}")
}

/// A fake Gmail mailbox of one message with `INLINE_ATTACHMENTS` attachments
/// riding inline; it logs each request it makes.
struct InlineFake {
    /// When the message was received.
    received_at: u64,
    /// Whether the credential check before the first request was made.
    checked: Cell<bool>,
    requests: RefCell<Vec<MailCall>>,
}

impl InlineFake {
    fn new() -> Self {
        Self {
            received_at: now(),
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

    fn headers(&self) -> MailHeaders {
        MailHeaders {
            provider_id: MESSAGE_ID.to_owned(),
            thread_id: Some("t0000".to_owned()),
            rfc_message_id: Some("<m0000@example.com>".to_owned()),
            in_reply_to: None,
            references: Vec::new(),
            from: Some("yuki@example.com".to_owned()),
            to: vec![OWNER_ADDRESS.to_owned()],
            cc: Vec::new(),
            reply_to: Vec::new(),
            subject: Some("Notes".to_owned()),
            date: Some(self.received_at),
            received_at: self.received_at,
            labels: vec!["INBOX".to_owned()],
            sent_by_mailbox: false,
            trash_or_spam: false,
            draft: false,
        }
    }
}

impl MailProviderWire for InlineFake {
    fn current_anchor(&self, _source: &MailSyncSource) -> oneiron::Result<String> {
        self.request(MailCall::Anchor);
        Ok("100".to_owned())
    }

    fn list_page(
        &self,
        _source: &MailSyncSource,
        _query: &MailListQuery,
        _page: Option<&str>,
    ) -> oneiron::Result<MailIdPage> {
        self.request(MailCall::ListPage);
        Ok(MailIdPage {
            messages: vec![MailMessageRef {
                provider_id: MESSAGE_ID.to_owned(),
                thread_id: Some("t0000".to_owned()),
            }],
            next_page: None,
        })
    }

    fn headers(
        &self,
        _source: &MailSyncSource,
        provider_id: &str,
    ) -> oneiron::Result<Option<MailHeaders>> {
        self.request(MailCall::Headers);
        Ok((provider_id == MESSAGE_ID).then(|| self.headers()))
    }

    fn full(
        &self,
        _source: &MailSyncSource,
        provider_id: &str,
    ) -> oneiron::Result<Option<MailFull>> {
        self.request(MailCall::Full);
        if provider_id != MESSAGE_ID {
            return Ok(None);
        }
        Ok(Some(MailFull {
            headers: self.headers(),
            body_text: Some("The notes are attached.".to_owned()),
            attachments: (0..INLINE_ATTACHMENTS)
                .map(|index| MailAttachmentRef {
                    part_id: part_id(index),
                    provider_attachment_id: None,
                    filename: Some(format!("note-{index}.txt")),
                    media_type: "text/plain".to_owned(),
                    size_bytes: 16,
                })
                .collect(),
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
            changes: Vec::new(),
            next_page: None,
            anchor: anchor.to_owned(),
        }))
    }

    fn attachment(
        &self,
        source: &MailSyncSource,
        provider_id: &str,
        attachment: &MailAttachmentRef,
    ) -> oneiron::Result<Option<Vec<u8>>> {
        self.attachment_charging(source, provider_id, attachment, &|_| Ok(()))
    }

    fn attachment_charging(
        &self,
        _source: &MailSyncSource,
        provider_id: &str,
        attachment: &MailAttachmentRef,
        charge: &dyn Fn(MailCall) -> oneiron::Result<()>,
    ) -> oneiron::Result<Option<Vec<u8>>> {
        // An inline attachment is read in its part of the whole message,
        // that read charged before it is made.
        charge(MailCall::Full)?;
        self.request(MailCall::Full);
        if provider_id != MESSAGE_ID {
            return Ok(None);
        }
        Ok(Some(
            format!("Note {} text.", attachment.part_id).into_bytes(),
        ))
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

/// A reader opens every inline attachment of one message, and the next step
/// fetches them: each fetch reads the whole message and is charged as that
/// read, so the fetches stop where the next does not fit, within the minute.
/// The reviewed head charges each as an attachment read and fetches all 120,
/// 7,200 units of reads.
#[test]
fn each_inline_attachment_fetch_is_charged_as_the_whole_message_it_reads() -> TestResult {
    let mailbox = Mailbox::connect()?;
    let wire = InlineFake::new();
    mailbox.step(
        &wire,
        MailSyncBudget {
            history_pages: 1,
            list_pages: 1,
            bodies: 1,
            attachments: 0,
        },
    )?;
    let memory = mailbox.vault.memory(mailbox.owner, EdgeActorClass::Human);
    let inbox = memory.mail_inbox(&MailInboxRequest {
        source_ref: Some(mailbox.source.to_hex()),
        include_source_deleted: false,
        cursor: None,
        limit: None,
    })?;
    let turn_ref = inbox
        .items
        .first()
        .map(|item| item.turn_ref.clone())
        .ok_or("the message lands in the owner's inbox")?;
    for index in 0..INLINE_ATTACHMENTS {
        let opened = memory.mail_attachments_open(&MailAttachmentOpenRequest {
            source_ref: mailbox.source.to_hex(),
            turn_ref: turn_ref.clone(),
            part_id: part_id(index),
        })?;
        assert_eq!(
            opened.state,
            MailAttachmentState::Waiting,
            "an opened attachment waits for the next step: {opened:?}"
        );
    }
    let before = wire.requests().len();
    let report = mailbox.step(
        &wire,
        MailSyncBudget {
            history_pages: 0,
            list_pages: 0,
            bodies: 0,
            attachments: INLINE_ATTACHMENTS,
        },
    )?;
    let requests = wire.requests();
    let fetches = requests
        .iter()
        .skip(before)
        .filter(|call| **call == MailCall::Full)
        .count() as u64;
    assert!(
        units(&requests) <= MINUTE_UNITS,
        "the two steps spend at most the minute: {} units, {fetches} fetches",
        units(&requests)
    );
    assert!(
        fetches > 0 && fetches < u64::from(INLINE_ATTACHMENTS),
        "the step fetches until the next whole-message read does not fit: {fetches} fetches"
    );
    assert_eq!(
        report.attachments_stored, fetches,
        "each fetch stores its attachment: {report:?}"
    );
    assert!(
        report.quota_paused_until.is_some(),
        "the step pauses where the next fetch does not fit: {report:?}"
    );
    Ok(())
}
