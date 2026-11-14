//! L3-16 PR 6 (L3-16-COPY-PACE = A, Engine 14 Nov 20:57; RESEARCH-1393
//! #backfill plans the copy at 75% of the per-user quota): each step of a
//! Gmail mailbox names when the host steps it again. A step that ran out of
//! its minute names the window's end; one that ended on its budget names
//! now; a mailbox that owes nothing, or a wire that paces nothing, names no
//! next step, and the host's periodic pass keeps it.
//!
//! The provider is a fake Gmail wire with Gmail's quota, or none.
//!
//! Public paths only:
//! `cargo test --locked -p oneiron --all-features --test mail_gmail_copy_pace`.

#[path = "mail_gmail_quota/fixture.rs"]
mod fixture;

use fixture::{Mailbox, OWNER_ADDRESS, TestResult, now};
use oneiron::mail_pack::{
    GMAIL_MAIL_QUOTA, MailAttachmentRef, MailFull, MailHeaders, MailHistoryPage, MailHistoryRead,
    MailIdPage, MailListQuery, MailMessageRef, MailProviderWire, MailQuota, MailSyncBudget,
    MailSyncSource,
};

/// The messages one listing page names, as Gmail's wire lists them.
const PAGE_SIZE: u32 = 100;

/// A fake Gmail mailbox of `messages` messages, newest first, behind
/// `quota`.
struct PacedFake {
    messages: u32,
    quota: Option<MailQuota>,
    newest_at: u64,
}

impl PacedFake {
    fn new(messages: u32, quota: Option<MailQuota>) -> Self {
        Self {
            messages,
            quota,
            newest_at: now(),
        }
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

impl MailProviderWire for PacedFake {
    fn current_anchor(&self, _source: &MailSyncSource) -> oneiron::Result<String> {
        Ok("100".to_owned())
    }

    fn list_page(
        &self,
        _source: &MailSyncSource,
        _query: &MailListQuery,
        page: Option<&str>,
    ) -> oneiron::Result<MailIdPage> {
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
        Ok(Self::index(provider_id).map(|index| self.headers_of(index)))
    }

    fn full(
        &self,
        _source: &MailSyncSource,
        provider_id: &str,
    ) -> oneiron::Result<Option<MailFull>> {
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
        Ok(MailHistoryRead::Page(MailHistoryPage {
            changes: Vec::new(),
            next_page: None,
            anchor: anchor.to_owned(),
        }))
    }

    fn attachment(
        &self,
        _source: &MailSyncSource,
        _provider_id: &str,
        _attachment: &MailAttachmentRef,
    ) -> oneiron::Result<Option<Vec<u8>>> {
        Ok(None)
    }

    fn quota(&self) -> Option<MailQuota> {
        self.quota
    }
}

/// One listing page and no bodies, after one change-feed page: about 2,000
/// units, under the copy's 4,500.
const ONE_PAGE: MailSyncBudget = MailSyncBudget {
    history_pages: 1,
    list_pages: 1,
    bodies: 0,
    attachments: 0,
};

#[test]
fn a_step_that_ran_out_of_its_minute_names_the_window_s_end_as_its_next_step() -> TestResult {
    let mailbox = Mailbox::connect()?;
    // Two pages of headers (4,013 units) and eight bodies fill the copy's
    // 4,500; the ninth body does not fit.
    let wire = PacedFake::new(300, Some(GMAIL_MAIL_QUOTA));
    let report = mailbox.step(&wire, MailSyncBudget::default())?;
    let paused = report
        .quota_paused_until
        .ok_or("the copy ran out of its minute")?;
    assert!(paused > now(), "{report:?}");
    assert_eq!(
        report.next_step_at,
        Some(paused),
        "the host steps it again when its window opens: {report:?}"
    );
    Ok(())
}

#[test]
fn a_step_that_ended_on_its_budget_names_now_as_its_next_step() -> TestResult {
    let mailbox = Mailbox::connect()?;
    let wire = PacedFake::new(300, Some(GMAIL_MAIL_QUOTA));
    let before = now();
    let report = mailbox.step(&wire, ONE_PAGE)?;
    let after = now();
    assert_eq!(report.quota_paused_until, None, "{report:?}");
    let next = report.next_step_at.ok_or("the copy owes more")?;
    assert!(
        (before..=after).contains(&next),
        "the host steps it again at once: {report:?}"
    );
    Ok(())
}

#[test]
fn a_mailbox_with_nothing_owed_names_no_next_step() -> TestResult {
    let mailbox = Mailbox::connect()?;
    let wire = PacedFake::new(0, Some(GMAIL_MAIL_QUOTA));
    let report = mailbox.step(&wire, ONE_PAGE)?;
    assert!(report.copy_done, "{report:?}");
    assert_eq!(
        report.next_step_at, None,
        "the periodic pass keeps a copied mailbox: {report:?}"
    );
    Ok(())
}

#[test]
fn a_wire_that_paces_nothing_names_no_next_step() -> TestResult {
    let mailbox = Mailbox::connect()?;
    let wire = PacedFake::new(300, None);
    let report = mailbox.step(&wire, ONE_PAGE)?;
    assert!(!report.copy_done, "{report:?}");
    assert_eq!(
        report.next_step_at, None,
        "a provider with no quota keeps the periodic pass's pace: {report:?}"
    );
    Ok(())
}
