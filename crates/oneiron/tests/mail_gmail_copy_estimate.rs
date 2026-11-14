//! L3-16 PR 5 (ARCH-0063 #mail-copy: "At connect, the companion gives a real
//! time estimate from the mailbox size (`users.getProfile`,
//! `messagesTotal`)"): the step that takes a Gmail mailbox's anchor reads
//! its size from the same profile answer, and the source's status, like
//! each step's report, gives how long the copy has left at Gmail's pace:
//! 80 units a message not yet copied (its metadata read and its full read),
//! 60 a message waiting for its body, at the copy's 4,500 units a minute;
//! once whole reads show what a message downloads, the 2,500 MB day may
//! bind instead. A connected mailbox wakes its host, so that first step runs
//! at once.
//!
//! The provider is a fake Gmail wire that declares Gmail's quota and gives
//! a size of 10,000 messages with its anchor.
//!
//! Public paths only:
//! `cargo test --locked -p oneiron --all-features --test mail_gmail_copy_estimate`.

#[path = "mail_gmail_quota/fixture.rs"]
mod fixture;

use std::cell::Cell;

use fixture::{Mailbox, OWNER_ADDRESS, TestResult, now};
use oneiron::EdgeActorClass;
use oneiron::mail_pack::{
    GMAIL_MAIL_QUOTA, MailAttachmentRef, MailCopyBound, MailCopyEstimate, MailCopySetting,
    MailFull, MailHeaders, MailHistoryPage, MailHistoryRead, MailIdPage, MailListQuery,
    MailMessageRef, MailProvider, MailProviderWire, MailQuota, MailSourceConnectRequest,
    MailSourceKind, MailSourceSettingsRequest, MailSyncBudget, MailSyncSource, MailboxAnchor,
};
use tokio::sync::broadcast::error::TryRecvError;

/// The messages one listing page names, as Gmail's wire lists them.
const PAGE_SIZE: u32 = 100;
/// The size the fake's profile gives.
const MESSAGES_TOTAL: u64 = 10_000;

/// A fake Gmail mailbox of `messages` listed messages, newest first, behind
/// Gmail's quota, whose profile gives `size` with its anchor (none: the
/// trait's default, the anchor alone).
struct SizedFake {
    messages: u32,
    size: Option<u64>,
    newest_at: u64,
    /// The bytes each whole-message read answers.
    full_bytes: u64,
    read: Cell<u64>,
}

impl SizedFake {
    fn new(messages: u32, size: Option<u64>, full_bytes: u64) -> Self {
        Self {
            messages,
            size,
            newest_at: now(),
            full_bytes,
            read: Cell::new(0),
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

impl MailProviderWire for SizedFake {
    fn current_anchor(&self, _source: &MailSyncSource) -> oneiron::Result<String> {
        Ok("100".to_owned())
    }

    fn mailbox_anchor(&self, source: &MailSyncSource) -> oneiron::Result<MailboxAnchor> {
        let Some(size) = self.size else {
            return Ok(MailboxAnchor {
                anchor: self.current_anchor(source)?,
                messages_total: None,
            });
        };
        Ok(MailboxAnchor {
            anchor: "100".to_owned(),
            messages_total: Some(size),
        })
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
        Some(GMAIL_MAIL_QUOTA)
    }

    fn bytes_read(&self) -> u64 {
        self.read.get()
    }
}

/// A step's budget: `list_pages` listing pages and `bodies` bodies after
/// one change-feed page.
fn budget(list_pages: u32, bodies: u32) -> MailSyncBudget {
    MailSyncBudget {
        history_pages: 1,
        list_pages,
        bodies,
        attachments: 0,
    }
}

/// Sets the mailbox's copy setting, as the owner's
/// `vault.mail.sources.settings.set` does.
fn set_copy(mailbox: &Mailbox, copy: MailCopySetting) -> TestResult {
    let memory = mailbox.vault.memory(mailbox.owner, EdgeActorClass::Human);
    memory.mail_sources_settings_set(&MailSourceSettingsRequest {
        source_ref: mailbox.source.to_hex(),
        copy: Some(copy),
        on_provider_delete: None,
        calendar_details: None,
        status: None,
        own_addresses: None,
    })?;
    Ok(())
}

/// The estimate a step and the status read give, which must agree.
fn estimate_after_step(
    mailbox: &Mailbox,
    wire: &SizedFake,
    budget: MailSyncBudget,
) -> Result<Option<MailCopyEstimate>, Box<dyn std::error::Error>> {
    let report = mailbox.step(wire, budget)?;
    let status = mailbox.status()?;
    assert_eq!(
        report.copy_estimate, status.copy_estimate,
        "the step's report and the status read give one estimate: {report:?} / {status:?}"
    );
    Ok(status.copy_estimate)
}

#[test]
fn the_first_step_reads_the_mailbox_size_and_the_status_gives_the_copy_time() -> TestResult {
    let mailbox = Mailbox::connect()?;
    assert_eq!(
        mailbox.status()?.copy_estimate,
        None,
        "before any step the size is unknown"
    );
    let wire = SizedFake::new(300, Some(MESSAGES_TOTAL), 10_000);
    let before = now();
    let estimate = estimate_after_step(&mailbox, &wire, budget(0, 0))?
        .ok_or("the step read the size, so the status gives the copy time")?;
    let after = now();
    assert_eq!(estimate.messages_total, MESSAGES_TOTAL, "{estimate:?}");
    assert!(
        (before..=after).contains(&estimate.read_at),
        "read at the step: {estimate:?}"
    );
    assert!(!estimate.at_most, "all mail is copied: {estimate:?}");
    assert_eq!(estimate.bound, MailCopyBound::Units, "{estimate:?}");
    // 10,000 messages x 80 units at 4,500 units a minute: 10,666.7 s.
    assert_eq!(estimate.seconds_left, 10_667, "{estimate:?}");
    Ok(())
}

#[test]
fn landed_headers_and_waiting_bodies_shorten_the_time() -> TestResult {
    let mailbox = Mailbox::connect()?;
    let wire = SizedFake::new(300, Some(MESSAGES_TOTAL), 10_000);
    let estimate =
        estimate_after_step(&mailbox, &wire, budget(1, 0))?.ok_or("the step read the size")?;
    assert_eq!(mailbox.status()?.bodies_waiting, 100, "one page of headers");
    // 9,900 messages x 80 units and 100 bodies x 60, at 75 units a second.
    assert_eq!(estimate.seconds_left, 10_640, "{estimate:?}");
    assert_eq!(estimate.bound, MailCopyBound::Units, "{estimate:?}");
    Ok(())
}

#[test]
fn the_day_s_byte_cap_binds_once_bodies_show_their_size() -> TestResult {
    let mailbox = Mailbox::connect()?;
    let wire = SizedFake::new(300, Some(MESSAGES_TOTAL), 1_000_000);
    let estimate =
        estimate_after_step(&mailbox, &wire, budget(1, 2))?.ok_or("the step read the size")?;
    let status = mailbox.status()?;
    assert_eq!(
        (status.bodies, status.bodies_waiting),
        (2, 98),
        "{status:?}"
    );
    // 9,998 whole reads of 1,000,000 bytes at 2,500 MB a day: 345,530.9 s;
    // by units it would be 10,639 s.
    assert_eq!(estimate.bound, MailCopyBound::Bytes, "{estimate:?}");
    assert_eq!(estimate.seconds_left, 345_531, "{estimate:?}");
    Ok(())
}

#[test]
fn recent_months_gives_the_time_as_at_most() -> TestResult {
    let mailbox = Mailbox::connect()?;
    set_copy(&mailbox, MailCopySetting::RecentMonths { months: 3 })?;
    let wire = SizedFake::new(300, Some(MESSAGES_TOTAL), 10_000);
    let estimate =
        estimate_after_step(&mailbox, &wire, budget(0, 0))?.ok_or("the step read the size")?;
    assert!(
        estimate.at_most,
        "Gmail counts the whole mailbox: {estimate:?}"
    );
    assert_eq!(estimate.seconds_left, 10_667, "{estimate:?}");
    Ok(())
}

#[test]
fn search_only_gives_no_copy_time() -> TestResult {
    let mailbox = Mailbox::connect()?;
    set_copy(&mailbox, MailCopySetting::SearchOnly)?;
    let wire = SizedFake::new(300, Some(MESSAGES_TOTAL), 10_000);
    assert_eq!(
        estimate_after_step(&mailbox, &wire, budget(1, 0))?,
        None,
        "search only copies nothing"
    );
    Ok(())
}

#[test]
fn a_wire_without_a_size_gives_no_copy_time() -> TestResult {
    let mailbox = Mailbox::connect()?;
    let wire = SizedFake::new(300, None, 10_000);
    assert_eq!(
        estimate_after_step(&mailbox, &wire, budget(1, 0))?,
        None,
        "a provider whose anchor read gives no size (IMAP, Graph)"
    );
    assert!(mailbox.status()?.live, "the anchor was still taken");
    Ok(())
}

/// A connect request for the owner's own `kind` source at `address`.
fn connect_request(kind: MailSourceKind, address: &str) -> MailSourceConnectRequest {
    MailSourceConnectRequest {
        provider: MailProvider::Google,
        kind,
        address: address.to_owned(),
        provider_account: OWNER_ADDRESS.to_owned(),
        custody_ref: "test-gmail-quota-cred".to_owned(),
        members: Vec::new(),
        for_person: None,
        channel_identity_ref: None,
        copy: None,
        on_provider_delete: None,
        calendar_details: None,
    }
}

#[test]
fn connecting_a_mailbox_wakes_its_host() -> TestResult {
    let mailbox = Mailbox::connect()?;
    let mut wakes = mailbox.vault.subscribe_mail_source_wakes();
    let memory = mailbox.vault.memory(mailbox.owner, EdgeActorClass::Human);

    let second = memory.mail_sources_connect(&connect_request(
        MailSourceKind::PersonalMailbox,
        "owen.work@example.com",
    ))?;
    assert!(!second.resumed, "{second:?}");
    assert_eq!(
        wakes.try_recv().map(|source| source.to_hex()),
        Ok(second.source.source_ref.clone()),
        "a new mailbox wakes its host"
    );

    let again = memory.mail_sources_connect(&connect_request(
        MailSourceKind::PersonalMailbox,
        OWNER_ADDRESS,
    ))?;
    assert!(again.resumed, "{again:?}");
    assert_eq!(
        wakes.try_recv(),
        Ok(mailbox.source),
        "a mailbox connected again wakes its host"
    );

    memory.mail_sources_connect(&connect_request(MailSourceKind::Calendar, OWNER_ADDRESS))?;
    assert_eq!(
        wakes.try_recv(),
        Err(TryRecvError::Empty),
        "a calendar wakes no mail step"
    );
    Ok(())
}
