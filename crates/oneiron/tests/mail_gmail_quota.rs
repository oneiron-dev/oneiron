//! Census L2-17 PR 1 (MAIL-GOOGLE = A, ARCH-0027 #mail-drive): one import
//! step of a Gmail mailbox spends within Gmail's per-user quota. The change
//! feed may take the whole 6,000-unit minute, the copy three quarters of it;
//! downloads stop before the 2,500 MB day; a rate-limit answer rests the
//! source a minute. A step out of quota ends as a pause, not a failure, and
//! a resting source makes no provider call and is not due.
//!
//! The provider is a fake Gmail wire that declares Gmail's quota and logs
//! each call; the units are counted from that log at Gmail's costs.
//!
//! Public paths only:
//! `cargo test --locked -p oneiron --all-features --test mail_gmail_quota`.

use std::cell::{Cell, RefCell};
use std::sync::Arc;

use oneiron::authority::{HostSlipIssuer, MachineRole};
use oneiron::mail_pack::source::{active_sources, due_sources};
use oneiron::mail_pack::{
    GMAIL_MAIL_QUOTA, MAIL_WIRE_RATE_LIMITED, MailAttachmentRef, MailCall, MailCallCosts,
    MailCopySetting, MailFull, MailHeaders, MailHistoryPage, MailHistoryRead, MailIdPage,
    MailListQuery, MailMessageRef, MailProvider, MailProviderWire, MailQuota,
    MailSourceConnectRequest, MailSourceKind, MailSourceRef, MailSyncBudget, MailSyncReport,
    MailSyncSource,
};
use oneiron::secret_custody::{SECRET_CUSTODY_SCHEMA_VERSION, decode_secret_custody_body};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// The mailbox's address and the custody record its credential is under.
const OWNER_ADDRESS: &str = "owen@example.com";
const CUSTODY_REF: &str = "test-gmail-quota-cred";
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
    calls: RefCell<Vec<MailCall>>,
    read: Cell<u64>,
}

impl GmailFake {
    fn new(messages: u32, quota: MailQuota, full_bytes: u64) -> Self {
        Self {
            quota,
            messages,
            newest_at: now(),
            full_bytes,
            rate_limit_next_headers: Cell::new(false),
            calls: RefCell::new(Vec::new()),
            read: Cell::new(0),
        }
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
            labels: vec!["INBOX".to_owned()],
            sent_by_mailbox: false,
            trash_or_spam: false,
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

/// Unix seconds now.
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

/// The units `calls` cost at `costs`.
fn units(calls: &[MailCall], costs: &MailCallCosts) -> u64 {
    calls.iter().map(|call| u64::from(costs.of(*call))).sum()
}

/// Whether `call` reads the change feed (or its anchor).
fn live(call: MailCall) -> bool {
    matches!(call, MailCall::Anchor | MailCall::History)
}

/// Registers the Gmail credential `CUSTODY_REF`, stored for the owner, as
/// the owner's custody door registers one.
fn register_mail_credential(vault: &Vault) -> TestResult {
    use rmpv::Value;
    let band = |min: u64, max: u64| {
        Value::Map(vec![
            (Value::from("min"), Value::from(min)),
            (Value::from("max"), Value::from(max)),
        ])
    };
    let floor = Value::Map(vec![
        (Value::from("portable"), band(0, 2)),
        (Value::from("device_bound"), band(0, 2)),
        (Value::from("cross_vault"), band(0, 0)),
        (Value::from("rotation_max_age_secs"), Value::Nil),
        (Value::from("env_bindings"), Value::Map(vec![])),
    ]);
    let binding = Value::Map(vec![
        (Value::from("effector"), Value::from("connector:gmail")),
        (Value::from("tier_ceiling"), Value::from(0_u64)),
        (Value::from("scopes"), Value::Array(vec![])),
    ]);
    let body = Value::Map(vec![
        (
            Value::from("schema_version"),
            Value::from(u64::from(SECRET_CUSTODY_SCHEMA_VERSION)),
        ),
        (Value::from("name"), Value::from(CUSTODY_REF)),
        (Value::from("class"), Value::from("custody-portable")),
        (Value::from("device_only"), Value::from(false)),
        (
            Value::from("value_bytes"),
            Value::Binary(b"test-gmail-token".to_vec()),
        ),
        (Value::from("status"), Value::from("active")),
        (Value::from("registered_at"), Value::from(1_u64)),
        (Value::from("rotated_at"), Value::Nil),
        (Value::from("rotation_generation"), Value::from(0_u64)),
        (Value::from("bindings"), Value::Array(vec![binding])),
        (Value::from("manifest_ref"), Value::from("")),
        (Value::from("declared_paths"), Value::Array(vec![])),
        (Value::from("policy_floor_snapshot"), floor),
        (Value::from("model_reveal_allowed"), Value::from(true)),
    ]);
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &body)?;
    vault.register_secret(decode_secret_custody_body(&bytes)?)?;
    Ok(())
}

/// A vault with the mail pack installed and the owner's Gmail mailbox
/// connected, copying all mail.
struct Mailbox {
    _directory: tempfile::TempDir,
    vault: Vault,
    owner: EntityId,
    source: EntityId,
}

impl Mailbox {
    fn connect() -> Result<Self, Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        // The pack installs as the embedded owner, whose proof needs the
        // vault's writer lease: open it owned, and start the host as a
        // server does.
        let vault = Vault::open_owned(directory.path(), VaultConfig::default())?;
        let owner = vault.ensure_embedded_owner_actor()?;
        let issuer = HostSlipIssuer::from_secret(b"mail gmail quota test host")?;
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        vault.ensure_host_root_slip(&issuer)?;
        vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
        let memory = vault.memory(owner, EdgeActorClass::Human);
        oneiron::mail_pack::install_mail_calendar_pack_embedded(&memory)?;
        register_mail_credential(&vault)?;
        let connected = memory.mail_sources_connect(&MailSourceConnectRequest {
            provider: MailProvider::Google,
            kind: MailSourceKind::PersonalMailbox,
            address: OWNER_ADDRESS.to_owned(),
            provider_account: OWNER_ADDRESS.to_owned(),
            custody_ref: CUSTODY_REF.to_owned(),
            members: Vec::new(),
            for_person: None,
            channel_identity_ref: None,
            copy: Some(MailCopySetting::All),
            on_provider_delete: None,
            calendar_details: None,
        })?;
        let source = EntityId::from_hex(&connected.source.source_ref)?;
        Ok(Self {
            _directory: directory,
            vault,
            owner,
            source,
        })
    }

    /// One import step through `wire`, as the owner's
    /// `vault.mail.sources.sync` runs it.
    fn step(
        &self,
        wire: &GmailFake,
        budget: MailSyncBudget,
    ) -> Result<MailSyncReport, Box<dyn std::error::Error>> {
        let memory = self.vault.memory(self.owner, EdgeActorClass::Human);
        let owner = memory.embedded_owner("vault.mail.sources.sync")?;
        Ok(self
            .vault
            .mail_sync_step(&owner, self.source, wire, budget)?)
    }

    fn status(&self) -> Result<oneiron::mail_pack::MailSyncStatusView, Box<dyn std::error::Error>> {
        let memory = self.vault.memory(self.owner, EdgeActorClass::Human);
        Ok(memory.mail_sources_sync_status(&MailSourceRef {
            source_ref: self.source.to_hex(),
        })?)
    }

    fn due(&self) -> Result<bool, Box<dyn std::error::Error>> {
        Ok(due_sources(&self.vault)?
            .iter()
            .any(|(source, _)| *source == self.source))
    }
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
