//! Census L2-17 PR 2 (MAIL-GOOGLE = A, ARCH-0027 #mail-drive, ARCH-0063
//! #mail-import): new mail arrives through Gmail push, with a reconcile
//! behind it. A host with a Pub/Sub topic opens a push channel for each
//! Active Gmail mailbox and renews it before Google closes it; a channel is
//! closed once its source leaves Active or the host drops its topic. A
//! notice wakes the mailbox it names while its stored change anchor is older
//! than the notice's, and the next step lands the new mail; a dropped notice
//! is reconciled by the host's next plain step.
//!
//! The provider is a fake Gmail wire that logs each call.
//!
//! Public paths only:
//! `cargo test --locked -p oneiron --all-features --test mail_gmail_push`.

use std::cell::{Cell, RefCell};
use std::sync::Arc;

use oneiron::authority::{HostSlipIssuer, MachineRole};
use oneiron::mail_pack::{
    GMAIL_MAIL_QUOTA, MailAttachmentRef, MailCopySetting, MailFull, MailHeaders, MailHistoryChange,
    MailHistoryPage, MailHistoryRead, MailIdPage, MailListQuery, MailMessageRef, MailProvider,
    MailProviderWire, MailQuota, MailSourceConnectRequest, MailSourceKind,
    MailSourceSettingsRequest, MailSourceStatus, MailSyncBudget, MailSyncReport, MailSyncSource,
    MailWatchAct,
};
use oneiron::secret_custody::{SECRET_CUSTODY_SCHEMA_VERSION, decode_secret_custody_body};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// The mailbox's address and the custody record its credential is under.
const OWNER_ADDRESS: &str = "owen@example.com";
const CUSTODY_REF: &str = "test-gmail-push-cred";
/// The host's Pub/Sub topic, and another one.
const TOPIC: &str = "projects/owen-mail/topics/gmail";
const OTHER_TOPIC: &str = "projects/owen-mail/topics/gmail-2";
/// The anchor the mailbox stands at before its new mail, and after.
const FIRST_ANCHOR: &str = "100";
const NEW_ANCHOR: &str = "105";
/// Seven days, Gmail's longest channel.
const WEEK_SECS: u64 = 7 * 86_400;

/// One call the fake answered.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Call {
    Anchor,
    List,
    Headers(String),
    Full(String),
    History(String),
    Attachment,
    Watch(String),
    StopWatch,
}

/// A fake Gmail mailbox at anchor 100 with no mail, which gains one new
/// message at anchor 105 once `arrive` is called; each call is logged.
struct PushFake {
    arrived: Cell<bool>,
    /// When the next channel `watch` opens closes.
    watch_expires_at: Cell<u64>,
    calls: RefCell<Vec<Call>>,
}

impl PushFake {
    fn new() -> Self {
        Self {
            arrived: Cell::new(false),
            watch_expires_at: Cell::new(now() + 3_600),
            calls: RefCell::new(Vec::new()),
        }
    }

    /// The new message arrives in the mailbox.
    fn arrive(&self) {
        self.arrived.set(true);
    }

    fn log(&self, call: Call) {
        self.calls.borrow_mut().push(call);
    }

    fn calls(&self) -> Vec<Call> {
        self.calls.borrow().clone()
    }

    fn headers_of(provider_id: &str) -> MailHeaders {
        let received_at = now();
        MailHeaders {
            provider_id: provider_id.to_owned(),
            thread_id: Some("t0001".to_owned()),
            rfc_message_id: Some("<m0001@example.com>".to_owned()),
            in_reply_to: None,
            references: Vec::new(),
            from: Some("yuki@example.com".to_owned()),
            to: vec![OWNER_ADDRESS.to_owned()],
            cc: Vec::new(),
            reply_to: Vec::new(),
            subject: Some("The new note".to_owned()),
            date: Some(received_at),
            received_at,
            labels: vec!["INBOX".to_owned()],
            sent_by_mailbox: false,
            trash_or_spam: false,
            draft: false,
        }
    }
}

impl MailProviderWire for PushFake {
    fn current_anchor(&self, _source: &MailSyncSource) -> oneiron::Result<String> {
        self.log(Call::Anchor);
        Ok(FIRST_ANCHOR.to_owned())
    }

    fn list_page(
        &self,
        _source: &MailSyncSource,
        _query: &MailListQuery,
        _page: Option<&str>,
    ) -> oneiron::Result<MailIdPage> {
        self.log(Call::List);
        Ok(MailIdPage {
            messages: Vec::new(),
            next_page: None,
        })
    }

    fn headers(
        &self,
        _source: &MailSyncSource,
        provider_id: &str,
    ) -> oneiron::Result<Option<MailHeaders>> {
        self.log(Call::Headers(provider_id.to_owned()));
        Ok((provider_id == "m0001" && self.arrived.get()).then(|| Self::headers_of(provider_id)))
    }

    fn full(
        &self,
        _source: &MailSyncSource,
        provider_id: &str,
    ) -> oneiron::Result<Option<MailFull>> {
        self.log(Call::Full(provider_id.to_owned()));
        Ok(
            (provider_id == "m0001" && self.arrived.get()).then(|| MailFull {
                headers: Self::headers_of(provider_id),
                body_text: Some("The body of the new note.".to_owned()),
                attachments: Vec::new(),
                content_digest: None,
            }),
        )
    }

    fn history(
        &self,
        _source: &MailSyncSource,
        anchor: &str,
        _page: Option<&str>,
    ) -> oneiron::Result<MailHistoryRead> {
        self.log(Call::History(anchor.to_owned()));
        let changes = if anchor == FIRST_ANCHOR && self.arrived.get() {
            vec![MailHistoryChange::Added(MailMessageRef {
                provider_id: "m0001".to_owned(),
                thread_id: Some("t0001".to_owned()),
            })]
        } else {
            Vec::new()
        };
        let anchor = if self.arrived.get() {
            NEW_ANCHOR
        } else {
            FIRST_ANCHOR
        };
        Ok(MailHistoryRead::Page(MailHistoryPage {
            changes,
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
        self.log(Call::Attachment);
        Ok(None)
    }

    fn watch(&self, _source: &MailSyncSource, topic: &str) -> oneiron::Result<u64> {
        self.log(Call::Watch(topic.to_owned()));
        Ok(self.watch_expires_at.get())
    }

    fn stop_watch(&self, _source: &MailSyncSource) -> oneiron::Result<()> {
        self.log(Call::StopWatch);
        Ok(())
    }

    fn quota(&self) -> Option<MailQuota> {
        Some(GMAIL_MAIL_QUOTA)
    }
}

/// Unix seconds now.
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
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
            Value::Binary(b"test-gmail-push-token".to_vec()),
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
        let issuer = HostSlipIssuer::from_secret(b"mail gmail push test host")?;
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

    /// One import step through `wire`, as the host's periodic pass and a
    /// woken source run it.
    fn step(&self, wire: &PushFake) -> Result<MailSyncReport, Box<dyn std::error::Error>> {
        let memory = self.vault.memory(self.owner, EdgeActorClass::Human);
        let owner = memory.embedded_owner("vault.mail.sources.sync")?;
        Ok(self
            .vault
            .mail_sync_step(&owner, self.source, wire, MailSyncBudget::default())?)
    }

    /// One act on the source's push channel under the host's `topic`.
    fn watch_step(
        &self,
        wire: &PushFake,
        topic: Option<&str>,
    ) -> Result<Option<MailWatchAct>, Box<dyn std::error::Error>> {
        Ok(self.vault.mail_watch_step(self.source, wire, topic)?)
    }

    /// Whether the source's push channel owes an act under `topic`.
    fn watch_due(&self, topic: Option<&str>) -> Result<bool, Box<dyn std::error::Error>> {
        Ok(self.vault.mail_watches_due(topic)?.contains(&self.source))
    }

    /// The mailboxes a Gmail notice for `address` at `anchor` wakes.
    fn notice(
        &self,
        address: &str,
        anchor: &str,
    ) -> Result<Vec<EntityId>, Box<dyn std::error::Error>> {
        Ok(self
            .vault
            .mail_push_notice(MailProvider::Google, address, anchor)?)
    }

    fn set_status(&self, status: MailSourceStatus) -> TestResult {
        let memory = self.vault.memory(self.owner, EdgeActorClass::Human);
        memory.mail_sources_settings_set(&MailSourceSettingsRequest {
            source_ref: self.source.to_hex(),
            copy: None,
            on_provider_delete: None,
            calendar_details: None,
            status: Some(status),
            own_addresses: None,
        })?;
        Ok(())
    }
}

#[test]
fn gmail_watch_opens_a_push_channel_and_renews_it_before_it_closes() -> TestResult {
    let mailbox = Mailbox::connect()?;
    let fake = PushFake::new();
    assert!(
        mailbox.watch_due(Some(TOPIC))?,
        "an Active Gmail mailbox owes a channel"
    );
    assert!(!mailbox.watch_due(None)?, "a host with no topic opens none");

    let opened = mailbox.watch_step(&fake, Some(TOPIC))?;
    let first_close = fake.watch_expires_at.get();
    assert_eq!(
        opened,
        Some(MailWatchAct::Watched {
            expires_at: first_close
        })
    );
    assert_eq!(fake.calls(), vec![Call::Watch(TOPIC.to_owned())]);

    // Google closes this channel within the day: it is renewed at once.
    assert!(
        mailbox.watch_due(Some(TOPIC))?,
        "a channel closing within a day is renewed"
    );
    fake.watch_expires_at.set(now() + WEEK_SECS);
    let renewed = mailbox.watch_step(&fake, Some(TOPIC))?;
    assert_eq!(
        renewed,
        Some(MailWatchAct::Watched {
            expires_at: fake.watch_expires_at.get()
        })
    );
    assert_eq!(fake.calls().len(), 2, "{:?}", fake.calls());

    // Renewed today and open for a week: nothing is owed.
    assert!(
        !mailbox.watch_due(Some(TOPIC))?,
        "a fresh channel owes nothing"
    );
    assert_eq!(mailbox.watch_step(&fake, Some(TOPIC))?, None);
    assert_eq!(fake.calls().len(), 2, "no call while nothing is owed");

    // The host's topic changed: the channel is opened to the new one.
    assert!(mailbox.watch_due(Some(OTHER_TOPIC))?);
    mailbox.watch_step(&fake, Some(OTHER_TOPIC))?;
    assert_eq!(
        fake.calls().last(),
        Some(&Call::Watch(OTHER_TOPIC.to_owned()))
    );
    Ok(())
}

#[test]
fn a_push_notice_wakes_its_source_and_the_step_lands_the_new_mail() -> TestResult {
    let mailbox = Mailbox::connect()?;
    let fake = PushFake::new();
    let first = mailbox.step(&fake)?;
    assert_eq!(first.landed, 0, "{first:?}");
    // The source stands at the anchor the notice names: nothing to wake.
    assert!(mailbox.notice(OWNER_ADDRESS, FIRST_ANCHOR)?.is_empty());

    fake.arrive();
    // Gmail writes the address as the account has it; the source matches
    // it case-folded. Another mailbox's notice wakes nothing.
    assert_eq!(
        mailbox.notice("Owen@Example.com", NEW_ANCHOR)?,
        vec![mailbox.source]
    );
    assert!(mailbox.notice("yuki@example.com", NEW_ANCHOR)?.is_empty());

    let woken = mailbox.step(&fake)?;
    assert!(
        woken.landed > 0,
        "the woken step lands the new mail: {woken:?}"
    );
    assert!(
        fake.calls().contains(&Call::Headers("m0001".to_owned()))
            || fake.calls().contains(&Call::Full("m0001".to_owned())),
        "{:?}",
        fake.calls()
    );
    // Its anchor moved past the notice: the same notice again wakes nothing.
    assert!(mailbox.notice(OWNER_ADDRESS, NEW_ANCHOR)?.is_empty());
    Ok(())
}

#[test]
fn a_dropped_notice_is_reconciled_by_the_next_plain_step() -> TestResult {
    let mailbox = Mailbox::connect()?;
    let fake = PushFake::new();
    mailbox.step(&fake)?;
    // The new mail arrives and its notice never comes: the host's next
    // periodic step reads the change feed from the committed anchor.
    fake.arrive();
    let reconciled = mailbox.step(&fake)?;
    assert!(reconciled.landed > 0, "{reconciled:?}");
    assert!(
        fake.calls()
            .contains(&Call::History(FIRST_ANCHOR.to_owned())),
        "{:?}",
        fake.calls()
    );
    Ok(())
}

#[test]
fn leaving_active_or_the_hosts_topic_closes_the_channel_once() -> TestResult {
    let mailbox = Mailbox::connect()?;
    let fake = PushFake::new();
    fake.watch_expires_at.set(now() + WEEK_SECS);
    mailbox.watch_step(&fake, Some(TOPIC))?;

    // The host drops its topic: the channel is closed, once.
    assert!(
        mailbox.watch_due(None)?,
        "a channel the host no longer serves is closed"
    );
    assert_eq!(
        mailbox.watch_step(&fake, None)?,
        Some(MailWatchAct::Stopped)
    );
    assert_eq!(fake.calls().last(), Some(&Call::StopWatch));
    assert!(!mailbox.watch_due(None)?);

    // Opened again, then the owner pauses the source.
    mailbox.watch_step(&fake, Some(TOPIC))?;
    mailbox.set_status(MailSourceStatus::Paused)?;
    let before = fake.calls().len();
    assert!(
        mailbox.watch_due(Some(TOPIC))?,
        "a paused source's channel is owed its close"
    );
    assert!(
        mailbox.notice(OWNER_ADDRESS, NEW_ANCHOR)?.is_empty(),
        "a paused source wakes on no notice"
    );
    assert_eq!(
        mailbox.watch_step(&fake, Some(TOPIC))?,
        Some(MailWatchAct::Stopped)
    );
    assert_eq!(
        fake.calls()[before..],
        [Call::StopWatch],
        "the close makes one call and no other"
    );
    assert!(!mailbox.watch_due(Some(TOPIC))?, "closed once");
    assert_eq!(mailbox.watch_step(&fake, Some(TOPIC))?, None);
    assert_eq!(fake.calls().len(), before + 1);
    Ok(())
}
