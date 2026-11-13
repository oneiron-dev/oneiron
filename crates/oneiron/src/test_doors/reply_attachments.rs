//! Doors for `tests/reply_attachments.rs` (fix list row 17645): seed a Google
//! mailbox (with its sending identity), a Microsoft 365 or an IMAP mailbox
//! with one received message and an artifact with two versions, then draft a reply
//! that names one exact version and read back what the draft froze. Thin
//! wrappers over production APIs only. The draft reads the answered
//! message's addresses as its thread stored them, since a test cannot reach
//! Gmail. Compiled only under `--cfg oneiron_test_support` (`test_doors`);
//! hidden, never API.

use base64::Engine as _;

use crate::blob_artifact::{ArtifactCreateRequest, BlobVersionProvenance};
use crate::channel_identity::{
    ChannelIdentityFulfillment, ChannelIdentityStep, DelegatedGrantScope,
    delegated_custody_scopes_for_grant,
};
use crate::channel_identity_provider::gmail::{
    GMAIL_READONLY_OAUTH_SCOPE, GMAIL_SEND_OAUTH_SCOPE, GmailDelegatedAdapter,
    GmailDelegatedAdapterConfig,
};
use crate::counterparty_contact::CounterpartyContactRecord;
use crate::disclosure::DisclosureScope;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::federation::Scope;
use crate::mail_pack::{
    MailAddressHeaders, MailAttachmentRef, MailFull, MailHeaders, MailHistoryPage, MailHistoryRead,
    MailIdPage, MailInboxRequest, MailListQuery, MailMessageRef, MailProvider, MailProviderWire,
    MailReplyDraftRequest, MailReplyDraftView, MailSourceConnectRequest, MailSourceKind,
    MailSyncBudget, MailSyncSource,
};
use crate::temporal::TimeRange;
use crate::vault::Vault;

/// The mailbox the seeded source reads and replies from.
const MAILBOX: &str = "owen@example.com";
/// The answered message's sender, whom the reply goes to.
const SENDER: &str = "yuki@example.com";
/// The custody name the mailbox's credential is stored under.
const CUSTODY_REF: &str = "reply-attachments-mail-cred";
/// The provider id and thread of the one received message.
const PROVIDER_ID: &str = "msg-1";
const THREAD_ID: &str = "thread-1";

/// What [`seed_gmail_thread`] leaves for the test.
#[doc(hidden)]
pub struct SeededThread {
    /// The vault's embedded owner, who owns the mailbox and drafts.
    pub owner: EntityId,
    /// The thread's CONVERSATION, 32-hex.
    pub thread_ref: String,
}

/// One file of a drafted reply, as its reader sees it.
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DraftedFile {
    /// The artifact, 32-hex.
    pub artifact_ref: String,
    /// The version that sends.
    pub version: u64,
    /// BLAKE3 of that version's stored bytes, 64 lower-hex.
    pub stored_version_blake3: String,
}

/// What [`draft_reply_with_file`] read back from the draft it made, taken
/// from the draft's view by field name, so this door reads a view of any
/// shape (a view with no files reads as none).
#[doc(hidden)]
pub struct DraftedReply {
    /// The files the reader sees, in their order.
    pub files: Vec<DraftedFile>,
    /// The exact message's length in octets, when the draft names it.
    pub message_octets: Option<u64>,
    /// The exact message's BLAKE3, when the draft names it.
    pub message_blake3: Option<String>,
    /// The manifest digest the draft's own row names; `None` for a draft
    /// without files.
    pub manifest_digest: Option<[u8; 32]>,
}

/// The files and the exact message `view` names, read by field name.
fn drafted_files(view: &MailReplyDraftView) -> std::result::Result<DraftedReply, String> {
    let view = serde_json::to_value(view).map_err(|error| format!("the draft view: {error}"))?;
    let text = |value: &serde_json::Value, field: &str| {
        value
            .get(field)
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
    };
    let mut files = Vec::new();
    for file in view
        .get("attachments")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
    {
        files.push(DraftedFile {
            artifact_ref: text(file, "artifact_ref").ok_or("a file names no artifact")?,
            version: file
                .get("version")
                .and_then(serde_json::Value::as_u64)
                .ok_or("a file names no version")?,
            stored_version_blake3: text(file, "stored_version_blake3")
                .ok_or("a file names no stored BLAKE3")?,
        });
    }
    Ok(DraftedReply {
        files,
        message_octets: view
            .get("message_octets")
            .and_then(serde_json::Value::as_u64),
        message_blake3: text(&view, "message_blake3"),
        manifest_digest: None,
    })
}

fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(reason.to_owned())
}

fn memory_invalid(where_: &str, error: crate::memory::MemoryError) -> Error {
    invalid(&format!("{where_}: {}: {}", error.code, error.message))
}

/// The received message's headers at `received_at`: from [`SENDER`] to the
/// mailbox, on one thread, with its Message-ID.
fn received_headers(received_at: u64) -> MailHeaders {
    MailHeaders {
        provider_id: PROVIDER_ID.to_owned(),
        thread_id: Some(THREAD_ID.to_owned()),
        rfc_message_id: Some("<msg-1@example.com>".to_owned()),
        in_reply_to: None,
        references: Vec::new(),
        from: Some(SENDER.to_owned()),
        to: vec![MAILBOX.to_owned()],
        cc: Vec::new(),
        reply_to: Vec::new(),
        subject: Some("The quarterly report".to_owned()),
        date: Some(received_at),
        received_at,
        labels: vec!["INBOX".to_owned()],
        sent_by_mailbox: false,
        trash_or_spam: false,
        draft: false,
    }
}

/// The fake provider wire the seed imports through: one received message,
/// listed and read whole, never deleted.
struct ReceivedMailWire {
    headers: MailHeaders,
}

impl MailProviderWire for ReceivedMailWire {
    fn current_anchor(&self, _source: &MailSyncSource) -> Result<String> {
        Ok("seed-anchor".to_owned())
    }

    fn list_page(
        &self,
        _source: &MailSyncSource,
        _query: &MailListQuery,
        _page: Option<&str>,
    ) -> Result<MailIdPage> {
        Ok(MailIdPage {
            messages: vec![MailMessageRef {
                provider_id: PROVIDER_ID.to_owned(),
                thread_id: Some(THREAD_ID.to_owned()),
            }],
            next_page: None,
        })
    }

    fn headers(&self, _source: &MailSyncSource, provider_id: &str) -> Result<Option<MailHeaders>> {
        Ok((provider_id == PROVIDER_ID).then(|| self.headers.clone()))
    }

    fn full(&self, _source: &MailSyncSource, provider_id: &str) -> Result<Option<MailFull>> {
        Ok((provider_id == PROVIDER_ID).then(|| MailFull {
            headers: self.headers.clone(),
            body_text: Some("Could you send me the report?".to_owned()),
            attachments: Vec::new(),
            content_digest: None,
        }))
    }

    fn history(
        &self,
        _source: &MailSyncSource,
        _anchor: &str,
        _page: Option<&str>,
    ) -> Result<MailHistoryRead> {
        Ok(MailHistoryRead::Page(MailHistoryPage {
            changes: Vec::new(),
            next_page: None,
            anchor: "seed-anchor".to_owned(),
        }))
    }

    fn attachment(
        &self,
        _source: &MailSyncSource,
        _provider_id: &str,
        _attachment: &MailAttachmentRef,
    ) -> Result<Option<Vec<u8>>> {
        Ok(None)
    }

    fn raw_address_headers(
        &self,
        _source: &MailSyncSource,
        _provider_id: &str,
    ) -> Result<Option<MailAddressHeaders>> {
        Ok(None)
    }
}

/// Stores the mailbox's credential under [`CUSTODY_REF`], bound to
/// `effector` with `scopes`.
fn register_mail_credential(
    vault: &Vault,
    effector: &str,
    scopes: Vec<String>,
    now_sec: u64,
) -> Result<()> {
    vault.register_secret(crate::secret_custody::SecretCustodyRecord {
        schema_version: crate::secret_custody::SECRET_CUSTODY_SCHEMA_VERSION,
        name: CUSTODY_REF.to_owned(),
        class: crate::secret_custody::CustodyClass::CustodyPortable,
        device_only: false,
        model_reveal_allowed: true,
        value_bytes: b"reply-attachments-mail-token".to_vec(),
        status: crate::secret_custody::SecretCustodyStatus::Active,
        registered_at: now_sec,
        rotated_at: None,
        rotation_generation: 0,
        bindings: vec![crate::secret_custody::SecretBinding {
            effector: effector.to_owned(),
            tier_ceiling: crate::secret_custody::CustodyTier::T0Doored,
            scopes,
        }],
        manifest_ref: String::new(),
        declared_paths: Vec::new(),
        policy_floor_snapshot: crate::secret_custody::SecretCustodyFloor::default(),
    })?;
    Ok(())
}

/// Connects the owner's `provider` mailbox (sending through `identity`,
/// when it names one), imports the one received message into it, makes
/// [`SENDER`] the owner's contact on `contact_identity`, cleared to see
/// everything below Tier A, and returns the thread.
fn connect_and_import(
    vault: &Vault,
    owner: EntityId,
    provider: MailProvider,
    identity: Option<EntityId>,
    contact_identity: EntityId,
    now_sec: u64,
) -> Result<SeededThread> {
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let receipt = memory
        .mail_sources_connect(&MailSourceConnectRequest {
            provider,
            kind: MailSourceKind::PersonalMailbox,
            address: MAILBOX.to_owned(),
            provider_account: MAILBOX.to_owned(),
            custody_ref: CUSTODY_REF.to_owned(),
            members: Vec::new(),
            for_person: None,
            channel_identity_ref: identity.map(|identity| identity.to_hex()),
            copy: None,
            on_provider_delete: None,
            calendar_details: None,
        })
        .map_err(|error| memory_invalid("mail connect", error))?;
    let source =
        EntityId::from_hex(&receipt.source.source_ref).map_err(|_| invalid("mail source ref"))?;
    let owner_proof = memory
        .embedded_owner("vault.mail.sources.sync")
        .map_err(|error| memory_invalid("owner proof", error))?;
    let wire = ReceivedMailWire {
        headers: received_headers(now_sec),
    };
    vault
        .mail_sync_step(&owner_proof, source, &wire, MailSyncBudget::default())
        .map_err(|error| memory_invalid("mail import", error))?;
    let contact = EntityId::now();
    vault.create_counterparty_contact(
        &contact,
        &CounterpartyContactRecord::user_introduction(contact_identity, SENDER, now_sec)?,
    )?;
    let clearance = DisclosureScope::new(Scope::top(), "reply attachments test", now_sec)?;
    vault.with_write_txn_grouped(|txn| {
        vault.set_counterparty_disclosure_scope_in_txn(txn, &contact, &clearance)
    })?;
    let page = memory
        .mail_inbox(&MailInboxRequest::default())
        .map_err(|error| memory_invalid("mail inbox", error))?;
    let item = page
        .items
        .first()
        .ok_or_else(|| invalid("the imported message is not in the inbox"))?;
    Ok(SeededThread {
        owner,
        thread_ref: item.thread_ref.clone(),
    })
}

/// Seeds a Google mailbox the embedded owner connects with a sending
/// identity (its delegated grant holds `gmail.readonly` and `gmail.send`,
/// with the matching custody evidence), one message from [`SENDER`]
/// imported into it, and [`SENDER`] as the owner's contact on that identity,
/// cleared to see everything below Tier A: a file reaches a recipient only
/// when the recipient's clearance admits it, and an unknown party is cleared
/// for public records alone.
///
/// # Errors
///
/// The vault's, or a seeded step the vault refuses.
#[doc(hidden)]
pub fn seed_gmail_thread(vault: &Vault, now_sec: u64) -> Result<SeededThread> {
    let owner = vault
        .ensure_embedded_owner_actor()
        .map_err(|error| memory_invalid("embedded owner", error))?;
    crate::mail_pack::install_mail_calendar_pack_embedded(
        &vault.memory(owner, EdgeActorClass::Human),
    )
    .map_err(|error| memory_invalid("mail pack install", error))?;
    register_mail_credential(
        vault,
        "connector:gmail",
        delegated_custody_scopes_for_grant(
            "email",
            MAILBOX,
            &[DelegatedGrantScope::MailRead, DelegatedGrantScope::MailSend],
        ),
        now_sec,
    )?;
    let adapter = GmailDelegatedAdapter::new(
        GmailDelegatedAdapterConfig::new(MAILBOX, CUSTODY_REF)?
            .with_google_oauth_scopes_allowing_send(&[
                GMAIL_READONLY_OAUTH_SCOPE,
                GMAIL_SEND_OAUTH_SCOPE,
            ])?,
    );
    let identity = EntityId::now();
    adapter.provision_delegated_identity(vault, identity, owner, now_sec)?;
    vault.step_channel_identity(
        &identity,
        ChannelIdentityStep::Bind(ChannelIdentityFulfillment::Api),
        now_sec,
    )?;
    vault.step_channel_identity(&identity, ChannelIdentityStep::Fulfill, now_sec)?;
    connect_and_import(
        vault,
        owner,
        MailProvider::Google,
        Some(identity),
        identity,
        now_sec,
    )
}

/// Seeds a Microsoft 365 mailbox the embedded owner connects (its
/// credential stored for the owner, read and sent on Graph), one message
/// from [`SENDER`] imported into it, and [`SENDER`] as the owner's contact,
/// cleared to see everything below Tier A. A Microsoft 365 reply names no
/// sending identity, so the contact sits on an identity no row holds, which
/// the send lookup matches on every channel.
///
/// # Errors
///
/// The vault's, or a seeded step the vault refuses.
#[doc(hidden)]
pub fn seed_microsoft_thread(vault: &Vault, now_sec: u64) -> Result<SeededThread> {
    let owner = vault
        .ensure_embedded_owner_actor()
        .map_err(|error| memory_invalid("embedded owner", error))?;
    crate::mail_pack::install_mail_calendar_pack_embedded(
        &vault.memory(owner, EdgeActorClass::Human),
    )
    .map_err(|error| memory_invalid("mail pack install", error))?;
    register_mail_credential(
        vault,
        crate::mail_pack::MICROSOFT365_CONNECTOR_EFFECTOR,
        Vec::new(),
        now_sec,
    )?;
    connect_and_import(
        vault,
        owner,
        MailProvider::Microsoft365,
        None,
        EntityId::now(),
        now_sec,
    )
}

/// Seeds an IMAP mailbox the embedded owner connects (its credential stored
/// for the owner, read over IMAP and sent by SMTP submission), one message
/// from [`SENDER`] imported into it, and [`SENDER`] as the owner's contact,
/// cleared to see everything below Tier A. The vault installs no mail host,
/// so no runner for the submission server's size check.
///
/// # Errors
///
/// The vault's, or a seeded step the vault refuses.
#[doc(hidden)]
pub fn seed_imap_thread(vault: &Vault, now_sec: u64) -> Result<SeededThread> {
    let owner = vault
        .ensure_embedded_owner_actor()
        .map_err(|error| memory_invalid("embedded owner", error))?;
    crate::mail_pack::install_mail_calendar_pack_embedded(
        &vault.memory(owner, EdgeActorClass::Human),
    )
    .map_err(|error| memory_invalid("mail pack install", error))?;
    register_mail_credential(
        vault,
        crate::mail_pack::IMAP_CONNECTOR_EFFECTOR,
        Vec::new(),
        now_sec,
    )?;
    connect_and_import(
        vault,
        owner,
        MailProvider::Imap,
        None,
        EntityId::now(),
        now_sec,
    )
}

/// Creates one artifact as `actor`, a text file whose versions hold
/// `versions` in order (version 1 first), and returns it.
///
/// # Errors
///
/// The vault's, or no version given.
#[doc(hidden)]
pub fn seed_artifact(vault: &Vault, actor: EntityId, versions: &[&[u8]]) -> Result<EntityId> {
    let (first, later) = versions
        .split_first()
        .ok_or_else(|| invalid("an artifact needs a first version"))?;
    let memory = vault.memory(actor, EdgeActorClass::Human);
    let view = memory
        .artifacts_create(&ArtifactCreateRequest {
            name: "report.txt".to_owned(),
            media_type: "text/plain".to_owned(),
            content_base64: base64::engine::general_purpose::STANDARD.encode(first),
            run_ref: None,
            made_by: None,
        })
        .map_err(|error| memory_invalid("artifact create", error))?
        .ok_or_else(|| invalid("the artifact create answered no artifact"))?;
    for bytes in later {
        let now = vault.now_recorded_at();
        vault.append_blob_artifact_version(
            &view.artifact_id,
            bytes,
            &BlobVersionProvenance::UserUpload,
            memory.write_actor(),
            TimeRange {
                start: now,
                end: now,
            },
            now,
        )?;
    }
    Ok(view.artifact_id)
}

/// Drafts, as `actor`, a reply on `thread_ref` that names `version` of
/// `artifact` as its one file, reading the answered message's addresses as
/// the thread stored them, and reads back what the draft froze. The request
/// is built from JSON, as a caller's would be. `Err` carries the refusal.
///
/// # Errors
///
/// The draft's refusal, as text.
#[doc(hidden)]
pub fn draft_reply_with_file(
    vault: &Vault,
    actor: EntityId,
    thread_ref: &str,
    artifact: EntityId,
    version: u64,
) -> std::result::Result<DraftedReply, String> {
    let request: MailReplyDraftRequest = serde_json::from_value(serde_json::json!({
        "thread_ref": thread_ref,
        "body": "Here is the report.",
        "attachments": [{ "artifact_ref": artifact.to_hex(), "version": version }],
        "request_key": "reply-with-report",
    }))
    .map_err(|error| format!("the draft request: {error}"))?;
    let memory = vault.memory(actor, EdgeActorClass::Human);
    let view = crate::mail_pack::mail_reply_draft_as_stored_for_test(&memory, &request)
        .map_err(|error| format!("{}: {}", error.code, error.message))?;
    let draft = EntityId::from_hex(&view.draft_ref).map_err(|error| format!("{error:?}"))?;
    let manifest_digest = crate::mail_pack::reply_draft_manifest_digest_for_test(vault, &draft)
        .map_err(|error| format!("{error:?}"))?;
    Ok(DraftedReply {
        manifest_digest,
        ..drafted_files(&view)?
    })
}
