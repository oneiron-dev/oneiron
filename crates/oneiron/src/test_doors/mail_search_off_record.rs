//! Doors for `tests/mail_search_off_record.rs` (ARCH-0063 #searched-mail,
//! UNBUILT-01): mail that a search finds inside an off-record session stays
//! in the session's overlay and is dropped at close. A Google mailbox on a
//! fresh vault, a provider whose search finds one message and which counts
//! its whole-message reads, the search itself, and where the found message
//! is held: in base, or in the session's composed view. Thin wrappers over
//! production APIs only; no landing logic here. Compiled only under
//! `--cfg oneiron_test_support` (`test_doors`); hidden, never API.

use std::sync::atomic::{AtomicU32, Ordering};

use crate::consent::AuthenticatedOwner;
use crate::edge::EdgeActorClass;
use crate::entity_id::{EntityId, derived_domains};
use crate::error::{Error, Result};
use crate::mail_pack::{
    MailAttachmentRef, MailFull, MailHeaders, MailHistoryPage, MailHistoryRead, MailIdPage,
    MailListQuery, MailMessageRef, MailProvider, MailProviderWire, MailSearchReport,
    MailSourceConnectRequest, MailSourceKind, MailSyncSource,
};
use crate::off_record::OffRecordSession;
use crate::ports::EntityStoreRead;
use crate::vault::Vault;

/// The provider id of the one message the search finds.
const PROVIDER_ID: &str = "searched-msg-1";

/// The provider thread the found message is in.
const THREAD_ID: &str = "searched-thread-1";

/// The query the search runs.
const SEARCH_QUERY: &str = "from:owen@example.com";

/// The custody name the mailbox credential is stored under.
const CUSTODY_REF: &str = "test-search-mail-cred";

/// The sender of the found message.
const SENDER_ADDRESS: &str = "owen@example.com";

/// The mailbox's own address and provider account.
const MAILBOX_ADDRESS: &str = "yuki@example.com";
const MAILBOX_ACCOUNT: &str = "test-search-account";

fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(reason.to_owned())
}

fn memory_invalid(where_: &str, error: crate::memory::MemoryError) -> Error {
    invalid(&format!("{where_}: {}: {}", error.code, error.message))
}

/// A provider whose search finds the one message, received from Owen at
/// `received_at`, and which counts each whole read of it.
pub struct CountingSearchWire {
    received_at: u64,
    whole_reads: AtomicU32,
}

impl CountingSearchWire {
    /// A provider holding the one message, received at `received_at`.
    #[must_use]
    pub const fn new(received_at: u64) -> Self {
        Self {
            received_at,
            whole_reads: AtomicU32::new(0),
        }
    }

    /// How many times a search read the message whole.
    #[must_use]
    pub fn whole_reads(&self) -> u32 {
        self.whole_reads.load(Ordering::SeqCst)
    }

    fn headers(&self) -> MailHeaders {
        MailHeaders {
            provider_id: PROVIDER_ID.to_owned(),
            thread_id: Some(THREAD_ID.to_owned()),
            rfc_message_id: Some("<searched-msg-1@example.com>".to_owned()),
            in_reply_to: None,
            references: Vec::new(),
            from: Some(SENDER_ADDRESS.to_owned()),
            to: vec![MAILBOX_ADDRESS.to_owned()],
            cc: Vec::new(),
            reply_to: Vec::new(),
            subject: Some("Contract draft".to_owned()),
            date: Some(self.received_at),
            received_at: self.received_at,
            labels: vec!["INBOX".to_owned()],
            sent_by_mailbox: false,
            trash_or_spam: false,
            draft: false,
        }
    }
}

impl MailProviderWire for CountingSearchWire {
    fn current_anchor(&self, _source: &MailSyncSource) -> Result<String> {
        Ok("anchor".to_owned())
    }

    fn list_page(
        &self,
        _source: &MailSyncSource,
        _query: &MailListQuery,
        _page: Option<&str>,
    ) -> Result<MailIdPage> {
        Ok(MailIdPage {
            messages: Vec::new(),
            next_page: None,
        })
    }

    fn headers(&self, _source: &MailSyncSource, provider_id: &str) -> Result<Option<MailHeaders>> {
        Ok((provider_id == PROVIDER_ID).then(|| self.headers()))
    }

    fn full(&self, _source: &MailSyncSource, provider_id: &str) -> Result<Option<MailFull>> {
        if provider_id != PROVIDER_ID {
            return Ok(None);
        }
        self.whole_reads.fetch_add(1, Ordering::SeqCst);
        Ok(Some(MailFull {
            headers: self.headers(),
            body_text: Some("The contract draft is attached; please read clause 4.".to_owned()),
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
            anchor: "anchor".to_owned(),
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

    fn search_page(
        &self,
        _source: &MailSyncSource,
        _query: &str,
        _limit: u32,
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
}

/// The mailbox the searches run on, and the owner proof they run under.
pub struct SearchMailbox {
    /// The mailbox source.
    pub source: EntityId,
    /// The vault owner's proof, as the search door takes it.
    pub owner: AuthenticatedOwner,
}

/// Connects one Google mailbox on `vault` as its embedded owner, with
/// nothing imported, and answers it with the owner's proof.
///
/// # Errors
///
/// The vault's, or the connect's own refusal.
pub fn connect_search_mailbox(vault: &Vault, now_sec: u64) -> Result<SearchMailbox> {
    let owner = vault
        .ensure_embedded_owner_actor()
        .map_err(|error| invalid(&format!("embedded owner: {error:?}")))?;
    let memory = vault.memory(owner, EdgeActorClass::Human);
    crate::mail_pack::install_mail_calendar_pack_embedded(&memory)
        .map_err(|error| memory_invalid("mail pack install", error))?;
    vault.register_secret(crate::secret_custody::SecretCustodyRecord {
        schema_version: crate::secret_custody::SECRET_CUSTODY_SCHEMA_VERSION,
        name: CUSTODY_REF.to_owned(),
        class: crate::secret_custody::CustodyClass::CustodyPortable,
        device_only: false,
        model_reveal_allowed: true,
        value_bytes: b"test-search-mail-token".to_vec(),
        status: crate::secret_custody::SecretCustodyStatus::Active,
        registered_at: now_sec,
        rotated_at: None,
        rotation_generation: 0,
        bindings: vec![crate::secret_custody::SecretBinding {
            effector: "connector:gmail".to_owned(),
            tier_ceiling: crate::secret_custody::CustodyTier::T0Doored,
            scopes: Vec::new(),
        }],
        manifest_ref: String::new(),
        declared_paths: Vec::new(),
        policy_floor_snapshot: crate::secret_custody::SecretCustodyFloor::default(),
    })?;
    let receipt = memory
        .mail_sources_connect(&MailSourceConnectRequest {
            provider: MailProvider::Google,
            kind: MailSourceKind::PersonalMailbox,
            address: MAILBOX_ADDRESS.to_owned(),
            provider_account: MAILBOX_ACCOUNT.to_owned(),
            custody_ref: CUSTODY_REF.to_owned(),
            members: Vec::new(),
            for_person: None,
            channel_identity_ref: None,
            copy: None,
            on_provider_delete: None,
            calendar_details: None,
        })
        .map_err(|error| memory_invalid("mail connect", error))?;
    let source =
        EntityId::from_hex(&receipt.source.source_ref).map_err(|_| invalid("mail source ref"))?;
    let owner = memory
        .embedded_owner("vault.mail.sources.search")
        .map_err(|error| memory_invalid("owner proof", error))?;
    Ok(SearchMailbox { source, owner })
}

/// One search of `mailbox` through `wire`, run inside `session`.
///
/// # Errors
///
/// The search's own refusal.
pub fn search_in_session(
    vault: &Vault,
    mailbox: &SearchMailbox,
    session: &OffRecordSession<'_>,
    wire: &CountingSearchWire,
) -> Result<MailSearchReport> {
    vault
        .mail_search_step_in_session(
            &mailbox.owner,
            session,
            mailbox.source,
            wire,
            SEARCH_QUERY,
            None,
            10,
        )
        .map_err(|error| memory_invalid("mail search", error))
}

/// Whether base holds any trace of the found message: its occurrence, its
/// TURN, or its thread's CONVERSATION.
///
/// # Errors
///
/// The vault's.
pub fn base_holds_found_message(vault: &Vault, mailbox: &SearchMailbox) -> Result<bool> {
    let txn = vault.store.env.read_txn()?;
    if crate::mail_pack::occurrence_rows_in(&vault.store, &txn, mailbox.source, PROVIDER_ID)?
        .is_some()
    {
        return Ok(true);
    }
    let source = mailbox.source.to_hex();
    let thread = format!("provider:{THREAD_ID}");
    let turn = EntityId::derive(
        derived_domains::MAIL_TURN,
        &[source.as_bytes(), PROVIDER_ID.as_bytes()],
    )?;
    let conversation = EntityId::derive(
        derived_domains::MAIL_CONVERSATION,
        &[source.as_bytes(), thread.as_bytes()],
    )?;
    Ok(vault.store.port_entity_record(&txn, &turn)?.is_some()
        || vault
            .store
            .port_entity_record(&txn, &conversation)?
            .is_some())
}

/// Whether `session` reads the found message: its occurrence, and every row
/// that occurrence names (CONVERSATION, TURN, each MESSAGE), on the
/// session's composed view of overlay and base.
///
/// # Errors
///
/// The session's or the vault's.
pub fn session_reads_found_message(
    vault: &Vault,
    mailbox: &SearchMailbox,
    session: &OffRecordSession<'_>,
) -> Result<bool> {
    let view = session.read_view()?;
    let txn = vault.store.env.read_txn()?;
    let Some(rows) =
        crate::mail_pack::occurrence_rows_in(&view, &txn, mailbox.source, PROVIDER_ID)?
    else {
        return Ok(false);
    };
    for row in rows {
        if view.port_entity_record(&txn, &row)?.is_none() {
            return Ok(false);
        }
    }
    Ok(true)
}
