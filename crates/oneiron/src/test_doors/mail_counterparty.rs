//! Doors for `tests/mail_counterparty_author.rs` (fix list row 15412): land one
//! provider message through a mail sync step on a fresh vault, and read back
//! the author each stored MESSAGE of its TURN names. Thin wrappers over
//! production APIs only; no landing logic here. Compiled only under
//! `--cfg oneiron_test_support` (`test_doors`); hidden, never API.

use crate::edge::{EdgeActorClass, EdgeKind};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::mail_pack::{
    MailAddressHeaders, MailAttachmentRef, MailFull, MailHeaders, MailHistoryPage, MailHistoryRead,
    MailIdPage, MailListQuery, MailMessageRef, MailProvider, MailProviderWire,
    MailSourceConnectRequest, MailSourceKind, MailSyncBudget, MailSyncSource,
};
use crate::ports::{EdgeDirection, EdgeStoreRead, EntityStoreRead};
use crate::registry::ENTITY_TYPE_MESSAGE;
use crate::vault::Vault;

/// The provider id the landed message carries.
const PROVIDER_ID: &str = "counterparty-msg-1";

/// The custody name the mailbox credential is stored under.
const CUSTODY_REF: &str = "test-mail-cred";

/// The mailbox's own address and provider account.
const MAILBOX_ADDRESS: &str = "yuki@example.com";
const MAILBOX_ACCOUNT: &str = "test-account";

fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(reason.to_owned())
}

fn memory_invalid(where_: &str, error: crate::memory::MemoryError) -> Error {
    invalid(&format!("{where_}: {}: {}", error.code, error.message))
}

/// The landed message's headers at `received_at`: from Owen to the mailbox,
/// or, when `sent_by_mailbox`, from the mailbox to Owen.
fn headers(received_at: u64, sent_by_mailbox: bool) -> MailHeaders {
    let (from, to) = if sent_by_mailbox {
        (MAILBOX_ADDRESS, "owen@example.com")
    } else {
        ("owen@example.com", MAILBOX_ADDRESS)
    };
    MailHeaders {
        provider_id: PROVIDER_ID.to_owned(),
        thread_id: Some("thread-1".to_owned()),
        rfc_message_id: Some("<counterparty-msg-1@example.com>".to_owned()),
        in_reply_to: None,
        references: Vec::new(),
        from: Some(from.to_owned()),
        to: vec![to.to_owned()],
        cc: Vec::new(),
        reply_to: Vec::new(),
        subject: Some("Quarterly plan".to_owned()),
        date: Some(received_at),
        received_at,
        labels: vec![if sent_by_mailbox { "SENT" } else { "INBOX" }.to_owned()],
        sent_by_mailbox,
        trash_or_spam: false,
        draft: false,
    }
}

/// A provider that lists the one message and serves its headers and body.
struct OneMessageWire {
    headers: MailHeaders,
}

impl MailProviderWire for OneMessageWire {
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
            messages: vec![MailMessageRef {
                provider_id: PROVIDER_ID.to_owned(),
                thread_id: Some("thread-1".to_owned()),
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
            body_text: Some("Can we move the review to Thursday?".to_owned()),
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

    fn raw_address_headers(
        &self,
        _source: &MailSyncSource,
        _provider_id: &str,
    ) -> Result<Option<MailAddressHeaders>> {
        Ok(None)
    }
}

/// Connects one Google mailbox on `vault` as its embedded owner, lands one
/// message through a sync step (received from Owen, or sent by the mailbox
/// when `sent_by_mailbox`), and answers the `author` each stored MESSAGE of
/// the message's TURN names, in edge order.
///
/// # Errors
///
/// The vault's, or the landing's when no MESSAGE was stored.
#[doc(hidden)]
pub fn landed_message_authors(
    vault: &Vault,
    now_sec: u64,
    sent_by_mailbox: bool,
) -> Result<Vec<String>> {
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
        value_bytes: b"test-mail-token".to_vec(),
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
    let owner_proof = memory
        .embedded_owner("vault.mail.sources.sync")
        .map_err(|error| memory_invalid("owner proof", error))?;
    let wire = OneMessageWire {
        headers: headers(now_sec, sent_by_mailbox),
    };
    vault
        .mail_sync_step(&owner_proof, source, &wire, MailSyncBudget::default())
        .map_err(|error| memory_invalid("mail import", error))?;
    let turn = EntityId::derive(
        crate::entity_id::derived_domains::MAIL_TURN,
        &[source.to_hex().as_bytes(), PROVIDER_ID.as_bytes()],
    )?;
    let txn = vault.store.env.read_txn()?;
    let mut authors = Vec::new();
    for edge in
        vault
            .store
            .port_edges(&txn, &turn, EdgeDirection::In, Some(EdgeKind::PartOf), None)?
    {
        let message = edge?.target;
        let Some(raw) = vault.store.port_entity_record(&txn, &message)? else {
            continue;
        };
        if raw.entity_type != ENTITY_TYPE_MESSAGE {
            continue;
        }
        authors.push(stored_author(&raw.body)?);
    }
    if authors.is_empty() {
        return Err(invalid("the landing stored no MESSAGE under the mail TURN"));
    }
    Ok(authors)
}

/// The `author` token a stored MESSAGE body names; a document-pointer body
/// keeps the key too.
fn stored_author(body: &[u8]) -> Result<String> {
    let value = rmpv::decode::read_value(&mut &body[..])
        .map_err(|_| invalid("a stored MESSAGE body is not msgpack"))?;
    value
        .as_map()
        .and_then(|fields| {
            fields
                .iter()
                .find(|(key, _)| key.as_str() == Some("author"))
                .and_then(|(_, author)| author.as_str())
        })
        .map(str::to_owned)
        .ok_or_else(|| invalid("a stored MESSAGE body names no author"))
}
