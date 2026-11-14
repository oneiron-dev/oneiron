//! Doors for `tests/check_in_mail_reply_approve.rs` (2k9a): seed one IMAP mailbox, message and proposed reply, read it back, and hold it as a held dispatch would.

use crate::EdgeActorClass;
use crate::EntityId;
use crate::Vault;
use crate::error::{Error, Result};
use crate::mail_pack::{
    MailAttachmentRef, MailFull, MailHeaders, MailHistoryPage, MailHistoryRead, MailIdPage,
    MailListQuery, MailMessageRef, MailProvider, MailProviderWire, MailReplyDraftRequest,
    MailReplyDraftView, MailReplyDraftsRequest, MailSourceConnectRequest, MailSourceKind,
    MailSyncBudget, MailSyncSource, mail_calendar_pack_files,
};
use crate::secret_custody::{CustodyClass, CustodyTier, OwnerSecretRegistration, RequestedBinding};
use crate::store::GateDecisionId;

type Seeded = (EntityId, u64, String);

fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(reason.to_owned())
}

fn memory_invalid(where_: &str, error: crate::memory::MemoryError) -> Error {
    invalid(&format!("{where_}: {}: {}", error.code, error.message))
}

struct Wire(MailHeaders);

impl MailProviderWire for Wire {
    fn current_anchor(&self, _s: &MailSyncSource) -> Result<String> {
        Ok("seed-anchor".to_owned())
    }

    fn list_page(
        &self,
        _s: &MailSyncSource,
        _q: &MailListQuery,
        _p: Option<&str>,
    ) -> Result<MailIdPage> {
        Ok(MailIdPage {
            messages: vec![MailMessageRef {
                provider_id: self.0.provider_id.clone(),
                thread_id: self.0.thread_id.clone(),
            }],
            next_page: None,
        })
    }

    fn headers(&self, _s: &MailSyncSource, id: &str) -> Result<Option<MailHeaders>> {
        Ok((id == self.0.provider_id).then(|| self.0.clone()))
    }

    fn full(&self, _s: &MailSyncSource, id: &str) -> Result<Option<MailFull>> {
        Ok((id == self.0.provider_id).then(|| MailFull {
            headers: self.0.clone(),
            body_text: Some("Can we move the review to Thursday?".to_owned()),
            ..Default::default()
        }))
    }

    fn history(&self, _s: &MailSyncSource, _a: &str, _p: Option<&str>) -> Result<MailHistoryRead> {
        Ok(MailHistoryRead::Page(MailHistoryPage {
            changes: Vec::new(),
            next_page: None,
            anchor: "seed-anchor".to_owned(),
        }))
    }

    fn attachment(
        &self,
        _s: &MailSyncSource,
        _id: &str,
        _a: &MailAttachmentRef,
    ) -> Result<Option<Vec<u8>>> {
        Ok(None)
    }
}

/// Seeds a Proposed IMAP reply for `who` (`mbox` answering `sender`); the draft id, revision and plan ref.
pub fn seed(vault: &Vault, who: EntityId, mbox: &str, sender: &str) -> Result<Seeded> {
    let owner = vault
        .ensure_embedded_owner_actor()
        .map_err(|_| invalid("owner"))?;
    let proof = vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?;
    vault.put_pack(&proof, mail_calendar_pack_files())?;
    let scopes = Vec::from_iter((who != owner).then(|| format!("actor:{}", who.to_hex())));
    vault.register_secret_as_owner(
        &proof,
        &OwnerSecretRegistration {
            name: &format!("test-mail-cred-{mbox}"),
            class: CustodyClass::CustodyPortable,
            device_only: false,
            rung: CustodyTier::T0Doored,
            bindings: vec![RequestedBinding {
                effector: "connector:imap".to_owned(),
                tier_ceiling: None,
                scopes,
            }],
            manifest: None,
            value: b"test-mail-token",
        },
        crate::unix_seconds_now(),
    )?;
    let receipt = vault
        .memory(owner, EdgeActorClass::Human)
        .mail_sources_connect(&MailSourceConnectRequest {
            provider: MailProvider::Imap,
            kind: MailSourceKind::PersonalMailbox,
            address: mbox.to_owned(),
            provider_account: mbox.to_owned(),
            custody_ref: format!("test-mail-cred-{mbox}"),
            members: Vec::new(),
            for_person: (who != owner).then(|| who.to_hex()),
            channel_identity_ref: None,
            copy: None,
            on_provider_delete: None,
            calendar_details: None,
        })
        .map_err(|error| memory_invalid("mail connect", error))?;
    let source = EntityId::from_hex(&receipt.source.source_ref).map_err(|_| invalid("source"))?;
    let wire = Wire(MailHeaders {
        provider_id: "seed-msg-1".to_owned(),
        thread_id: Some("seed-thread-1".to_owned()),
        rfc_message_id: Some("<seed-msg-1@example.com>".to_owned()),
        from: Some(sender.to_owned()),
        to: vec![mbox.to_owned()],
        ..Default::default()
    });
    vault
        .mail_sync_step(&proof, source, &wire, MailSyncBudget::default())
        .map_err(|error| memory_invalid("mail import", error))?;
    let thread = EntityId::derive(
        crate::entity_id::derived_domains::MAIL_CONVERSATION,
        &[source.to_hex().as_bytes(), b"provider:seed-thread-1"],
    )
    .map_err(|_| invalid("thread"))?;
    let view = vault
        .memory(who, EdgeActorClass::Human)
        .mail_reply_draft(&MailReplyDraftRequest {
            thread_ref: thread.to_hex(),
            parent_turn_ref: None,
            body: "Thanks, I will take a look.".to_owned(),
            body_html: None,
            reply_all: false,
            cc: Vec::new(),
            request_key: "seed-1".to_owned(),
        })
        .map_err(|error| memory_invalid("mail reply draft", error))?;
    let draft = EntityId::from_hex(&view.draft_ref).map_err(|_| invalid("draft"))?;
    Ok((draft, view.revision, view.plan_ref))
}

/// Reads `draft` as `who` reads it.
pub fn read_draft(vault: &Vault, who: EntityId, draft: EntityId) -> Result<MailReplyDraftView> {
    vault
        .memory(who, EdgeActorClass::Human)
        .mail_reply_drafts(&MailReplyDraftsRequest::default())
        .map_err(|error| memory_invalid("mail reply drafts", error))?
        .drafts
        .into_iter()
        .find(|view| view.draft_ref == draft.to_hex())
        .ok_or_else(|| invalid("no draft"))
}

/// Leaves `draft` Approved, as a dispatch the outbound gate held leaves it:
/// a retry then reaches the approval's check-in guard (2k9a review).
pub fn hold_draft(vault: &Vault, draft: EntityId) -> Result<()> {
    crate::mail_pack::hold_draft_in_test(vault, draft)
}
