//! The durable store of frozen Gmail send plans (FIX 1053). A plan its host
//! keeps is read back by its content ref, so a scheduled member send finds it
//! after a restart with no host registering it again. A row is checked as it
//! is read: it rebuilds through the plan's own Message-ID gate and seals to
//! the ref it is kept under, or it is no plan. A delivered send drops its
//! plan's row; its receipt keeps the ref.
//!
//! A plan with files (fix list row 17645) keeps no file's name, ref or hash
//! and never its message: only the digest of its manifest and the ref of
//! the carrier its message is held in. Their holder's own live row keeps
//! the manifest, so a row a checkpoint brings back after that holder was
//! erased reads as no plan and never sends.

use serde::{Deserialize, Serialize};

use super::{GmailReplyThread, GmailSendPlan};
use crate::Vault;
use crate::channel_identity_provider::mail_attachments::{MailManifest, RetainedMailMessage};
use crate::error::{Error, Result};
use crate::outbound::OutboundRecipient;
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;
use crate::thread_passport::{CanonicalMessageId, canonical_message_id};

const SEND_PLANS: SideTable<String, StoredPlan, Named> =
    SideTable::new(&side_table::GMAIL_SEND_PLAN);

/// A plan's fields as its row keeps them.
#[derive(Serialize, Deserialize)]
struct StoredPlan {
    from_mailbox: String,
    from_display_name: Option<String>,
    to: String,
    /// Every recipient of a plan to several (fix list row 17645).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    recipients: Vec<OutboundRecipient>,
    subject: String,
    body_text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    body_html: Option<String>,
    date: String,
    message_id: String,
    reply: Option<StoredReply>,
    /// The digest of the files and the exact message a plan with files was
    /// frozen with ([`MailManifest::digest`], fix list row 17645).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    manifest: Option<[u8; 32]>,
    /// The ref of the carrier its message is held in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    carrier: Option<String>,
}

/// A reply half's fields as its plan's row keeps them.
#[derive(Serialize, Deserialize)]
struct StoredReply {
    gmail_thread_id: String,
    in_reply_to: String,
    references: Vec<String>,
}

impl GmailSendPlan {
    /// Keeps this plan in `vault` under its content ref, for a send that
    /// dispatches later, a scheduled connector-TASK member send among them.
    /// Keeping it again writes the same row.
    ///
    /// # Errors
    ///
    /// Storage and encoding errors as they occur.
    pub fn keep(&self, vault: &Vault) -> Result<()> {
        vault.with_write_txn_grouped(|txn| self.keep_in_txn(&vault.store, txn))
    }

    /// [`Self::keep`] in `txn`, the writer that publishes what the plan is
    /// for (fix list row 17645): a drafted reply with files keeps its plan
    /// in the writer that lands its draft and its message, or not at all.
    ///
    /// # Errors
    ///
    /// Storage and encoding errors as they occur, and a plan with files not
    /// yet bound to its message and carrier.
    pub(crate) fn keep_in_txn(&self, store: &Store, txn: &mut heed::RwTxn<'_>) -> Result<()> {
        let (manifest, carrier) = if self.attachments.is_empty() {
            (None, None)
        } else {
            let (Some(message), Some(carrier)) = (self.message, self.carrier.as_ref()) else {
                return Err(Error::InvalidConfig(
                    "a gmail send plan with files is kept only once its message is held".to_owned(),
                ));
            };
            let manifest = MailManifest {
                attachments: self.attachments.clone(),
                message,
            };
            (Some(manifest.digest()), Some(carrier.clone()))
        };
        let stored = StoredPlan {
            from_mailbox: self.from_mailbox.clone(),
            from_display_name: self.from_display_name.clone(),
            to: self.to.clone(),
            recipients: self.recipients.clone(),
            subject: self.subject.clone(),
            body_text: self.body_text.clone(),
            body_html: self.body_html.clone(),
            date: self.date.clone(),
            message_id: self.message_id.as_str().to_owned(),
            reply: self.reply.as_ref().map(|reply| StoredReply {
                gmail_thread_id: reply.gmail_thread_id.clone(),
                in_reply_to: reply.in_reply_to.as_str().to_owned(),
                references: reply
                    .references
                    .iter()
                    .map(|reference| reference.as_str().to_owned())
                    .collect(),
            }),
            manifest,
            carrier,
        };
        SEND_PLANS.put(store, txn, &self.content_ref, &stored)
    }

    /// The plan `vault` keeps under `content_ref`, when one stands and still
    /// seals to it. A plan with files stands only beside `holder`, the
    /// holder of exactly that plan's message in exactly the carrier its row
    /// names, whose own live row still keeps the manifest its row's digest
    /// names, each file's name and type still ones a part header carries;
    /// without one, it is no plan.
    pub(super) fn kept(
        vault: &Vault,
        content_ref: &str,
        holder: Option<&dyn RetainedMailMessage>,
    ) -> Result<Option<Self>> {
        let stored = {
            let txn = vault.store.env.read_txn()?;
            SEND_PLANS.get_lenient(&vault.store, &txn, &content_ref.to_owned())?
        };
        let Some(stored) = stored else {
            return Ok(None);
        };
        let reply = match stored.reply {
            Some(reply) => Some(GmailReplyThread {
                gmail_thread_id: reply.gmail_thread_id,
                in_reply_to: canonical_message_id(&reply.in_reply_to)?,
                references: reply
                    .references
                    .iter()
                    .map(String::as_str)
                    .map(canonical_message_id)
                    .collect::<Result<Vec<CanonicalMessageId>>>()?,
            }),
            None => None,
        };
        let (attachments, message, carrier) = match (stored.manifest, stored.carrier) {
            (None, None) => (Vec::new(), None, None),
            (Some(digest), Some(carrier)) => {
                let Some(holder) = holder.filter(|holder| {
                    holder.content_ref() == content_ref && holder.carrier_ref() == carrier
                }) else {
                    return Ok(None);
                };
                let Some(manifest) = holder
                    .manifest()?
                    .filter(|manifest| manifest.digest() == digest)
                else {
                    return Ok(None);
                };
                for file in &manifest.attachments {
                    file.validate()?;
                }
                (manifest.attachments, Some(manifest.message), Some(carrier))
            }
            _ => return Ok(None),
        };
        let mut plan = Self {
            from_mailbox: stored.from_mailbox,
            from_display_name: stored.from_display_name,
            to: stored.to,
            recipients: stored.recipients,
            subject: stored.subject,
            body_text: stored.body_text,
            body_html: stored.body_html,
            date: stored.date,
            message_id: canonical_message_id(&stored.message_id)?,
            reply,
            attachments,
            message,
            carrier,
            content_ref: String::new(),
        };
        plan.seal();
        Ok((plan.content_ref == content_ref).then_some(plan))
    }

    /// Drops the row kept under `content_ref`, once its send was delivered.
    pub(crate) fn drop_kept(vault: &Vault, content_ref: &str) -> Result<()> {
        vault.with_write_txn_grouped(|txn| Self::drop_kept_in_txn(&vault.store, txn, content_ref))
    }

    /// [`Self::drop_kept`] in `txn`, the writer that retires the plan's
    /// draft (fix list row 17645).
    pub(crate) fn drop_kept_in_txn(
        store: &Store,
        txn: &mut heed::RwTxn<'_>,
        content_ref: &str,
    ) -> Result<()> {
        SEND_PLANS.delete(store, txn, &content_ref.to_owned())?;
        Ok(())
    }
}
