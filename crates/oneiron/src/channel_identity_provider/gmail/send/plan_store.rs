//! The durable store of frozen Gmail send plans (FIX 1053). A plan its host
//! keeps is read back by its content ref, so a scheduled member send finds it
//! after a restart with no host registering it again. A row is checked as it
//! is read: it rebuilds through the plan's own Message-ID gate and seals to
//! the ref it is kept under, or it is no plan. A delivered send drops its
//! plan's row; its receipt keeps the ref. A plan with files keeps their
//! descriptions and its exact message's length and BLAKE3, never the
//! message: its host holds that (fix list row 17645).

use serde::{Deserialize, Serialize};

use super::{GmailReplyThread, GmailSendPlan};
use crate::Vault;
use crate::channel_identity_provider::mail_attachments::{MailAttachment, MailMessageIdentity};
use crate::error::Result;
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
    /// The files a plan sends, in their order (fix list row 17645).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    attachments: Vec<MailAttachment>,
    /// The exact message a plan with files sends: its length and BLAKE3.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    message: Option<MailMessageIdentity>,
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
    /// Storage and encoding errors as they occur.
    pub(crate) fn keep_in_txn(&self, store: &Store, txn: &mut heed::RwTxn<'_>) -> Result<()> {
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
            attachments: self.attachments.clone(),
            message: self.message,
        };
        SEND_PLANS.put(store, txn, &self.content_ref, &stored)
    }

    /// The plan `vault` keeps under `content_ref`, when one stands and still
    /// seals to it. A plan with files stands only beside the exact message
    /// it was sealed with, each file's name and type still ones a part
    /// header carries.
    pub(super) fn kept(vault: &Vault, content_ref: &str) -> Result<Option<Self>> {
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
        for file in &stored.attachments {
            file.validate()?;
        }
        if !stored.attachments.is_empty() && stored.message.is_none() {
            return Ok(None);
        }
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
            attachments: stored.attachments,
            message: stored.message,
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
