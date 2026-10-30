//! The durable store of frozen Gmail send plans (FIX 1053). A plan its host
//! keeps is read back by its content ref, so a scheduled member send finds it
//! after a restart with no host registering it again. A row is checked as it
//! is read: it rebuilds through the plan's own Message-ID gate and seals to
//! the ref it is kept under, or it is no plan. A delivered send drops its
//! plan's row; its receipt keeps the ref.

use serde::{Deserialize, Serialize};

use super::{GmailReplyThread, GmailSendPlan};
use crate::Vault;
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};
use crate::thread_passport::{CanonicalMessageId, canonical_message_id};

const SEND_PLANS: SideTable<String, StoredPlan, Named> =
    SideTable::new(&side_table::GMAIL_SEND_PLAN);

/// A plan's fields as its row keeps them.
#[derive(Serialize, Deserialize)]
struct StoredPlan {
    from_mailbox: String,
    from_display_name: Option<String>,
    to: String,
    subject: String,
    body_text: String,
    date: String,
    message_id: String,
    reply: Option<StoredReply>,
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
        let stored = StoredPlan {
            from_mailbox: self.from_mailbox.clone(),
            from_display_name: self.from_display_name.clone(),
            to: self.to.clone(),
            subject: self.subject.clone(),
            body_text: self.body_text.clone(),
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
        };
        vault.with_write_txn_grouped(|txn| {
            SEND_PLANS.put(&vault.store, txn, &self.content_ref, &stored)
        })
    }

    /// The plan `vault` keeps under `content_ref`, when one stands and still
    /// seals to it.
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
        let mut plan = Self {
            from_mailbox: stored.from_mailbox,
            from_display_name: stored.from_display_name,
            to: stored.to,
            subject: stored.subject,
            body_text: stored.body_text,
            date: stored.date,
            message_id: canonical_message_id(&stored.message_id)?,
            reply,
            content_ref: String::new(),
        };
        plan.seal();
        Ok((plan.content_ref == content_ref).then_some(plan))
    }

    /// Drops the row kept under `content_ref`, once its send was delivered.
    pub(super) fn drop_kept(vault: &Vault, content_ref: &str) -> Result<()> {
        vault.with_write_txn_grouped(|txn| {
            SEND_PLANS.delete(&vault.store, txn, &content_ref.to_owned())?;
            Ok(())
        })
    }
}
