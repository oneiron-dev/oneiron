//! The durable store of frozen Gmail send plans (FIX 1053). A plan its host
//! keeps is read back by its content ref, so a scheduled member send finds it
//! after a restart with no host registering it again. A row is checked as it
//! is read: it rebuilds through the plan's own Message-ID gate and seals to
//! the ref it is kept under, or it is no plan. A delivered send drops its
//! plan's row; its receipt keeps the ref.
//!
//! A plan with files (fix list row 17645) is not kept here: the holder of
//! its message keeps it, as the stub [`GmailSendPlan::stub`] writes, sealed
//! beside that message and gone with it. The stub keeps no file's name, ref
//! or hash and never the message: only the digest of its manifest and the
//! ref of the carrier its message is held in, and the plan stands only
//! while that holder still keeps both.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::{GMAIL_ATTACHED_SEND_PLAN_REF_PREFIX, GmailReplyThread, GmailSendPlan};
use crate::Vault;
use crate::channel_identity_provider::mail_attachments::{MailManifest, RetainedMailMessage};
use crate::error::{Error, Result};
use crate::outbound::OutboundRecipient;
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
    /// The plan's fields as a row keeps them, with `manifest` and `carrier`
    /// for a plan with files.
    fn stored(&self, manifest: Option<[u8; 32]>, carrier: Option<String>) -> StoredPlan {
        StoredPlan {
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
        }
    }

    /// Keeps this plan in `vault` under its content ref, for a send that
    /// dispatches later, a scheduled connector-TASK member send among them.
    /// Keeping it again writes the same row.
    ///
    /// # Errors
    ///
    /// Storage and encoding errors as they occur, and a plan with files,
    /// which the holder of its message keeps ([`Self::stub`]).
    pub fn keep(&self, vault: &Vault) -> Result<()> {
        if !self.attachments.is_empty() {
            return Err(Error::InvalidConfig(
                "a gmail send plan with files is kept by the holder of its message".to_owned(),
            ));
        }
        let stored = self.stored(None, None);
        vault.with_write_txn_grouped(|txn| {
            SEND_PLANS.put(&vault.store, txn, &self.content_ref, &stored)
        })
    }

    /// The stub a plan with files is kept as, by the holder of its message
    /// and sealed beside it (fix list row 17645): every field a kept plan
    /// keeps, then the digest of its manifest and the ref of its carrier,
    /// never a file's name, ref or hash.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] for a plan without files, or one with files
    /// not yet bound to its message and carrier.
    pub(crate) fn stub(&self) -> Result<Zeroizing<Vec<u8>>> {
        let (Some(message), Some(carrier)) = (self.message, self.carrier.as_ref()) else {
            return Err(Error::InvalidConfig(
                "a gmail send plan with files is kept only once its message is held".to_owned(),
            ));
        };
        if self.attachments.is_empty() {
            return Err(Error::InvalidConfig(
                "a gmail send plan without files is kept in the plan store".to_owned(),
            ));
        }
        let manifest = MailManifest {
            attachments: self.attachments.clone(),
            message,
        };
        let stored = self.stored(Some(manifest.digest()), Some(carrier.clone()));
        serde_json::to_vec(&stored)
            .map(Zeroizing::new)
            .map_err(|_| Error::InvariantViolation("gmail send plan stub"))
    }

    /// The plan kept under `content_ref`, when one stands and still seals to
    /// it. A plan without files is read from `vault`'s plan store, as
    /// before. A plan with files stands only beside `holder`, the holder of
    /// exactly that plan's message in exactly the carrier its stub names,
    /// which still keeps that stub and the manifest its digest names, each
    /// file's name and type still ones a part header carries; without one,
    /// it is no plan.
    pub(super) fn kept(
        vault: &Vault,
        content_ref: &str,
        holder: Option<&dyn RetainedMailMessage>,
    ) -> Result<Option<Self>> {
        let attached = content_ref.starts_with(GMAIL_ATTACHED_SEND_PLAN_REF_PREFIX);
        let holder = holder.filter(|holder| holder.content_ref() == content_ref);
        let stored = if attached {
            let Some(stub) = holder
                .map(|holder| holder.plan_stub())
                .transpose()?
                .flatten()
            else {
                return Ok(None);
            };
            serde_json::from_slice::<StoredPlan>(&stub).ok()
        } else {
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
        let (attachments, message, carrier) = match (attached, stored.manifest, stored.carrier) {
            (false, None, None) => (Vec::new(), None, None),
            (true, Some(digest), Some(carrier)) => {
                let Some(holder) = holder.filter(|holder| holder.carrier_ref() == carrier) else {
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
        vault.with_write_txn_grouped(|txn| {
            SEND_PLANS.delete(&vault.store, txn, &content_ref.to_owned())?;
            Ok(())
        })
    }
}
