//! A drafted reply as the Internet message it sends (fix list rows 17872,
//! 17643): the frozen plain-text reply an IMAP mailbox submits over SMTP and
//! a Microsoft 365 mailbox sends through Graph. Every field the owner
//! approves is frozen when the draft is written and hashed into its content
//! ref, and the bytes sent are rendered from exactly those fields, with the
//! dispatch's frozen hygiene headers. One recipient or, for a reply to
//! several, every To and Cc in its role (fix list row 17645), no
//! attachments, UTF-8 text in base64 and, when drafted, an HTML alternative
//! beside it, threaded by `In-Reply-To` and `References` (RFC 5322).

use std::collections::BTreeMap;

use base64::Engine as _;
use serde::{Deserialize, Serialize};

use crate::channel_identity_provider::mail_html::{push_mail_body, sanitize_mail_html};
use crate::channel_identity_provider::native_mail::canonical_recipient;
use crate::error::{Error, Result};
use crate::outbound::{OutboundRecipient, OutboundRecipientRole};
use crate::write_envelope::thread_claim::{canonical_message_id, canonical_message_id_list};

/// The prefix of a frozen reply's content ref.
pub(super) const REPLY_MESSAGE_REF_PREFIX: &str = "mail-reply:message:v1:";
/// The longest Subject a reply carries, in bytes.
const MAX_SUBJECT_BYTES: usize = 900;
/// The longest body a reply carries, in bytes.
const MAX_BODY_BYTES: usize = 64 * 1024;
/// The most hygiene headers one send carries.
const MAX_HYGIENE_HEADERS: usize = 16;
/// The longest hygiene header value, in bytes.
const MAX_HYGIENE_VALUE_BYTES: usize = 900;
/// The most references a reply carries: the oldest go first beyond it.
const MAX_REFERENCES: usize = 50;

fn invalid(message: &str) -> Error {
    Error::InvalidConfig(format!("mail reply message: {message}"))
}

/// One reply, frozen as the owner approves it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct ReplyMessage {
    /// The mailbox it is sent from: the source's own address.
    pub(super) from: String,
    /// Its first recipient, in To, canonical.
    pub(super) to: String,
    /// Every recipient of a reply to several, canonical, in its role and
    /// place, `to` first (fix list row 17645); empty for a reply to `to`
    /// alone.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) recipients: Vec<OutboundRecipient>,
    pub(super) subject: String,
    pub(super) body: String,
    /// The HTML alternative, as the mail HTML gate wrote it again; `None`
    /// for plain text alone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) html: Option<String>,
    /// RFC 5322 `Date`, frozen when drafted.
    pub(super) date: String,
    /// Its own `Message-ID`, without angle brackets.
    pub(super) message_id: String,
    /// The answered message's `Message-ID`, without angle brackets.
    pub(super) in_reply_to: String,
    /// The thread's `References`, the answered message last, without angle
    /// brackets.
    pub(super) references: Vec<String>,
}

/// What a reply is written from.
pub(super) struct ReplyDraft<'d> {
    pub(super) from: &'d str,
    pub(super) to: &'d str,
    /// Every recipient of a reply to several, `to` first; empty for one.
    pub(super) recipients: &'d [OutboundRecipient],
    pub(super) subject: &'d str,
    pub(super) body: &'d str,
    /// The HTML alternative as drafted, before the mail HTML gate.
    pub(super) html: Option<&'d str>,
    /// The answered message's `Message-ID`.
    pub(super) parent_message_id: &'d str,
    /// The answered message's own `References`.
    pub(super) parent_references: &'d [String],
    /// The logical send it is: one per draft revision.
    pub(super) send_ref: &'d str,
    pub(super) composed_at: u64,
}

impl ReplyMessage {
    /// Freezes one reply.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] for a malformed sender or recipient, a
    /// recipient list that is no message's whole list, a Subject that is too
    /// long or carries a control character, a body that is too long, HTML the
    /// mail HTML gate refuses, a malformed `Message-ID`, or an
    /// unrepresentable time.
    pub(super) fn new(draft: &ReplyDraft<'_>) -> Result<Self> {
        let from = canonical_recipient(draft.from)?;
        let to = canonical_recipient(draft.to)?;
        let recipients = draft
            .recipients
            .iter()
            .map(|named| -> Result<OutboundRecipient> {
                Ok(OutboundRecipient::new(
                    named.role,
                    canonical_recipient(&named.address)?,
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        OutboundRecipient::check_list(&to, &recipients).map_err(invalid)?;
        header_text(draft.subject, MAX_SUBJECT_BYTES)?;
        if draft.body.len() > MAX_BODY_BYTES {
            return Err(invalid("the body is too long"));
        }
        let html = draft.html.map(sanitize_mail_html).transpose()?;
        let date = i64::try_from(draft.composed_at)
            .ok()
            .and_then(|secs| chrono::DateTime::from_timestamp(secs, 0))
            .ok_or_else(|| invalid("the time is out of range"))?
            .to_rfc2822();
        let in_reply_to = canonical_message_id(draft.parent_message_id)?;
        let mut references = canonical_message_id_list(draft.parent_references)?;
        references.retain(|reference| *reference != in_reply_to);
        references.push(in_reply_to.clone());
        let skip = references.len().saturating_sub(MAX_REFERENCES);
        let references: Vec<String> = references
            .into_iter()
            .skip(skip)
            .map(|reference| reference.as_str().to_owned())
            .collect();
        let domain = from
            .rsplit_once('@')
            .map(|(_, domain)| domain.to_owned())
            .ok_or_else(|| invalid("the sender has no domain"))?;
        let mut seed = blake3::Hasher::new();
        seed.update(b"oneiron.mail_pack.reply.message_id.v1");
        for part in [
            draft.send_ref,
            from.as_str(),
            to.as_str(),
            draft.subject,
            draft.body,
        ] {
            hash_part(&mut seed, part);
        }
        if let Some(html) = &html {
            hash_part(&mut seed, html);
        }
        let digest = seed.finalize().to_hex();
        let local = &digest.as_str()[..32];
        let message_id = canonical_message_id(&format!("<{local}.oneiron@{domain}>"))?
            .as_str()
            .to_owned();
        Ok(Self {
            from,
            to,
            recipients,
            subject: draft.subject.to_owned(),
            body: draft.body.to_owned(),
            html,
            date,
            message_id,
            in_reply_to: in_reply_to.as_str().to_owned(),
            references,
        })
    }

    /// The content ref the owner's approval names: every field the message
    /// is rendered from, hashed.
    pub(super) fn content_ref(&self) -> String {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"oneiron.mail_pack.reply.message.v1");
        for part in [
            self.from.as_str(),
            self.to.as_str(),
            self.subject.as_str(),
            self.body.as_str(),
            self.date.as_str(),
            self.message_id.as_str(),
            self.in_reply_to.as_str(),
        ] {
            hash_part(&mut hasher, part);
        }
        hasher.update(&(self.references.len() as u64).to_le_bytes());
        for reference in &self.references {
            hash_part(&mut hasher, reference);
        }
        // An HTML alternative follows the counted references (fix list row
        // 17645); plain text alone hashes as before.
        if let Some(html) = &self.html {
            hasher.update(b"html");
            hash_part(&mut hasher, html);
        }
        // So do the recipients of a reply to several, counted, each in its
        // role and place; a reply to one hashes as before.
        if !self.recipients.is_empty() {
            hasher.update(b"recipients");
            hasher.update(&(self.recipients.len() as u64).to_le_bytes());
            for named in &self.recipients {
                hash_part(&mut hasher, named.role.as_str());
                hash_part(&mut hasher, &named.address);
            }
        }
        format!("{REPLY_MESSAGE_REF_PREFIX}{}", hasher.finalize().to_hex())
    }

    /// Every address the reply is delivered to, in its place: `to` alone,
    /// or each recipient of a reply to several.
    pub(super) fn delivery_addresses(&self) -> Vec<&str> {
        if self.recipients.is_empty() {
            vec![self.to.as_str()]
        } else {
            self.recipients
                .iter()
                .map(|named| named.address.as_str())
                .collect()
        }
    }

    /// The RFC 5322 bytes, with the hygiene headers the dispatch froze. The
    /// body is base64, so no line of its text reaches the header block or
    /// passes the line limit.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] for too many hygiene headers, a name that is
    /// no plain token or restates a header the message owns, or a value with
    /// a control character.
    pub(super) fn render(&self, hygiene_headers: &BTreeMap<String, String>) -> Result<Vec<u8>> {
        if hygiene_headers.len() > MAX_HYGIENE_HEADERS {
            return Err(invalid("too many hygiene headers"));
        }
        let mut out = String::new();
        push_header(&mut out, "From", &self.from);
        if self.recipients.is_empty() {
            push_header(&mut out, "To", &self.to);
        } else {
            for (role, name) in [
                (OutboundRecipientRole::To, "To"),
                (OutboundRecipientRole::Cc, "Cc"),
            ] {
                let addresses = self
                    .recipients
                    .iter()
                    .filter(|named| named.role == role)
                    .map(|named| named.address.as_str())
                    .collect::<Vec<_>>();
                if !addresses.is_empty() {
                    push_header(&mut out, name, &addresses.join(",\r\n "));
                }
            }
        }
        push_header(&mut out, "Subject", &encode_word(&self.subject));
        push_header(&mut out, "Date", &self.date);
        push_header(&mut out, "Message-ID", &format!("<{}>", self.message_id));
        push_header(&mut out, "In-Reply-To", &format!("<{}>", self.in_reply_to));
        let references = self
            .references
            .iter()
            .map(|reference| format!("<{reference}>"))
            .collect::<Vec<_>>()
            .join("\r\n ");
        push_header(&mut out, "References", &references);
        for (name, value) in hygiene_headers {
            if name.is_empty()
                || !name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                || owned_header(name)
            {
                return Err(invalid("a hygiene header name is not a plain token"));
            }
            header_text(value, MAX_HYGIENE_VALUE_BYTES)?;
            push_header(&mut out, name, value);
        }
        push_header(&mut out, "MIME-Version", "1.0");
        push_mail_body(&mut out, &self.body, self.html.as_deref());
        Ok(out.into_bytes())
    }
}

fn hash_part(hasher: &mut blake3::Hasher, part: &str) {
    hasher.update(&(part.len() as u64).to_le_bytes());
    hasher.update(part.as_bytes());
}

fn push_header(out: &mut String, name: &str, value: &str) {
    out.push_str(name);
    out.push_str(": ");
    out.push_str(value);
    out.push_str("\r\n");
}

/// A header the message writes itself; a hygiene header may not restate it.
fn owned_header(name: &str) -> bool {
    [
        "from",
        "sender",
        "reply-to",
        "to",
        "cc",
        "bcc",
        "subject",
        "date",
        "message-id",
        "in-reply-to",
        "references",
        "mime-version",
        "content-type",
        "content-transfer-encoding",
    ]
    .iter()
    .any(|owned| name.eq_ignore_ascii_case(owned))
}

/// Header text carries no line break or other control character: that is
/// how a value would smuggle a second header into the block.
fn header_text(value: &str, max: usize) -> Result<()> {
    if value.len() > max {
        return Err(invalid("a header is too long"));
    }
    if value.chars().any(char::is_control) {
        return Err(invalid("a header carries a control character"));
    }
    Ok(())
}

/// RFC 2047 `B` encoded words for non-ASCII header text; ASCII passes as it
/// is. No word passes 75 bytes.
fn encode_word(text: &str) -> String {
    if text.is_ascii() {
        return text.to_owned();
    }
    let mut words = Vec::new();
    let mut chunk = String::new();
    for character in text.chars() {
        if chunk.len() + character.len_utf8() > 45 {
            words.push(std::mem::take(&mut chunk));
        }
        chunk.push(character);
    }
    if !chunk.is_empty() {
        words.push(chunk);
    }
    words
        .iter()
        .map(|word| {
            format!(
                "=?UTF-8?B?{}?=",
                base64::engine::general_purpose::STANDARD.encode(word.as_bytes())
            )
        })
        .collect::<Vec<_>>()
        .join("\r\n ")
}
