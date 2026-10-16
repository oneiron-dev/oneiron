//! Member send-as through a Gmail delegated row (OF-374).
//!
//! A member's own mailbox sends as the member, never as the product. The
//! pieces, in the order a send meets them:
//!
//! * **A frozen plan.** [`GmailSendPlan`] fixes From (the member's mailbox and
//!   nothing else), To, Subject, body, Date, the RFC `Message-ID` and the reply
//!   headers BEFORE anyone approves anything. Its content ref is a digest of
//!   all of them, the host puts that ref on `intent.content_ref`, and the
//!   canonical mail approve-once digest binds it. So the press the owner gives
//!   is for these exact bytes; a reworded draft is a new plan and a new press.
//! * **One gated write.** [`GmailDelegatedAdapter::dispatch_send_recorded`]
//!   checks the envelope names this adapter's live send-capable row and then
//!   crosses the ordinary recorded dispatch door: recipient binding, STOP and
//!   opt-out hydration, the Gate, the intent ledger and the outbound receipt
//!   are the ones every send uses. Whether a press is needed "depends on the
//!   grant" (ARCH-0046): a per-send press through
//!   [`GmailDelegatedAdapter::approve_send_once`], or a standing grant that
//!   covers the send.
//! * **A send-only credential door.** [`GmailSendAuthority`] re-proves the row
//!   AND the custody record (send evidence included) at the instant of egress,
//!   then injects the token at the SECRET-02 door. The read door's authority
//!   is never send authority, and a send-only grant cannot read.
//! * **Typed delivery certainty.** The wire reports [`GmailSendWireError`]
//!   `NotSent` only when Google provably did not accept the message; anything
//!   else is `Uncertain`, which the ledger resolves as ambiguous rather than
//!   resending: `users.messages.send` is not idempotent.
//! * **Thread record.** A delivered send records its `(identity × Message-ID)`
//!   passport with its References and In-Reply-To, beside the Gmail threadId on
//!   the receipt, and touches comm history for the recipient.

use std::cell::Cell;
use std::collections::BTreeMap;

use base64::Engine as _;

use super::{EMAIL_CHANNEL, GmailDelegatedAdapter, MAX_GMAIL_THREAD_ID_BYTES, validate_gmail_id};
use crate::Vault;
use crate::channel_identity_provider::native_mail::{
    approve_canonical_mail_send_once, canonical_mail_send_digest, canonical_recipient,
};
use crate::consent::{AuthenticatedOwner, ConsentReceipt};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::outbound::{
    OutboundDispatchError, OutboundDispatchOutcome, OutboundDispatchRequest,
    OutboundDispatchResult, OutboundExecutionOutcome, OutboundExecutionRequest,
    OutboundExecutionSink,
};
use crate::secret_lease::DoorInjectionReceipt;
use crate::thread_passport::{
    CanonicalMessageId, ThreadPassportInput, canonical_message_id, canonical_message_id_list,
};

/// Prefix of every Gmail send plan's content ref.
pub const GMAIL_SEND_PLAN_REF_PREFIX: &str = "gmail:plan:v1:";

const RECEIPT_GMAIL_MESSAGE_ID: &str = "gmail_message_id";
const RECEIPT_GMAIL_THREAD_ID: &str = "gmail_thread_id";
const RECEIPT_RFC_MESSAGE_ID: &str = "rfc_message_id";
const RECEIPT_RFC_MESSAGE_ID_SOURCE: &str = "rfc_message_id_source";
const RECEIPT_RFC_IN_REPLY_TO: &str = "rfc_in_reply_to";
const RECEIPT_RFC_REFERENCES: &str = "rfc_references";
const RECEIPT_SEND_PLAN_REF: &str = "gmail_send_plan_ref";
const RECEIPT_SEND_ERROR: &str = "gmail_send_error";

/// Room a `Subject:` line leaves inside RFC 5322's 998-byte line limit once
/// encoded-word overhead is allowed for.
const MAX_SUBJECT_BYTES: usize = 600;
const MAX_DISPLAY_NAME_BYTES: usize = 256;
/// Gmail accepts 35 MB raw; a plain-text member reply needs far less.
const MAX_BODY_BYTES: usize = 4 * 1024 * 1024;
const MAX_REFERENCES: usize = 64;
const MAX_HYGIENE_HEADERS: usize = 8;

/// The reply half of a send: the Gmail thread it joins and its RFC parents.
///
/// Gmail files a sent message into `thread_id` only when the References and
/// In-Reply-To headers agree and the Subject matches the thread's; the host
/// supplies the original Subject. `References` always ends with the parent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GmailReplyThread {
    gmail_thread_id: String,
    in_reply_to: CanonicalMessageId,
    references: Vec<CanonicalMessageId>,
}

impl GmailReplyThread {
    /// Builds the reply half from the parent's Gmail thread id, the parent's
    /// RFC `Message-ID`, and the parent's own `References` chain.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] for a malformed thread id or Message-ID, or a
    /// chain longer than 64 entries.
    pub fn new<S: AsRef<str>>(
        gmail_thread_id: &str,
        in_reply_to: &str,
        parent_references: &[S],
    ) -> Result<Self> {
        validate_gmail_id(
            gmail_thread_id,
            MAX_GMAIL_THREAD_ID_BYTES,
            "gmail thread id",
        )?;
        let in_reply_to = canonical_message_id(in_reply_to)?;
        let mut references = canonical_message_id_list(parent_references)?;
        references.retain(|reference| reference != &in_reply_to);
        references.push(in_reply_to.clone());
        if references.len() > MAX_REFERENCES {
            return Err(Error::InvalidConfig(format!(
                "gmail reply References exceeds {MAX_REFERENCES} entries"
            )));
        }
        Ok(Self {
            gmail_thread_id: gmail_thread_id.to_owned(),
            in_reply_to,
            references,
        })
    }

    /// The Gmail thread this reply joins.
    #[must_use]
    pub fn gmail_thread_id(&self) -> &str {
        &self.gmail_thread_id
    }
}

/// One frozen member send. No public field and no setter: every builder
/// re-seals the content ref, so the ref always names these exact fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GmailSendPlan {
    from_mailbox: String,
    from_display_name: Option<String>,
    to: String,
    subject: String,
    body_text: String,
    date: String,
    message_id: CanonicalMessageId,
    reply: Option<GmailReplyThread>,
    content_ref: String,
}

impl GmailSendPlan {
    /// Freezes one plain-text send from the adapter's member mailbox.
    ///
    /// `logical_ref` is the send's stable logical id (the dispatch
    /// `intent_ref`); it seeds the RFC `Message-ID`, so the same draft always
    /// carries the same id and two different sends never share one.
    /// `composed_at` (Unix seconds) is frozen as the `Date:` header.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] for a malformed recipient, a header-unsafe or
    /// over-long Subject, an over-long body, or an unrepresentable time.
    pub fn new(
        adapter: &GmailDelegatedAdapter,
        logical_ref: &str,
        to: &str,
        subject: &str,
        body_text: &str,
        reply: Option<GmailReplyThread>,
        composed_at: u64,
    ) -> Result<Self> {
        if logical_ref.trim().is_empty() {
            return Err(Error::InvalidConfig(
                "gmail send plan requires a logical send ref".to_owned(),
            ));
        }
        let from_mailbox = adapter.config().mailbox_address().to_owned();
        let to = canonical_recipient(to)?;
        validate_header_text(subject, MAX_SUBJECT_BYTES, "gmail send subject")?;
        if body_text.len() > MAX_BODY_BYTES {
            return Err(Error::InvalidConfig(format!(
                "gmail send body exceeds {MAX_BODY_BYTES} bytes"
            )));
        }
        let date = i64::try_from(composed_at)
            .ok()
            .and_then(|secs| chrono::DateTime::from_timestamp(secs, 0))
            .ok_or_else(|| Error::InvalidConfig("gmail send composed_at out of range".to_owned()))?
            .to_rfc2822();
        let domain = from_mailbox
            .rsplit_once('@')
            .map(|(_, domain)| domain)
            .ok_or_else(|| Error::InvalidConfig("gmail mailbox has no domain".to_owned()))?;
        let mut seed = blake3::Hasher::new();
        seed.update(b"oneiron.gmail.send.message_id.v1");
        for part in [
            logical_ref,
            from_mailbox.as_str(),
            to.as_str(),
            subject,
            body_text,
        ] {
            hash_part(&mut seed, part);
        }
        let digest = seed.finalize().to_hex();
        let local = &digest.as_str()[..32];
        let message_id = canonical_message_id(&format!("<{local}.oneiron@{domain}>"))?;
        let mut plan = Self {
            from_mailbox,
            from_display_name: None,
            to,
            subject: subject.to_owned(),
            body_text: body_text.to_owned(),
            date,
            message_id,
            reply,
            content_ref: String::new(),
        };
        plan.seal();
        Ok(plan)
    }

    /// Sets the From display name (the member's own name, e.g. "Yura"). The
    /// address stays the member's mailbox; only the phrase is added.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] for a blank, header-unsafe or over-long name.
    pub fn with_display_name(mut self, display_name: &str) -> Result<Self> {
        validate_header_text(
            display_name,
            MAX_DISPLAY_NAME_BYTES,
            "gmail From display name",
        )?;
        if display_name.trim().is_empty() {
            return Err(Error::InvalidConfig(
                "gmail From display name must not be blank".to_owned(),
            ));
        }
        self.from_display_name = Some(display_name.trim().to_owned());
        self.seal();
        Ok(self)
    }

    /// The content ref the host puts on `intent.content_ref`.
    #[must_use]
    pub fn content_ref(&self) -> &str {
        &self.content_ref
    }

    /// The canonical recipient this plan sends to.
    #[must_use]
    pub fn recipient(&self) -> &str {
        &self.to
    }

    /// The RFC `Message-ID` this plan mints.
    #[must_use]
    pub const fn message_id(&self) -> &CanonicalMessageId {
        &self.message_id
    }

    /// The reply half, when this send answers a thread.
    #[must_use]
    pub const fn reply(&self) -> Option<&GmailReplyThread> {
        self.reply.as_ref()
    }

    fn seal(&mut self) {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"oneiron.gmail.send.plan.v1");
        hash_part(&mut hasher, &self.from_mailbox);
        hash_optional(&mut hasher, self.from_display_name.as_deref());
        for part in [
            self.to.as_str(),
            self.subject.as_str(),
            self.body_text.as_str(),
            self.date.as_str(),
            self.message_id.as_str(),
        ] {
            hash_part(&mut hasher, part);
        }
        match &self.reply {
            Some(reply) => {
                hasher.update(&[1]);
                hash_part(&mut hasher, &reply.gmail_thread_id);
                hash_part(&mut hasher, reply.in_reply_to.as_str());
                hasher.update(&(reply.references.len() as u64).to_le_bytes());
                for reference in &reply.references {
                    hash_part(&mut hasher, reference.as_str());
                }
            }
            None => {
                hasher.update(&[0]);
            }
        }
        self.content_ref = format!("{GMAIL_SEND_PLAN_REF_PREFIX}{}", hasher.finalize().to_hex());
    }

    /// Renders the RFC 5322 bytes, with the CA-05 hygiene headers replayed
    /// from the frozen dispatch payload. The body is base64 so no line of user
    /// text can reach the header block or exceed the line limit.
    fn render(&self, hygiene_headers: &BTreeMap<String, String>) -> Result<Vec<u8>> {
        if hygiene_headers.len() > MAX_HYGIENE_HEADERS {
            return Err(Error::InvalidConfig(
                "gmail send carries too many hygiene headers".to_owned(),
            ));
        }
        let mut out = String::new();
        match &self.from_display_name {
            Some(name) => push_header(
                &mut out,
                "From",
                &format!("{} <{}>", encode_word(name), self.from_mailbox),
            ),
            None => push_header(&mut out, "From", &self.from_mailbox),
        }
        push_header(&mut out, "To", &self.to);
        push_header(&mut out, "Subject", &encode_word(&self.subject));
        push_header(&mut out, "Date", &self.date);
        push_header(&mut out, "Message-ID", &format!("<{}>", self.message_id));
        if let Some(reply) = &self.reply {
            push_header(&mut out, "In-Reply-To", &format!("<{}>", reply.in_reply_to));
            let references = reply
                .references
                .iter()
                .map(|reference| format!("<{reference}>"))
                .collect::<Vec<_>>()
                .join("\r\n ");
            push_header(&mut out, "References", &references);
        }
        for (name, value) in hygiene_headers {
            if name.is_empty()
                || !name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                || is_reserved_header(name)
            {
                return Err(Error::InvalidConfig(
                    "gmail send hygiene header name is not a plain token".to_owned(),
                ));
            }
            validate_header_text(value, 900, "gmail send hygiene header")?;
            push_header(&mut out, name, value);
        }
        push_header(&mut out, "MIME-Version", "1.0");
        push_header(&mut out, "Content-Type", "text/plain; charset=UTF-8");
        push_header(&mut out, "Content-Transfer-Encoding", "base64");
        out.push_str("\r\n");
        let body = self.body_text.replace("\r\n", "\n").replace('\n', "\r\n");
        let encoded = base64::engine::general_purpose::STANDARD.encode(body.as_bytes());
        for chunk in encoded.as_bytes().chunks(76) {
            out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
            out.push_str("\r\n");
        }
        Ok(out.into_bytes())
    }
}

fn hash_part(hasher: &mut blake3::Hasher, part: &str) {
    hasher.update(&(part.len() as u64).to_le_bytes());
    hasher.update(part.as_bytes());
}

fn hash_optional(hasher: &mut blake3::Hasher, part: Option<&str>) {
    match part {
        Some(part) => {
            hasher.update(&[1]);
            hash_part(hasher, part);
        }
        None => {
            hasher.update(&[0]);
        }
    }
}

fn push_header(out: &mut String, name: &str, value: &str) {
    out.push_str(name);
    out.push_str(": ");
    out.push_str(value);
    out.push_str("\r\n");
}

/// The plan owns these; a hygiene header may not restate one.
fn is_reserved_header(name: &str) -> bool {
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
    .any(|reserved| name.eq_ignore_ascii_case(reserved))
}

/// Header text may not carry a line break or any other control character:
/// that is how a value would smuggle a second header into the block.
fn validate_header_text(value: &str, max: usize, label: &str) -> Result<()> {
    if value.len() > max {
        return Err(Error::InvalidConfig(format!("{label} exceeds {max} bytes")));
    }
    if value.chars().any(char::is_control) {
        return Err(Error::InvalidConfig(format!(
            "{label} must not contain control characters"
        )));
    }
    Ok(())
}

/// RFC 2047 `B` encoded-word for non-ASCII header text; printable ASCII
/// passes through unchanged. Long text is split so no word exceeds 75 bytes.
fn encode_word(text: &str) -> String {
    if text.is_ascii() {
        return text.to_owned();
    }
    let mut words = Vec::new();
    let mut chunk = String::new();
    for ch in text.chars() {
        if chunk.len() + ch.len_utf8() > 45 {
            words.push(std::mem::take(&mut chunk));
        }
        chunk.push(ch);
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

/// What Google acknowledged for one sent message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GmailSentMessage {
    /// Gmail's REST message id (never an RFC Message-ID).
    pub gmail_message_id: String,
    /// The Gmail thread the message landed in.
    pub gmail_thread_id: String,
    /// The RFC `Message-ID` Gmail kept on the sent message, when the wire read
    /// it back; `None` keeps the plan's minted id.
    pub rfc_message_id: Option<String>,
}

/// Typed delivery certainty for one `users.messages.send` call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GmailSendWireError {
    /// Google provably did not accept the message (no request left the host,
    /// the credential door refused, or Google answered a 4xx).
    NotSent(String),
    /// The message may have been accepted; never resend blindly.
    Uncertain(String),
}

/// The Gmail send protocol seam: exactly one method, sending.
///
/// Implementations MUST resolve the token through
/// `authority.with_token_at_door` and make the provider request inside its
/// callback. A wire that reports success without using that door is treated
/// as a possible delivery that this engine did not authorize at egress.
pub trait GmailSendWire {
    /// Sends `raw` (RFC 5322 bytes) as the member, into `gmail_thread_id`
    /// when the send is a reply.
    ///
    /// # Errors
    ///
    /// [`GmailSendWireError`], with its delivery certainty.
    fn send_message(
        &self,
        authority: &GmailSendAuthority<'_>,
        raw: &[u8],
        gmail_thread_id: Option<&str>,
    ) -> std::result::Result<GmailSentMessage, GmailSendWireError>;
}

/// A mailbox- and identity-bound SEND handle supplied to the host wire.
///
/// No public constructor or credential field, and no relation to
/// [`super::GmailReadAuthority`]: holding a read handle never opens this door.
pub struct GmailSendAuthority<'a> {
    adapter: &'a GmailDelegatedAdapter,
    vault: &'a Vault,
    identity_id: EntityId,
    used: Cell<bool>,
}

impl GmailSendAuthority<'_> {
    /// Resolve the member's token at the send-aware SECRET-02 egress and make
    /// the provider request inside `apply`.
    ///
    /// # Errors
    ///
    /// When the row was withdrawn, the grant lost send, or custody no longer
    /// proves it, the callback is not invoked.
    pub fn with_token_at_door(
        &self,
        apply: &mut dyn FnMut(&[u8]) -> Result<()>,
    ) -> Result<DoorInjectionReceipt> {
        let mut guarded = |token: &[u8]| {
            apply(token)?;
            self.used.set(true);
            Ok(())
        };
        self.adapter
            .with_send_token_at_door(self.vault, self.identity_id, &mut guarded)
    }
}

/// OF-327 execution sink for a member's Gmail send.
///
/// Holds the frozen plans the host composed, keyed by content ref. The sink
/// sends only a plan whose ref the dispatched intent names, from this
/// adapter's mailbox, to the recipient the dispatch door bound.
pub struct GmailSendSink<'a, W> {
    vault: &'a Vault,
    adapter: &'a GmailDelegatedAdapter,
    identity_id: EntityId,
    wire: W,
    plans: BTreeMap<String, GmailSendPlan>,
}

impl<'a, W> GmailSendSink<'a, W> {
    /// Binds the sink to one adapter, its identity row and a send wire.
    #[must_use]
    pub const fn new(
        vault: &'a Vault,
        adapter: &'a GmailDelegatedAdapter,
        identity_id: EntityId,
        wire: W,
    ) -> Self {
        Self {
            vault,
            adapter,
            identity_id,
            wire,
            plans: BTreeMap::new(),
        }
    }

    /// Registers one frozen plan.
    #[must_use]
    pub fn with_plan(mut self, plan: GmailSendPlan) -> Self {
        self.add_plan(plan);
        self
    }

    /// Registers one frozen plan.
    pub fn add_plan(&mut self, plan: GmailSendPlan) {
        self.plans.insert(plan.content_ref.clone(), plan);
    }

    /// The plan a content ref names, if registered.
    #[must_use]
    pub fn plan(&self, content_ref: &str) -> Option<&GmailSendPlan> {
        self.plans.get(content_ref)
    }

    #[must_use]
    pub const fn wire(&self) -> &W {
        &self.wire
    }
}

impl<W: GmailSendWire> OutboundExecutionSink for GmailSendSink<'_, W> {
    fn execute(&mut self, request: &OutboundExecutionRequest<'_>) -> OutboundExecutionOutcome {
        if request.intent.channel != EMAIL_CHANNEL || request.verb_contract.kind != "send" {
            return OutboundExecutionOutcome::failed("gmail_send_requires_email_send");
        }
        if request.channel_identity_ref != Some(self.identity_id) {
            return OutboundExecutionOutcome::failed("gmail_send_identity_mismatch");
        }
        // Calendar invites ride the transactional domain (ARCH-0060), not a
        // member mailbox; refusing beats sending an email about a meeting.
        if request.calendar_invite.is_some() {
            return OutboundExecutionOutcome::failed("gmail_send_calendar_invite_unsupported");
        }
        let Some(plan) = request
            .intent
            .content_ref
            .as_deref()
            .and_then(|content_ref| self.plans.get(content_ref))
        else {
            return OutboundExecutionOutcome::failed("gmail_send_plan_missing");
        };
        let recipient = request.counterparty_ref.unwrap_or(&request.intent.target);
        if plan.to != recipient || plan.to != request.intent.target {
            return OutboundExecutionOutcome::failed("gmail_send_target_mismatch");
        }
        if plan.from_mailbox != self.adapter.config().mailbox_address() {
            return OutboundExecutionOutcome::failed("gmail_send_sender_mismatch");
        }
        let Ok(raw) = plan.render(&request.hygiene_headers) else {
            return OutboundExecutionOutcome::failed("gmail_send_headers_invalid");
        };
        let mut fields = BTreeMap::new();
        fields.insert(RECEIPT_SEND_PLAN_REF.to_owned(), plan.content_ref.clone());
        if let Some(reply) = &plan.reply {
            fields.insert(
                RECEIPT_RFC_IN_REPLY_TO.to_owned(),
                reply.in_reply_to.as_str().to_owned(),
            );
            fields.insert(
                RECEIPT_RFC_REFERENCES.to_owned(),
                reply
                    .references
                    .iter()
                    .map(CanonicalMessageId::as_str)
                    .collect::<Vec<_>>()
                    .join(" "),
            );
        }
        let authority = GmailSendAuthority {
            adapter: self.adapter,
            vault: self.vault,
            identity_id: self.identity_id,
            used: Cell::new(false),
        };
        let thread_id = plan.reply.as_ref().map(GmailReplyThread::gmail_thread_id);
        match self.wire.send_message(&authority, &raw, thread_id) {
            Ok(sent) => {
                let ids_valid = validate_gmail_id(
                    &sent.gmail_message_id,
                    super::MAX_GMAIL_MESSAGE_ID_BYTES,
                    "gmail message id",
                )
                .and_then(|()| {
                    validate_gmail_id(
                        &sent.gmail_thread_id,
                        MAX_GMAIL_THREAD_ID_BYTES,
                        "gmail thread id",
                    )
                })
                .is_ok();
                if !authority.used.get() || !ids_valid {
                    fields.insert(
                        RECEIPT_SEND_ERROR.to_owned(),
                        "gmail_send_unverified_acknowledgement".to_owned(),
                    );
                    return OutboundExecutionOutcome::failed(
                        "gmail_send_unverified_acknowledgement",
                    )
                    .with_receipt_fields(fields)
                    .with_possible_delivery();
                }
                let (rfc_message_id, source) =
                    match sent.rfc_message_id.as_deref().map(canonical_message_id) {
                        Some(Ok(observed)) => (observed, "provider"),
                        _ => (plan.message_id.clone(), "plan"),
                    };
                fields.insert(
                    RECEIPT_GMAIL_MESSAGE_ID.to_owned(),
                    sent.gmail_message_id.clone(),
                );
                fields.insert(
                    RECEIPT_GMAIL_THREAD_ID.to_owned(),
                    sent.gmail_thread_id.clone(),
                );
                fields.insert(
                    RECEIPT_RFC_MESSAGE_ID.to_owned(),
                    rfc_message_id.into_string(),
                );
                fields.insert(RECEIPT_RFC_MESSAGE_ID_SOURCE.to_owned(), source.to_owned());
                OutboundExecutionOutcome::delivered_to_channel(format!(
                    "gmail:{}",
                    sent.gmail_message_id
                ))
                .with_receipt_fields(fields)
            }
            Err(GmailSendWireError::NotSent(reason)) => {
                fields.insert(RECEIPT_SEND_ERROR.to_owned(), reason.clone());
                OutboundExecutionOutcome::failed(reason).with_receipt_fields(fields)
            }
            Err(GmailSendWireError::Uncertain(reason)) => {
                fields.insert(RECEIPT_SEND_ERROR.to_owned(), reason.clone());
                OutboundExecutionOutcome::failed(reason)
                    .with_receipt_fields(fields)
                    .with_possible_delivery()
            }
        }
    }
}

impl GmailDelegatedAdapter {
    /// The SEND credential door: runs `apply` with the grant's token for a
    /// LIVE send-capable row this adapter speaks for.
    ///
    /// Three checks, all before the injection: the adapter's grant carries
    /// `mail.send`; the stored row is this adapter's ACTIVE row with that same
    /// scope set; and the custody record still proves the grant, including the
    /// provider's granted-send evidence. That last re-proof is the egress-time
    /// one: a member who narrowed their Google consent after the row went live
    /// leaves a host that re-registers custody without the evidence, and the
    /// next send refuses here rather than at Google.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] for a read-only grant or a mismatched/inactive
    /// row, plus the custody and SECRET-02 door arms.
    pub fn with_send_token_at_door(
        &self,
        vault: &Vault,
        identity_id: EntityId,
        apply: &mut dyn FnMut(&[u8]) -> Result<()>,
    ) -> Result<DoorInjectionReceipt> {
        self.require_send_grant()?;
        self.require_active_row_matches_adapter(vault, &identity_id)?;
        self.verify_custody_grant(vault)?;
        vault.inject_secret_at_door(
            &self.config.custody_record_ref,
            super::GMAIL_CONNECTOR_EFFECTOR,
            apply,
        )
    }

    /// Owner approval for exactly one member send: "a press per send".
    ///
    /// Mints no standing authority. The envelope must name this adapter's live
    /// send-capable row, bound to the request's actor, and a frozen
    /// [`GmailSendPlan`] content ref; the digest is the canonical mail
    /// operation's, so a changed recipient, plan or send ref needs a new press.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] for an envelope this adapter does not speak
    /// for, plus the approve-once door's owner checks.
    pub fn approve_send_once(
        &self,
        vault: &Vault,
        owner: &AuthenticatedOwner,
        request: &OutboundDispatchRequest,
    ) -> Result<ConsentReceipt> {
        let (identity_ref, actor) = self.require_send_envelope(vault, request)?;
        approve_canonical_mail_send_once(vault, owner, request, identity_ref, actor)
    }

    /// One owner press for a REVIEWED BATCH: exact approvals for exactly the
    /// enumerated sends, all minted in one transaction (ARCH-0046 "one press
    /// for a reviewed batch").
    ///
    /// `reviewed_send_refs` is what the owner saw: the card's
    /// `BundleExactSends` refs. The requests must be exactly those sends, one
    /// each, every one this adapter's member send with a frozen plan. Each
    /// gets its own canonical digest, so the press covers these sends and no
    /// other: it mints no standing authority and is never converted into the
    /// brief-wide grant the card's other scope choice would mint. Either every
    /// approval lands or none does; an already-pressed send refuses the batch.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] when the requests are not exactly the reviewed
    /// refs or any envelope is not this adapter's, plus the approve-once
    /// door's owner and replay checks.
    pub fn approve_send_batch(
        &self,
        vault: &Vault,
        owner: &AuthenticatedOwner,
        reviewed_send_refs: &[String],
        requests: &[OutboundDispatchRequest],
    ) -> Result<Vec<ConsentReceipt>> {
        let mut reviewed = reviewed_send_refs
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        let mut requested = requests
            .iter()
            .map(|request| request.intent_ref.as_str())
            .collect::<Vec<_>>();
        reviewed.sort_unstable();
        requested.sort_unstable();
        if requests.is_empty()
            || reviewed != requested
            || requested.windows(2).any(|pair| pair[0] == pair[1])
        {
            return Err(Error::InvalidConfig(
                "gmail batch approval must cover exactly the reviewed sends, once each".to_owned(),
            ));
        }
        let mut digests = Vec::with_capacity(requests.len());
        for request in requests {
            let (identity_ref, actor) = self.require_send_envelope(vault, request)?;
            digests.push(canonical_mail_send_digest(request, identity_ref, actor)?);
        }
        vault.with_write_txn_grouped(|wtxn| {
            digests
                .into_iter()
                .map(|digest| vault.approve_once_in_txn(wtxn, owner, digest))
                .collect()
        })
    }

    /// Dispatches one member send through the recorded dispatch door, then
    /// records its thread passport and comm touch on delivery.
    ///
    /// The envelope check is this adapter's; recipient binding, STOP, the Gate,
    /// the intent ledger, the outbound receipt and the transport's frozen-call
    /// checks are the common ones. A Held result is the owner's approval card:
    /// press [`Self::approve_send_once`] for the same request and dispatch it
    /// again. A retry after a crash or a projection error replays the ledger's
    /// stored outcome and re-projects the thread record without resending.
    ///
    /// # Errors
    ///
    /// The envelope refusal, the dispatch error, or a thread/comm projection
    /// failure after delivery (retry the same request to re-project).
    pub fn dispatch_send_recorded<W: GmailSendWire>(
        &self,
        vault: &Vault,
        request: OutboundDispatchRequest,
        sink: &mut GmailSendSink<'_, W>,
    ) -> std::result::Result<OutboundDispatchResult, OutboundDispatchError> {
        let (identity_ref, actor) = self.require_send_envelope(vault, &request)?;
        if sink.identity_id != identity_ref
            || sink.adapter.config.mailbox_address != self.config.mailbox_address
        {
            return Err(Error::InvalidConfig(
                "gmail send sink is bound to another identity or mailbox".to_owned(),
            )
            .into());
        }
        let result = vault.dispatch_outbound_intent_recorded(request, sink)?;
        if result.outcome == OutboundDispatchOutcome::DeliveredToChannel {
            record_sent_thread(vault, identity_ref, actor, &result)?;
        }
        Ok(result)
    }

    fn require_send_grant(&self) -> Result<()> {
        if self.config.grants_send() {
            Ok(())
        } else {
            Err(Error::InvalidConfig(
                "gmail delegated send requires gmail.send on the grant".to_owned(),
            ))
        }
    }

    /// The member-send envelope: `email/send`, a logical ref, a frozen plan
    /// ref, and this adapter's ACTIVE send-capable row bound to the request's
    /// own actor.
    fn require_send_envelope(
        &self,
        vault: &Vault,
        request: &OutboundDispatchRequest,
    ) -> Result<(EntityId, EntityId)> {
        let invalid = || Error::InvalidConfig("invalid gmail member send envelope".to_owned());
        self.require_send_grant()?;
        let identity_ref = request.channel_identity_ref.ok_or_else(invalid)?;
        self.require_active_row_matches_adapter(vault, &identity_ref)?;
        let identity = vault
            .get_channel_identity(&identity_ref)?
            .ok_or_else(invalid)?;
        let actor = request.actor.actor_entity_ref.ok_or_else(invalid)?;
        if !request
            .intent
            .channel
            .trim()
            .eq_ignore_ascii_case(EMAIL_CHANNEL)
            || !request.intent.verb.trim().eq_ignore_ascii_case("send")
            || request.intent_ref.trim().is_empty()
            || !request
                .intent
                .content_ref
                .as_deref()
                .is_some_and(|content_ref| content_ref.starts_with(GMAIL_SEND_PLAN_REF_PREFIX))
            || !identity.may_send()
            || identity.binding().actor_ref() != Some(actor)
            || request.actor.actor_ref.as_deref() != Some(actor.to_hex().as_str())
        {
            return Err(invalid());
        }
        Ok((identity_ref, actor))
    }
}

/// Projects one delivered member send into the thread record: its
/// `(identity × Message-ID)` passport with References/In-Reply-To, and the
/// recipient's comm last-touch. Both read the durable receipt, so a replayed
/// Done result re-projects identically; both writes are idempotent.
fn record_sent_thread(
    vault: &Vault,
    identity_ref: EntityId,
    actor: EntityId,
    result: &OutboundDispatchResult,
) -> Result<()> {
    let fields = &result.receipt.fields;
    let Some(message_id) = fields.get(RECEIPT_RFC_MESSAGE_ID) else {
        return Ok(());
    };
    let mut input = ThreadPassportInput::new(
        identity_ref,
        actor,
        canonical_message_id(message_id)?,
        result.receipt.occurred_at,
    );
    if let Some(identity) = vault.get_channel_identity(&identity_ref)?
        && let Some(facet) = identity.binding().facet_ref()
    {
        input = input.with_facet(facet);
    }
    if let Some(parent) = fields.get(RECEIPT_RFC_IN_REPLY_TO) {
        input = input.with_in_reply_to(canonical_message_id(parent)?);
    }
    if let Some(references) = fields.get(RECEIPT_RFC_REFERENCES) {
        let references = references.split(' ').collect::<Vec<_>>();
        input = input.with_references(canonical_message_id_list(&references)?);
    }
    vault.record_thread_passport(input)?;
    if let Some(party) = fields.get("counterparty_ref") {
        crate::comm::record_comm_send_receipt(
            vault,
            party,
            EMAIL_CHANNEL,
            result.receipt.occurred_at,
        )
        .map_err(|err| Error::InvalidConfig(format!("gmail send comm projection failed: {err}")))?;
    }
    Ok(())
}
