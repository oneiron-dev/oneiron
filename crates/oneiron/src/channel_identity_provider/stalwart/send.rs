//! Native message fields and the common outbound sink's JMAP submission.
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{StalwartClient, StalwartMailbox, array, invalid, method_result, string};
use crate::channel_identity_provider::EmailThreadHeaders;
use crate::channel_identity_provider::native_mail::canonical_recipient;
use crate::outbound::{
    EngineSendId, OutboundExecutionOutcome, OutboundExecutionRequest, OutboundExecutionSink,
    SENT_LOOKUP_TIMEOUT, SentLookup, SentLookupTarget,
};
use crate::outbound_intent_ledger::DeliveryReadBack;
use crate::{EntityId, Result};

pub const NATIVE_MAIL_MAX_MESSAGE_BYTES: usize = 8 * 1024 * 1024;

/// Agent-visible fields only. Sender, headers and route come from the host and
/// frozen dispatch request. Unsupported fields fail deserialization, not send.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeMailMessage {
    pub to: String,
    pub subject: String,
    pub text: Option<String>,
    pub html: Option<String>,
}

impl NativeMailMessage {
    pub fn new(
        to: &str,
        subject: impl Into<String>,
        text: Option<String>,
        html: Option<String>,
    ) -> Result<Self> {
        let message = Self {
            to: canonical_recipient(to)?,
            subject: subject.into(),
            text,
            html,
        };
        message.validate()?;
        Ok(message)
    }

    pub fn validate(&self) -> Result<()> {
        if self.to != canonical_recipient(&self.to)?
            || self.subject.len() > 998
            || self.subject.contains(['\r', '\n'])
            || self.text.as_deref().is_none_or(str::is_empty)
                && self.html.as_deref().is_none_or(str::is_empty)
        {
            return Err(invalid("invalid native mail message fields"));
        }
        let bytes = self
            .subject
            .len()
            .saturating_add(self.text.as_ref().map_or(0, String::len))
            .saturating_add(self.html.as_ref().map_or(0, String::len));
        if bytes > NATIVE_MAIL_MAX_MESSAGE_BYTES {
            return Err(invalid("native mail message exceeds route capabilities"));
        }
        Ok(())
    }

    /// Freeze these exact bytes into the ordinary intent before asking for
    /// approval. Editing the message changes the one-send approval digest.
    pub fn content_ref(&self) -> Result<String> {
        self.validate()?;
        let bytes =
            serde_json::to_vec(self).map_err(|_| invalid("native mail message did not encode"))?;
        Ok(format!(
            "native-mail:content:{}",
            blake3::hash(&bytes).to_hex()
        ))
    }
}

/// One immutable message bound to a client. Only the common dispatcher calls
/// execute, after identity, consent, suppression, ledger and rate admission.
pub struct StalwartSendSink<'a> {
    client: &'a StalwartClient,
    message: &'a NativeMailMessage,
    /// The sending identity and its own address, derived or named, read from
    /// its facts by the caller. A request naming another identity fails.
    sender: EntityId,
    sender_address: &'a str,
}

impl<'a> StalwartSendSink<'a> {
    pub fn new(
        client: &'a StalwartClient,
        message: &'a NativeMailMessage,
        sender: EntityId,
        sender_address: &'a str,
    ) -> Result<Self> {
        message.validate()?;
        Ok(Self {
            client,
            message,
            sender,
            sender_address,
        })
    }
}

impl StalwartSendSink<'_> {
    /// The mailbox and Message-ID the frozen send `request` drafts under,
    /// after checking it is this sink's own message from its own identity.
    /// Its send and its read-back (FIX 8814 follow-up) both prepare here, so
    /// the read-back finds the draft the send made.
    fn prepared(
        &self,
        request: &OutboundExecutionRequest<'_>,
    ) -> Result<(StalwartMailbox, String)> {
        let content_ref = self.message.content_ref()?;
        if request.intent.channel != "email"
            || request.intent.verb != "send"
            || request.intent.content_ref.as_deref() != Some(content_ref.as_str())
            || request.intent.target != self.message.to
            || request.calendar_invite.is_some()
        {
            return Err(invalid(
                "native mail message differs from the frozen send or uses unsupported fields",
            ));
        }
        let identity = request
            .channel_identity_ref
            .ok_or_else(|| invalid("native mail send lacks an identity"))?;
        if identity != self.sender {
            return Err(invalid("native mail send names another identity"));
        }
        let mailbox = self.client.mailbox(identity, self.sender_address)?;
        // Email's common contract correctly does not claim provider-native
        // idempotency. This Message-ID is the draft/reconciliation key and
        // the id a lookup asks for; a connector-send TASK's send derives
        // it from its engine send id, the same on every machine (FIX
        // 4747).
        let key = request
            .engine_send_id
            .map(EngineSendId::as_str)
            .or(request.intent.idempotency_key.as_deref())
            .unwrap_or(request.intent_ref);
        if key.trim().is_empty() {
            return Err(invalid("native mail send lacks a logical send reference"));
        }
        Ok((mailbox, self.client.native_message_id(key)))
    }
}

impl OutboundExecutionSink for StalwartSendSink<'_> {
    fn execute(&mut self, request: &OutboundExecutionRequest<'_>) -> OutboundExecutionOutcome {
        let (mailbox, message_id) = match self.prepared(request) {
            Ok(prepared) => prepared,
            Err(_) => return OutboundExecutionOutcome::failed("native_mail_fields_or_binding"),
        };
        self.client.submit(
            &mailbox,
            self.message,
            &message_id,
            &request.hygiene_headers,
            None,
        )
    }

    /// FIX 4747: the submission of this sender's draft that carries the
    /// engine send id's Message-ID.
    fn lookup_sent(
        &mut self,
        engine_send_id: &EngineSendId,
        target: &SentLookupTarget<'_>,
    ) -> SentLookup {
        if target.intent.channel != "email"
            || target.intent.verb != "send"
            || target
                .channel_identity_ref
                .is_some_and(|identity| identity != self.sender)
        {
            return SentLookup::CannotTell;
        }
        match self.client.mailbox(self.sender, self.sender_address) {
            Ok(mailbox) => self.client.look_up_submission(
                &mailbox,
                &self.client.native_message_id(engine_send_id.as_str()),
            ),
            Err(_) => SentLookup::CannotTell,
        }
    }

    /// Reads back from the server the draft `request` would submit (FIX
    /// 8814 follow-up), by its Message-ID.
    fn read_back_delivery(&self, request: &OutboundExecutionRequest<'_>) -> DeliveryReadBack {
        match self.prepared(request) {
            Ok((mailbox, message_id)) => {
                self.client
                    .read_back(&mailbox, &message_id, &self.message.to)
            }
            Err(_) => DeliveryReadBack::Unknown,
        }
    }
}

impl StalwartClient {
    /// The Message-ID of the native mail send keyed `send_key`, the send's
    /// logical reference or its engine send id: its draft is found by it and
    /// its submission looked up by it.
    fn native_message_id(&self, send_key: &str) -> String {
        format!(
            "{}@{}",
            blake3::hash(send_key.as_bytes()).to_hex(),
            self.config.domain
        )
    }

    /// Whether the served send keyed `send_key` from `identity`'s mailbox at
    /// `address` went (FIX 4747): the submission of the draft its
    /// Message-ID names. Reads ids only, never a message.
    pub fn look_up_served_send(
        &self,
        identity: crate::EntityId,
        address: &str,
        send_key: &str,
    ) -> SentLookup {
        if send_key.trim().is_empty() {
            return SentLookup::CannotTell;
        }
        match self.mailbox(identity, address) {
            Ok(mailbox) => self.look_up_submission(&mailbox, &self.native_message_id(send_key)),
            Err(_) => SentLookup::CannotTell,
        }
    }

    /// The submission of the one draft carrying `message_id` (FIX 4747):
    /// `Email/query` by the Message-ID header, then `EmailSubmission/query`
    /// by that email, each bounded by [`SENT_LOOKUP_TIMEOUT`]. Engine call
    /// (CALLS, FIX 4747): no such email, or an email no submission sent, is
    /// not sent; a query that failed, or two emails under one id, cannot
    /// tell.
    fn look_up_submission(&self, mailbox: &StalwartMailbox, message_id: &str) -> SentLookup {
        let Ok(query) = self.call_within(
            "Email/query",
            json!({
                "accountId": &mailbox.account_id,
                "filter": {"header": ["Message-ID", message_id]}, "limit": 2
            }),
            SENT_LOOKUP_TIMEOUT,
        ) else {
            return SentLookup::CannotTell;
        };
        let Ok(ids) = array(&query, "ids") else {
            return SentLookup::CannotTell;
        };
        if ids.len() > 1 {
            return SentLookup::CannotTell;
        }
        let Some(email_id) = ids.first() else {
            return SentLookup::NotSent;
        };
        let Some(email_id) = email_id.as_str() else {
            return SentLookup::CannotTell;
        };
        let Ok(previous) = self.call_within(
            "EmailSubmission/query",
            json!({
                "accountId": &mailbox.account_id, "filter": {"emailIds": [email_id]}, "limit": 1
            }),
            SENT_LOOKUP_TIMEOUT,
        ) else {
            return SentLookup::CannotTell;
        };
        let Ok(ids) = array(&previous, "ids") else {
            return SentLookup::CannotTell;
        };
        match ids.first().map(Value::as_str) {
            None => SentLookup::NotSent,
            Some(Some(id)) => SentLookup::Sent {
                provider_ref: format!("stalwart:submission:{id}"),
            },
            Some(None) => SentLookup::CannotTell,
        }
    }

    /// Submits `message` from `identity`'s mailbox for a served send
    /// (OF-187), after the common dispatcher admitted it: the same draft and
    /// submission path as [`StalwartSendSink`], its Message-ID derived from
    /// `send_key`, the send's logical reference, so a retry finds its draft
    /// and its submission rather than sending twice. A send that answers a
    /// message, `answered` naming that message's headers, threads on it.
    pub fn submit_served_text(
        &self,
        identity: crate::EntityId,
        address: &str,
        message: &NativeMailMessage,
        send_key: &str,
        headers: &BTreeMap<String, String>,
        answered: Option<&EmailThreadHeaders>,
    ) -> OutboundExecutionOutcome {
        if send_key.trim().is_empty() || message.validate().is_err() {
            return OutboundExecutionOutcome::failed("native_mail_fields_or_binding");
        }
        let mailbox = match self.mailbox(identity, address) {
            Ok(mailbox) => mailbox,
            Err(_) => return OutboundExecutionOutcome::failed("native_mail_fields_or_binding"),
        };
        let message_id = self.native_message_id(send_key);
        self.submit(&mailbox, message, &message_id, headers, answered)
    }

    /// What the server's own record says became of the served send keyed
    /// `send_key` from `identity`'s mailbox to `to` (FIX 8814 follow-up): the
    /// read-back of [`Self::submit_served_text`]'s draft.
    pub fn read_back_served(
        &self,
        identity: crate::EntityId,
        address: &str,
        send_key: &str,
        to: &str,
    ) -> DeliveryReadBack {
        if send_key.trim().is_empty() {
            return DeliveryReadBack::Unknown;
        }
        let Ok(to) = canonical_recipient(to) else {
            return DeliveryReadBack::Unknown;
        };
        match self.mailbox(identity, address) {
            Ok(mailbox) => self.read_back(&mailbox, &self.native_message_id(send_key), &to),
            Err(_) => DeliveryReadBack::Unknown,
        }
    }

    /// What the server's own record says became of the send to `to` whose
    /// draft carries `message_id` in `mailbox` (FIX 8814 follow-up). Only a
    /// submission of the draft that was not cancelled and whose envelope is
    /// the frozen send's own (from the mailbox's address to `to` alone)
    /// proves the send: `Delivered`. Nothing here proves a send never went,
    /// since an unanswered submission may still be landing and Sent
    /// membership or a cleared `$draft` can be set by any client: every other
    /// answer, an ambiguous Message-ID and a failed read are `Unknown`
    /// (REVIEW-5934).
    fn read_back(&self, mailbox: &StalwartMailbox, message_id: &str, to: &str) -> DeliveryReadBack {
        self.read_back_checked(mailbox, message_id, to)
            .unwrap_or(DeliveryReadBack::Unknown)
    }

    fn read_back_checked(
        &self,
        mailbox: &StalwartMailbox,
        message_id: &str,
        to: &str,
    ) -> Result<DeliveryReadBack> {
        let query = self.call(
            "Email/query",
            json!({
                "accountId": &mailbox.account_id,
                "filter": {"header": ["Message-ID", message_id]}, "limit": 2
            }),
        )?;
        let email_id = match array(&query, "ids")?.as_slice() {
            [id] => id
                .as_str()
                .ok_or_else(|| invalid("invalid JMAP email id"))?
                .to_owned(),
            _ => return Ok(DeliveryReadBack::Unknown),
        };
        let submissions = self.call(
            "EmailSubmission/query",
            json!({
                "accountId": &mailbox.account_id, "filter": {"emailIds": [&email_id]}
            }),
        )?;
        let ids = array(&submissions, "ids")?;
        if ids.is_empty() {
            return Ok(DeliveryReadBack::Unknown);
        }
        let held = self.call(
            "EmailSubmission/get",
            json!({
                "accountId": &mailbox.account_id, "ids": ids,
                "properties": ["undoStatus", "envelope"]
            }),
        )?;
        // The envelope this sink submits: the mailbox's own address to the
        // frozen recipient alone. Another client's submission of the same
        // draft to anyone else proves nothing about this send.
        let addressed = |address: Option<&str>, expected: &str| {
            address
                .and_then(|address| canonical_recipient(address).ok())
                .is_some_and(|address| address == expected)
        };
        let Ok(from) = canonical_recipient(&mailbox.address) else {
            return Ok(DeliveryReadBack::Unknown);
        };
        let sent = array(&held, "list")?.iter().any(|submission| {
            let envelope = submission.get("envelope");
            let rcpt = envelope
                .and_then(|envelope| envelope.get("rcptTo"))
                .and_then(Value::as_array);
            submission.get("undoStatus").and_then(Value::as_str) != Some("canceled")
                && addressed(
                    envelope
                        .and_then(|envelope| envelope.pointer("/mailFrom/email"))
                        .and_then(Value::as_str),
                    &from,
                )
                && rcpt.is_some_and(|rcpt| {
                    matches!(rcpt.as_slice(), [only] if addressed(
                        only.get("email").and_then(Value::as_str),
                        to,
                    ))
                })
        });
        Ok(if sent {
            DeliveryReadBack::Delivered
        } else {
            DeliveryReadBack::Unknown
        })
    }

    fn submit(
        &self,
        mailbox: &StalwartMailbox,
        message: &NativeMailMessage,
        message_id: &str,
        headers: &BTreeMap<String, String>,
        answered: Option<&EmailThreadHeaders>,
    ) -> OutboundExecutionOutcome {
        // Draft creation is not delivery. Reuse its Message-ID after a crash;
        // an uncertain submission below is NEVER escalated to another route.
        let prepare = || -> Result<(String, String, String)> {
            let identity_reply =
                self.call("Identity/get", json!({"accountId": &mailbox.account_id}))?;
            let identities: Vec<_> = array(&identity_reply, "list")?
                .iter()
                .filter(|row| {
                    row.get("email").and_then(Value::as_str) == Some(mailbox.address.as_str())
                })
                .collect();
            if identities.len() != 1 {
                return Err(invalid("native sender has no unique JMAP identity"));
            }
            let identity_id = string(identities[0], "id")?.to_owned();
            let boxes = self.mailboxes(mailbox)?;
            let role = |role: &str| -> Result<String> {
                boxes
                    .iter()
                    .find(|row| row.get("role").and_then(Value::as_str) == Some(role))
                    .ok_or_else(|| invalid("native mailbox lacks a required role"))
                    .and_then(|row| string(row, "id").map(str::to_owned))
            };
            let drafts = role("drafts")?;
            let sent = role("sent")?;
            let query = self.call(
                "Email/query",
                json!({
                    "accountId": &mailbox.account_id,
                    "filter": {"header": ["Message-ID", message_id]}, "limit": 2
                }),
            )?;
            let ids = array(&query, "ids")?;
            if ids.len() > 1 {
                return Err(invalid("native Message-ID is ambiguous"));
            }
            let email_id = if let Some(id) = ids.first() {
                id.as_str()
                    .ok_or_else(|| invalid("invalid JMAP email id"))?
                    .to_owned()
            } else {
                let mut email = json!({
                    "mailboxIds": { (drafts): true }, "keywords": {"$draft": true},
                    "messageId": [message_id], "from": [{"email": &mailbox.address}],
                    "to": [{"email": &message.to}], "subject": &message.subject,
                    "bodyValues": {}, "textBody": [], "htmlBody": []
                });
                for (part_id, content_type, body, field) in [
                    ("text", "text/plain", message.text.as_ref(), "textBody"),
                    ("html", "text/html", message.html.as_ref(), "htmlBody"),
                ] {
                    if let Some(body) = body {
                        email["bodyValues"][part_id] = json!({"value": body});
                        email[field] = json!([{"partId": part_id, "type": content_type}]);
                    }
                }
                for (name, value) in headers {
                    if !matches!(
                        name.to_ascii_lowercase().as_str(),
                        "list-unsubscribe" | "list-unsubscribe-post"
                    ) || value.contains(['\r', '\n'])
                    {
                        return Err(invalid("unsupported native mail header"));
                    }
                    email[format!("header:{name}:asText")] = Value::String(value.clone());
                }
                // A reply threads on what it answers; ids that cannot
                // thread leave it a plain message, never an unsent one.
                if let Some((parent, references)) = answered.and_then(reply_thread) {
                    email["inReplyTo"] = json!([parent]);
                    email["references"] = json!(references);
                }
                let reply = self.call(
                    "Email/set",
                    json!({
                        "accountId": &mailbox.account_id, "create": {"draft": email}
                    }),
                )?;
                reply
                    .pointer("/created/draft/id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| invalid("Stalwart refused the native mail draft"))?
                    .to_owned()
            };
            Ok((email_id, identity_id, sent))
        };
        let (email_id, identity_id, sent) = match prepare() {
            Ok(prepared) => prepared,
            Err(_) => return OutboundExecutionOutcome::failed("native_mail_draft_failed"),
        };
        let previous = match self.call(
            "EmailSubmission/query",
            json!({
                "accountId": &mailbox.account_id, "filter": {"emailIds": [&email_id]}, "limit": 1
            }),
        ) {
            Ok(reply) => reply,
            Err(_) => {
                return OutboundExecutionOutcome::failed("native_mail_submission_lookup_failed");
            }
        };
        match array(&previous, "ids") {
            Ok(ids) if !ids.is_empty() => {
                if let Some(id) = ids[0].as_str() {
                    return submitted(id);
                }
                return OutboundExecutionOutcome::failed("native_mail_submission_lookup_invalid");
            }
            Ok(_) => {}
            Err(_) => {
                return OutboundExecutionOutcome::failed("native_mail_submission_lookup_invalid");
            }
        }
        let reply = match self.raw_call("EmailSubmission/set", json!({
            "accountId": &mailbox.account_id,
            "create": {"send": {"identityId": identity_id, "emailId": email_id,
                "envelope": {"mailFrom": {"email": &mailbox.address}, "rcptTo": [{"email": &message.to}]}}},
            "onSuccessUpdateEmail": {"#send": {"mailboxIds": {(sent): true}, "keywords/$draft": null}}
        })) {
            Ok(reply) => reply,
            Err(_) => return OutboundExecutionOutcome::failed("native_mail_submission_unknown").with_possible_delivery(),
        };
        match method_result(&reply, "EmailSubmission/set") {
            Ok(result) => {
                if let Some(id) = result.pointer("/created/send/id").and_then(Value::as_str) {
                    submitted(id)
                } else if result.pointer("/notCreated/send").is_some() {
                    OutboundExecutionOutcome::failed("native_mail_submission_rejected")
                } else {
                    OutboundExecutionOutcome::failed("native_mail_submission_unknown")
                        .with_possible_delivery()
                }
            }
            Err(_) => OutboundExecutionOutcome::failed("native_mail_submission_unknown")
                .with_possible_delivery(),
        }
    }
}

/// The `In-Reply-To` and `References` ids of a reply to the message whose
/// headers `answered` names (RFC 5322 3.6.4): the parent is its Message-ID,
/// and the references are its own References, else its In-Reply-To, then the
/// parent. Ids are bare, as JMAP sets them; `None` when one is not a
/// msg-id.
fn reply_thread(answered: &EmailThreadHeaders) -> Option<(String, Vec<String>)> {
    let bare = |id: &str| -> Option<String> {
        let id = id.trim();
        let id = id
            .strip_prefix('<')
            .and_then(|id| id.strip_suffix('>'))
            .unwrap_or(id);
        (!id.is_empty() && !id.contains(|c: char| c.is_whitespace() || c == '<' || c == '>'))
            .then(|| id.to_owned())
    };
    let parent = bare(answered.message_id.as_str())?;
    let ancestors = if answered.references.is_empty() {
        answered.in_reply_to.iter().collect::<Vec<_>>()
    } else {
        answered.references.iter().collect()
    };
    let mut references = Vec::with_capacity(ancestors.len() + 1);
    for id in ancestors {
        let id = bare(id.as_str())?;
        if !references.contains(&id) {
            references.push(id);
        }
    }
    references.retain(|id| *id != parent);
    references.push(parent.clone());
    Some((parent, references))
}

fn submitted(id: &str) -> OutboundExecutionOutcome {
    OutboundExecutionOutcome::delivered_to_channel(format!("stalwart:submission:{id}"))
        .with_receipt_field("mail_delivery_state", "submitted")
}
