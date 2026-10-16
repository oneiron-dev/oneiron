//! Native message fields and the common outbound sink's JMAP submission.
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{StalwartClient, StalwartMailbox, array, invalid, method_result, string};
use crate::Result;
use crate::channel_identity_provider::native_mail::canonical_recipient;
use crate::outbound::{OutboundExecutionOutcome, OutboundExecutionRequest, OutboundExecutionSink};

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
}

impl<'a> StalwartSendSink<'a> {
    pub fn new(client: &'a StalwartClient, message: &'a NativeMailMessage) -> Result<Self> {
        message.validate()?;
        Ok(Self { client, message })
    }
}

impl OutboundExecutionSink for StalwartSendSink<'_> {
    fn execute(&mut self, request: &OutboundExecutionRequest<'_>) -> OutboundExecutionOutcome {
        let prepare = || -> Result<(StalwartMailbox, String)> {
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
            let mailbox = self.client.mailbox(identity)?;
            // Email's common contract correctly does not claim provider-native
            // idempotency. This Message-ID is only a draft/reconciliation key;
            // ambiguous sends still remain ambiguous in the ordinary ledger.
            let key = request
                .intent
                .idempotency_key
                .as_deref()
                .unwrap_or(request.intent_ref);
            if key.trim().is_empty() {
                return Err(invalid("native mail send lacks a logical send reference"));
            }
            let message_id = format!(
                "{}@{}",
                blake3::hash(key.as_bytes()).to_hex(),
                self.client.config.domain
            );
            Ok((mailbox, message_id))
        };
        let (mailbox, message_id) = match prepare() {
            Ok(prepared) => prepared,
            Err(_) => return OutboundExecutionOutcome::failed("native_mail_fields_or_binding"),
        };
        self.client.submit(
            &mailbox,
            self.message,
            &message_id,
            &request.hygiene_headers,
        )
    }
}

impl StalwartClient {
    fn submit(
        &self,
        mailbox: &StalwartMailbox,
        message: &NativeMailMessage,
        message_id: &str,
        headers: &BTreeMap<String, String>,
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

fn submitted(id: &str) -> OutboundExecutionOutcome {
    OutboundExecutionOutcome::delivered_to_channel(format!("stalwart:submission:{id}"))
        .with_receipt_field("mail_delivery_state", "submitted")
}
