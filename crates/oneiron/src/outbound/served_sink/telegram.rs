//! Telegram (OF-187): the bot sends with the built-in Telegram pack's
//! checked bot token. A send that answers an inbound Telegram message posts
//! in that message's chat as a reply to it; any other send posts to its
//! target chat.
//!
//! A send the owner set to post as him (OF-414: a space posting preset in the
//! owner's mode) answers a Telegram Business message through the business
//! connection it came on, so Telegram shows the reply as the owner's own.
//! Only an answer to a business message has that connection; any other
//! owner-mode send fails as not started.

use std::io::Read;

use super::{
    MAX_REPLY_BYTES, POSTED_AS_FIELD, RETRY_AFTER_FIELD, ServedChannelSink, posts_as_owner,
};
use crate::error::Error;
use crate::outbound::{OutboundExecutionOutcome, OutboundExecutionRequest};
use crate::outbound_intent_ledger::ProviderWaitKind;

/// The outbound channel this transport serves.
pub(super) const TELEGRAM_CHANNEL: &str = "telegram";
/// The built-in Telegram pack connection whose checked bot token sends.
const TELEGRAM_PACK: &str = "oneiron.telegram";
const TELEGRAM_CONNECTION: &str = "telegram-bot";
const TELEGRAM_SEND_MESSAGE: &str = "sendMessage";
/// Telegram refuses a text message longer than this many characters.
const TELEGRAM_MAX_TEXT_CHARS: usize = 4096;
/// The prefixes a send names a Telegram chat or user by.
const TELEGRAM_TARGET_PREFIXES: [&str; 2] = ["telegram:chat:", "telegram:user:"];

impl ServedChannelSink<'_> {
    pub(super) fn telegram_send(
        &self,
        request: &OutboundExecutionRequest<'_>,
    ) -> OutboundExecutionOutcome {
        let Some(text) = self.text(request) else {
            return OutboundExecutionOutcome::failed("content_unresolvable");
        };
        let text: String = text.chars().take(TELEGRAM_MAX_TEXT_CHARS).collect();
        // Read before the door opens: the door holds the vault's writer.
        let answered = self
            .answered_provider_event(request, TELEGRAM_CHANNEL)
            .and_then(|body| answered_message(&body));
        let mut body = serde_json::json!({ "text": text });
        match &answered {
            Some(message) => {
                body["chat_id"] = message.chat.clone();
                body["reply_parameters"] = serde_json::json!({
                    "message_id": message.message_id,
                    "allow_sending_without_reply": true
                });
            }
            None => {
                let Some(chat) = telegram_chat(&request.intent.target) else {
                    return OutboundExecutionOutcome::failed("telegram_target_unrecognized");
                };
                body["chat_id"] = serde_json::Value::String(chat);
            }
        }
        let as_owner = posts_as_owner(request);
        if as_owner {
            let Some(connection) = answered
                .as_ref()
                .and_then(|message| message.business_connection.clone())
            else {
                return OutboundExecutionOutcome::failed("telegram_business_connection_absent");
            };
            body["business_connection_id"] = serde_json::Value::String(connection);
        }
        let secret = match self
            .vault
            .verified_pack_connection_secret(TELEGRAM_PACK, TELEGRAM_CONNECTION)
        {
            Ok(secret) => secret,
            Err(_) => return OutboundExecutionOutcome::failed("telegram_connection_unchecked"),
        };
        let mut outcome = None;
        let _door = self.vault.inject_secret_at_door(
            &secret.name,
            &secret.effector,
            &mut |value: &[u8]| {
                let token = std::str::from_utf8(value)
                    .map_err(|_| Error::InvalidClaimBody("the stored credential is not text"))?;
                outcome = Some(self.telegram_call(token.trim(), &body));
                Ok(())
            },
        );
        // Once the call ran, what Telegram said is the delivery fact,
        // whatever the door reports after it.
        let outcome = outcome
            .unwrap_or_else(|| OutboundExecutionOutcome::failed("telegram_credential_unavailable"));
        if as_owner {
            outcome.with_receipt_field(POSTED_AS_FIELD, "owner")
        } else {
            outcome
        }
    }

    /// One `sendMessage` call. The token is in the URL's path, so no error
    /// that may carry the URL is kept. A refused connection never reached
    /// Telegram; anything later may have, and Telegram dedupes nothing.
    fn telegram_call(&self, token: &str, body: &serde_json::Value) -> OutboundExecutionOutcome {
        let url = self
            .transports
            .endpoints()
            .telegram(token, TELEGRAM_SEND_MESSAGE);
        let response = match self.client.post(url).json(body).send() {
            Ok(response) => response,
            Err(error) if error.is_connect() => {
                return OutboundExecutionOutcome::failed("telegram_unreachable");
            }
            Err(_) => {
                return OutboundExecutionOutcome::failed("telegram_no_reply")
                    .with_possible_delivery();
            }
        };
        let status = response.status().as_u16();
        let mut reply = Vec::new();
        let read = response.take(MAX_REPLY_BYTES).read_to_end(&mut reply);
        let reply: serde_json::Value = read
            .ok()
            .and_then(|_| serde_json::from_slice(&reply).ok())
            .unwrap_or_default();
        if reply.get("ok").and_then(serde_json::Value::as_bool) == Some(true) {
            let id = |pointer: &str| {
                reply
                    .pointer(pointer)
                    .map_or_else(|| "unknown".to_owned(), scalar_text)
            };
            return OutboundExecutionOutcome::delivered_to_channel(format!(
                "telegram:{}:{}",
                id("/result/chat/id"),
                id("/result/message_id")
            ));
        }
        match status {
            // FIX 8818: a flood wait keeps the send queued for Telegram's
            // stated seconds.
            429 => {
                let failed = OutboundExecutionOutcome::failed("telegram_rate_limited")
                    .with_provider_wait(ProviderWaitKind::RateLimit);
                match reply
                    .pointer("/parameters/retry_after")
                    .and_then(serde_json::Value::as_u64)
                {
                    Some(secs) => failed.with_receipt_field(RETRY_AFTER_FIELD, secs.to_string()),
                    None => failed,
                }
            }
            // A success whose reply did not read, or a server fault, may
            // have landed the message.
            200..=299 | 500..=599 => {
                OutboundExecutionOutcome::failed(format!("telegram_http_{status}"))
                    .with_possible_delivery()
            }
            _ => OutboundExecutionOutcome::failed(format!("telegram_http_{status}")),
        }
    }
}

/// The inbound Telegram message a send answers, read from its archived
/// update: an ordinary message, or a business message with the business
/// connection it came on.
struct AnsweredMessage {
    chat: serde_json::Value,
    message_id: i64,
    business_connection: Option<String>,
}

fn answered_message(update: &serde_json::Value) -> Option<AnsweredMessage> {
    let message = update
        .get("business_message")
        .or_else(|| update.get("message"))?;
    let chat = message.pointer("/chat/id")?;
    if !(chat.is_i64() || chat.is_string()) {
        return None;
    }
    Some(AnsweredMessage {
        chat: chat.clone(),
        message_id: message.get("message_id")?.as_i64()?,
        business_connection: message
            .get("business_connection_id")
            .and_then(serde_json::Value::as_str)
            .filter(|id| !id.is_empty())
            .map(str::to_owned),
    })
}

/// The chat a send's target names: `telegram:chat:<id>`, `telegram:user:<id>`,
/// a bare chat id, or a public `@username`. `None` for a target Telegram
/// cannot address.
fn telegram_chat(target: &str) -> Option<String> {
    let chat = TELEGRAM_TARGET_PREFIXES
        .iter()
        .find_map(|prefix| target.strip_prefix(prefix))
        .unwrap_or(target)
        .trim();
    let digits = chat.strip_prefix('-').unwrap_or(chat);
    let numeric = !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit());
    let username = chat.strip_prefix('@').is_some_and(|name| {
        !name.is_empty()
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    });
    (numeric || username).then(|| chat.to_owned())
}

/// A JSON id as text: a number's digits, a string's own text.
fn scalar_text(value: &serde_json::Value) -> String {
    value
        .as_str()
        .map_or_else(|| value.to_string(), str::to_owned)
}
