//! The sink a served connector-send worker hands the connector executor
//! (OF-187): the transports this engine can drive itself, picked by the
//! frozen intent's channel and verb.
//!
//! It runs only after the common dispatcher has admitted the send (identity,
//! consent, gate, budget, window, ledger), and it never chooses a channel: the
//! intent already names one. A channel it has no transport for fails the
//! attempt as not started, so the ledger's retry rule decides what happens
//! next. The text a send carries comes from a typed content loader, never from
//! the agent at send time.

use std::io::Read;
use std::time::Duration;

use super::dispatch_types::{
    OutboundExecutionOutcome, OutboundExecutionRequest, OutboundExecutionSink,
};
use crate::Vault;
use crate::error::{Error, Result};

const SLACK_POST_MESSAGE: &str = "https://slack.com/api/chat.postMessage";
/// The built-in Slack pack connection whose checked credential posts.
const SLACK_PACK: &str = "oneiron.slack";
const SLACK_CONNECTION: &str = "slack-app";
const MAX_REPLY_BYTES: u64 = 64 * 1024;
/// Slack refuses a message longer than this many characters.
const SLACK_MAX_TEXT_CHARS: usize = 40_000;
/// The execution field a provider's own cool-down travels on.
const RETRY_AFTER_FIELD: &str = "retry_after";

impl Vault {
    /// The plain text an outbound content ref sends, when this engine has a
    /// typed loader for it: today, a commitment reminder.
    pub fn outbound_content_text(&self, content_ref: &str) -> Result<Option<String>> {
        self.commitment_reminder_text(content_ref)
    }
}

/// The served sink: one bounded HTTPS client and the vault its credentials
/// and content are read from.
pub struct ServedChannelSink<'a> {
    vault: &'a Vault,
    client: reqwest::blocking::Client,
}

impl<'a> ServedChannelSink<'a> {
    /// A bounded HTTPS client: no proxy, no redirects, short timeouts.
    ///
    /// # Errors
    ///
    /// The client could not be built.
    pub fn new(vault: &'a Vault) -> Result<Self> {
        let client = reqwest::blocking::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(20))
            .build()
            .map_err(|_| Error::InvalidConfig("served send client unavailable".to_owned()))?;
        Ok(Self { vault, client })
    }

    fn text(&self, request: &OutboundExecutionRequest<'_>) -> Option<String> {
        let content_ref = request.intent.content_ref.as_deref()?;
        match self.vault.outbound_content_text(content_ref) {
            Ok(text) => text,
            Err(error) => {
                tracing::info!(%error, "served send content is not sendable");
                None
            }
        }
    }

    fn slack_post(&self, request: &OutboundExecutionRequest<'_>) -> OutboundExecutionOutcome {
        let Some(text) = self.text(request) else {
            return OutboundExecutionOutcome::failed("content_unresolvable");
        };
        let text: String = text.chars().take(SLACK_MAX_TEXT_CHARS).collect();
        let secret = match self
            .vault
            .verified_pack_connection_secret(SLACK_PACK, SLACK_CONNECTION)
        {
            Ok(secret) => secret,
            Err(_) => return OutboundExecutionOutcome::failed("slack_connection_unchecked"),
        };
        let body = serde_json::json!({ "channel": request.intent.target, "text": text });
        let mut outcome = None;
        let _door = self
            .vault
            .inject_secret_at_door(&secret.name, &secret.effector, &mut |value: &[u8]| {
                let token = std::str::from_utf8(value)
                    .map_err(|_| Error::InvalidClaimBody("the stored credential is not text"))?;
                outcome = Some(self.slack_send(token.trim(), &body));
                Ok(())
            });
        // Once the POST ran, what Slack said is the delivery fact, whatever
        // the door reports after it.
        outcome.unwrap_or_else(|| OutboundExecutionOutcome::failed("slack_credential_unavailable"))
    }

    fn slack_send(&self, token: &str, body: &serde_json::Value) -> OutboundExecutionOutcome {
        let response = match self
            .client
            .post(SLACK_POST_MESSAGE)
            .bearer_auth(token)
            .json(body)
            .send()
        {
            Ok(response) => response,
            // A refused connection never reached Slack; anything later may have.
            Err(error) if error.is_connect() => {
                return OutboundExecutionOutcome::failed("slack_unreachable");
            }
            Err(_) => {
                return OutboundExecutionOutcome::failed("slack_no_reply").with_possible_delivery();
            }
        };
        let status = response.status().as_u16();
        let retry_after = response
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        if status == 429 {
            let failed = OutboundExecutionOutcome::failed("slack_rate_limited");
            return match retry_after {
                Some(secs) => failed.with_receipt_field(RETRY_AFTER_FIELD, secs),
                None => failed,
            };
        }
        let mut reply = Vec::new();
        if response
            .take(MAX_REPLY_BYTES)
            .read_to_end(&mut reply)
            .is_err()
        {
            return OutboundExecutionOutcome::failed("slack_reply_unreadable")
                .with_possible_delivery();
        }
        let reply: serde_json::Value = match serde_json::from_slice(&reply) {
            Ok(reply) => reply,
            Err(_) if (200..300).contains(&status) => {
                return OutboundExecutionOutcome::failed("slack_reply_unreadable")
                    .with_possible_delivery();
            }
            Err(_) => return OutboundExecutionOutcome::failed(format!("slack_http_{status}")),
        };
        if reply.get("ok").and_then(serde_json::Value::as_bool) == Some(true) {
            let ts = reply.get("ts").and_then(serde_json::Value::as_str);
            let channel = reply.get("channel").and_then(serde_json::Value::as_str);
            return OutboundExecutionOutcome::delivered_to_channel(format!(
                "slack:{}:{}",
                channel.unwrap_or("unknown"),
                ts.unwrap_or("unknown")
            ));
        }
        let error = reply
            .get("error")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown");
        OutboundExecutionOutcome::failed(format!("slack_{error}"))
    }
}

impl OutboundExecutionSink for ServedChannelSink<'_> {
    fn execute(&mut self, request: &OutboundExecutionRequest<'_>) -> OutboundExecutionOutcome {
        match (request.intent.channel.as_str(), request.intent.verb.as_str()) {
            ("slack", "send") => self.slack_post(request),
            _ => OutboundExecutionOutcome::failed("no_served_transport_for_channel"),
        }
    }
}
