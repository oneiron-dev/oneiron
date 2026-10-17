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
//!
//! LINE (OF-519): a send that answers an inbound LINE event replies with the
//! event's own reply token while the token is fresh, and otherwise pushes to
//! the sender. A push is counted against the account's monthly allowance
//! first; past it the send asks whether everything is okay and still goes.
//!
//! Slack (OF-519): a send that answers an inbound Slack message posts into
//! that message's own conversation and thread; any other send posts to the
//! target user's direct message.

use std::io::Read;
use std::sync::Arc;
use std::time::Duration;

use super::dispatch_types::{
    OutboundExecutionOutcome, OutboundExecutionRequest, OutboundExecutionSink,
};
use super::intent::OutboundIntentSource;
use super::reply_content::CONNECTOR_REPLY_BODY_PREFIX;
use crate::channel_identity_provider::{
    DEFAULT_LINE_PUSH_MONTHLY_ALLOWANCE, LINE_CHANNEL, SLACK_CHANNEL,
};
use crate::error::{Error, Result};
use crate::limit_ask::EngineLimit;
use crate::surface_event::SurfaceConnectorPayload;
use crate::{EntityId, Vault};

const SLACK_POST_MESSAGE: &str = "https://slack.com/api/chat.postMessage";
/// The built-in Slack pack connection whose checked credential posts.
const SLACK_PACK: &str = "oneiron.slack";
const SLACK_CONNECTION: &str = "slack-app";
const MAX_REPLY_BYTES: u64 = 64 * 1024;
/// Slack refuses a message longer than this many characters.
const SLACK_MAX_TEXT_CHARS: usize = 40_000;
/// What the Slack adapter puts between a workspace and a sender's user id.
const SLACK_USER_TARGET_INFIX: &str = ":user:";
/// A reply to a Slack message posted outside a direct message opens a thread
/// under it, so a channel is not filled with the agent's answers. A message
/// already in a thread is answered in that thread either way.
const SLACK_THREAD_CHANNEL_REPLIES: bool = true;
/// The execution field a provider's own cool-down travels on.
const RETRY_AFTER_FIELD: &str = "retry_after";

const LINE_REPLY_MESSAGE: &str = "https://api.line.me/v2/bot/message/reply";
const LINE_PUSH_MESSAGE: &str = "https://api.line.me/v2/bot/message/push";
const LINE_QUOTA_CONSUMPTION: &str = "https://api.line.me/v2/bot/message/quota/consumption";
/// The built-in LINE pack connection whose checked credential sends.
const LINE_PACK: &str = "oneiron.line";
const LINE_CONNECTION: &str = "line-channel";
/// LINE refuses a text message longer than this many characters (UTF-16
/// code units).
const LINE_MAX_TEXT_UNITS: usize = 5_000;
/// How old an inbound LINE event may be, in seconds from its own
/// `timestamp`, and still be answered with its reply token. LINE documents a
/// token as good for one minute after its webhook; past this the send pushes.
const LINE_REPLY_TOKEN_FRESH_SECS: u64 = 45;
/// The prefix the LINE adapter stamps on a sender's provider user id.
const LINE_USER_TARGET_PREFIX: &str = "line:user:";
/// LINE's answer to a reply token that is used or expired.
const LINE_INVALID_REPLY_TOKEN: &str = "Invalid reply token";
/// LINE's answer once the account has no messages left this month.
const LINE_MONTHLY_LIMIT: &str = "monthly limit";
/// How long the month-usage read before a push may take.
const LINE_USAGE_TIMEOUT: Duration = Duration::from_secs(5);

impl Vault {
    /// The plain text an outbound content ref sends, when this engine has a
    /// typed loader for it: an agent's connector reply body, or a commitment
    /// reminder.
    pub fn outbound_content_text(&self, content_ref: &str) -> Result<Option<String>> {
        if content_ref.starts_with(CONNECTOR_REPLY_BODY_PREFIX) {
            return self.connector_reply_body_text(content_ref);
        }
        self.commitment_reminder_text(content_ref)
    }
}

/// The served sink: one bounded HTTPS client and the vault its credentials
/// and content are read from.
pub struct ServedChannelSink<'a> {
    vault: &'a Vault,
    client: reqwest::blocking::Client,
    /// The LINE account plan's monthly push allowance.
    line_push_allowance: u32,
}

/// How a LINE send may go out: by the answered event's reply token, by a
/// push to the sender, or by the token while it is fresh and a push after.
#[derive(Clone, Copy, PartialEq, Eq)]
enum LineMode {
    Reply,
    Push,
    ReplyOrPush,
}

/// What one LINE call came to: a final outcome, or a reply token LINE said
/// is used or expired, which nothing was delivered on.
enum LineAnswer {
    Done(OutboundExecutionOutcome),
    TokenInvalid,
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
        Ok(Self {
            vault,
            client,
            line_push_allowance: DEFAULT_LINE_PUSH_MONTHLY_ALLOWANCE,
        })
    }

    /// The LINE account plan's monthly push allowance, LINE's free plan
    /// allowance unless the host names its plan.
    #[must_use]
    pub fn with_line_push_allowance(mut self, allowance: u32) -> Self {
        self.line_push_allowance = allowance;
        self
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
        let Some((channel, thread_ts)) = self.slack_destination(request) else {
            return OutboundExecutionOutcome::failed("slack_target_unrecognized");
        };
        let secret = match self
            .vault
            .verified_pack_connection_secret(SLACK_PACK, SLACK_CONNECTION)
        {
            Ok(secret) => secret,
            Err(_) => return OutboundExecutionOutcome::failed("slack_connection_unchecked"),
        };
        let mut body = serde_json::json!({ "channel": channel, "text": text });
        if let Some(thread_ts) = thread_ts {
            body["thread_ts"] = serde_json::Value::String(thread_ts);
        }
        let mut outcome = None;
        let _door = self.vault.inject_secret_at_door(
            &secret.name,
            &secret.effector,
            &mut |value: &[u8]| {
                let token = std::str::from_utf8(value)
                    .map_err(|_| Error::InvalidClaimBody("the stored credential is not text"))?;
                outcome = Some(self.slack_send(token.trim(), &body));
                Ok(())
            },
        );
        // Once the POST ran, what Slack said is the delivery fact, whatever
        // the door reports after it.
        outcome.unwrap_or_else(|| OutboundExecutionOutcome::failed("slack_credential_unavailable"))
    }

    /// Where a Slack send posts: the answered message's own conversation and
    /// thread ([`slack_reply_thread`]) when the send answers an inbound Slack
    /// message, else the target user's direct message (Slack opens it from
    /// the user id) or a bare channel id. `None` for a target Slack cannot
    /// address.
    fn slack_destination(
        &self,
        request: &OutboundExecutionRequest<'_>,
    ) -> Option<(String, Option<String>)> {
        if let Some(body) = self.answered_provider_event(request, SLACK_CHANNEL)
            && let Some(channel) = body
                .pointer("/event/channel")
                .and_then(serde_json::Value::as_str)
                .filter(|channel| !channel.is_empty())
        {
            return Some((channel.to_owned(), slack_reply_thread(&body)));
        }
        let target = request.intent.target.as_str();
        let to = target
            .rsplit_once(SLACK_USER_TARGET_INFIX)
            .map_or(target, |(_, user)| user);
        (!to.is_empty() && !to.contains(':')).then(|| (to.to_owned(), None))
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

    fn line_send(
        &self,
        request: &OutboundExecutionRequest<'_>,
        mode: LineMode,
    ) -> OutboundExecutionOutcome {
        let Some(text) = self.text(request) else {
            return OutboundExecutionOutcome::failed("content_unresolvable");
        };
        let text = line_text(&text);
        let secret = match self
            .vault
            .verified_pack_connection_secret(LINE_PACK, LINE_CONNECTION)
        {
            Ok(secret) => secret,
            Err(_) => return OutboundExecutionOutcome::failed("line_connection_unchecked"),
        };
        // Read before the door opens: the door holds the vault's writer.
        let reply_token = match mode {
            LineMode::Push => None,
            LineMode::Reply | LineMode::ReplyOrPush => self.line_reply_token(request),
        };
        if mode == LineMode::Reply && reply_token.is_none() {
            return OutboundExecutionOutcome::failed("line_reply_token_unavailable");
        }
        let mut outcome = None;
        let _door = self.vault.inject_secret_at_door(
            &secret.name,
            &secret.effector,
            &mut |value: &[u8]| {
                let token = std::str::from_utf8(value)
                    .map_err(|_| Error::InvalidClaimBody("the stored credential is not text"))?;
                outcome = Some(self.line_deliver(
                    token.trim(),
                    request,
                    &text,
                    reply_token.as_deref(),
                    mode,
                ));
                Ok(())
            },
        );
        // Once a call ran, what LINE said is the delivery fact, whatever the
        // door reports after it.
        outcome.unwrap_or_else(|| OutboundExecutionOutcome::failed("line_credential_unavailable"))
    }

    fn line_deliver(
        &self,
        token: &str,
        request: &OutboundExecutionRequest<'_>,
        text: &str,
        reply_token: Option<&str>,
        mode: LineMode,
    ) -> OutboundExecutionOutcome {
        let messages = serde_json::json!([{ "type": "text", "text": text }]);
        if let Some(reply_token) = reply_token {
            let body = serde_json::json!({ "replyToken": reply_token, "messages": messages });
            match self.line_call(LINE_REPLY_MESSAGE, token, &body, None, "reply") {
                LineAnswer::Done(outcome) => return outcome,
                // A used or expired token delivered nothing, so a send may
                // still push in the same attempt.
                LineAnswer::TokenInvalid if mode == LineMode::ReplyOrPush => {}
                LineAnswer::TokenInvalid => {
                    return OutboundExecutionOutcome::failed("line_reply_token_invalid");
                }
            }
        }
        let target = request.intent.target.as_str();
        let to = target
            .strip_prefix(LINE_USER_TARGET_PREFIX)
            .unwrap_or(target);
        if to.is_empty() || to.contains(':') {
            return OutboundExecutionOutcome::failed("line_target_unrecognized");
        }
        self.line_count_push(token);
        let retry_key = line_retry_key(
            request
                .idempotency_key
                .or(request.intent.idempotency_key.as_deref())
                .unwrap_or(request.intent_ref),
        );
        let body = serde_json::json!({ "to": to, "messages": messages });
        match self.line_call(LINE_PUSH_MESSAGE, token, &body, Some(&retry_key), "push") {
            LineAnswer::Done(outcome) => outcome,
            LineAnswer::TokenInvalid => OutboundExecutionOutcome::failed("line_http_400"),
        }
    }

    /// The archived provider event on `channel` this send answers: the
    /// intent's trigger names the connector event, and its frozen origin
    /// names the archived provider event. `None` when the send answers no
    /// event on `channel`, or the event is not this send's target's.
    fn answered_provider_event(
        &self,
        request: &OutboundExecutionRequest<'_>,
        channel: &str,
    ) -> Option<serde_json::Value> {
        let intent = request.intent;
        if intent.intent_source != OutboundIntentSource::AgentImmediate.as_str() {
            return None;
        }
        let agent = EntityId::from_hex(&intent.actor).ok()?;
        let event = match self.vault.connector_event_woken(agent, &intent.trigger_ref) {
            Ok(event) => event?,
            Err(error) => {
                tracing::info!(%error, channel, "the answered event is unreadable");
                return None;
            }
        };
        let origin = SurfaceConnectorPayload::from_connector_event(&event).ok()?;
        if origin.channel != channel || origin.source.user_ref != intent.target {
            return None;
        }
        let body = match self
            .vault
            .read_provider_event(origin.payload_ref.as_deref()?)
        {
            Ok(body) => body?,
            Err(error) => {
                tracing::info!(%error, channel, "the answered event's archive is unreadable");
                return None;
            }
        };
        serde_json::from_slice(&body).ok()
    }

    /// The fresh reply token of the inbound LINE event this send answers;
    /// the archive keeps the token. `None` when the send answers no LINE
    /// event, the event is not this send's sender's, or it is older than
    /// [`LINE_REPLY_TOKEN_FRESH_SECS`]: the send pushes.
    fn line_reply_token(&self, request: &OutboundExecutionRequest<'_>) -> Option<String> {
        let body = self.answered_provider_event(request, LINE_CHANNEL)?;
        fresh_line_reply_token(&body, crate::unix_seconds_now())
    }

    /// Tells the OF-520 port when this push takes the account past its plan's
    /// monthly allowance. The push goes either way, and an unreadable count
    /// never holds it.
    fn line_count_push(&self, token: &str) {
        let Some(used) = self.line_month_usage(token) else {
            tracing::info!("LINE month usage unreadable; the push goes uncounted");
            return;
        };
        let bound = u64::from(self.line_push_allowance);
        let with_this = used.saturating_add(1);
        if with_this > bound {
            self.vault
                .limit_watch()
                .crossed(EngineLimit::LinePushMonthly, bound, with_this);
        }
    }

    /// The messages LINE counts as sent this month (`totalUsage`).
    fn line_month_usage(&self, token: &str) -> Option<u64> {
        let response = self
            .client
            .get(LINE_QUOTA_CONSUMPTION)
            .bearer_auth(token)
            .timeout(LINE_USAGE_TIMEOUT)
            .send()
            .ok()?;
        if !response.status().is_success() {
            return None;
        }
        let mut body = Vec::new();
        response.take(MAX_REPLY_BYTES).read_to_end(&mut body).ok()?;
        serde_json::from_slice::<serde_json::Value>(&body)
            .ok()?
            .get("totalUsage")?
            .as_u64()
    }

    /// One LINE send call, mapped the way Slack's is: a refused connection
    /// never reached LINE; anything later may have, unless the call carried
    /// a retry key LINE dedupes on.
    fn line_call(
        &self,
        url: &str,
        token: &str,
        body: &serde_json::Value,
        retry_key: Option<&str>,
        kind: &str,
    ) -> LineAnswer {
        let mut call = self.client.post(url).bearer_auth(token).json(body);
        if let Some(retry_key) = retry_key {
            call = call.header("X-Line-Retry-Key", retry_key);
        }
        let response = match call.send() {
            Ok(response) => response,
            Err(error) if error.is_connect() => {
                return LineAnswer::Done(OutboundExecutionOutcome::failed("line_unreachable"));
            }
            Err(_) => {
                return LineAnswer::Done(
                    OutboundExecutionOutcome::failed("line_no_reply").with_possible_delivery(),
                );
            }
        };
        let status = response.status().as_u16();
        let header = |name: &str| {
            response
                .headers()
                .get(name)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
        };
        let retry_after = header(reqwest::header::RETRY_AFTER.as_str());
        let request_id = header("x-line-request-id");
        let accepted_id = header("x-line-accepted-request-id");
        // The status is the delivery fact; the body only names the message
        // and the refusal.
        let mut reply = Vec::new();
        let _ = response.take(MAX_REPLY_BYTES).read_to_end(&mut reply);
        let reply: Option<serde_json::Value> = serde_json::from_slice(&reply).ok();
        let message = reply
            .as_ref()
            .and_then(|reply| reply.get("message"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        let outcome = match status {
            200..=299 => {
                let sent = reply
                    .as_ref()
                    .and_then(|reply| reply.pointer("/sentMessages/0/id"))
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned);
                OutboundExecutionOutcome::delivered_to_channel(format!(
                    "line:{kind}:{}",
                    sent.or(request_id).unwrap_or_else(|| "unknown".to_owned())
                ))
            }
            // LINE already accepted a push with this retry key.
            409 if retry_key.is_some() => OutboundExecutionOutcome::delivered_to_channel(format!(
                "line:{kind}:{}",
                accepted_id.unwrap_or_else(|| "unknown".to_owned())
            )),
            400 if message == LINE_INVALID_REPLY_TOKEN => return LineAnswer::TokenInvalid,
            429 if message.contains(LINE_MONTHLY_LIMIT) => {
                OutboundExecutionOutcome::failed("line_monthly_limit")
            }
            429 => {
                let failed = OutboundExecutionOutcome::failed("line_rate_limited");
                match retry_after {
                    Some(secs) => failed.with_receipt_field(RETRY_AFTER_FIELD, secs),
                    None => failed,
                }
            }
            // A server fault may have landed a call LINE cannot dedupe.
            500..=599 if retry_key.is_none() => {
                OutboundExecutionOutcome::failed(format!("line_http_{status}"))
                    .with_possible_delivery()
            }
            _ => OutboundExecutionOutcome::failed(format!("line_http_{status}")),
        };
        LineAnswer::Done(outcome)
    }
}

/// A send's text cut to LINE's text-message limit, whole characters only.
fn line_text(text: &str) -> String {
    let mut units = 0;
    text.chars()
        .take_while(|c| {
            units += c.len_utf16();
            units <= LINE_MAX_TEXT_UNITS
        })
        .collect()
}

/// The thread a reply to an archived Slack message posts in: the message's
/// own thread, else, under [`SLACK_THREAD_CHANNEL_REPLIES`], a new thread
/// under a message posted outside a direct message. A direct message is
/// answered in line.
fn slack_reply_thread(body: &serde_json::Value) -> Option<String> {
    let event = body.get("event")?;
    let ts = |field: &str| {
        event
            .get(field)
            .and_then(serde_json::Value::as_str)
            .filter(|ts| !ts.is_empty())
            .map(str::to_owned)
    };
    if let Some(thread) = ts("thread_ts") {
        return Some(thread);
    }
    let direct = event
        .get("channel_type")
        .and_then(serde_json::Value::as_str)
        == Some("im");
    if SLACK_THREAD_CHANNEL_REPLIES && !direct {
        return ts("ts");
    }
    None
}

/// The reply token an archived LINE event carries, while the event is
/// younger than [`LINE_REPLY_TOKEN_FRESH_SECS`] by its own `timestamp` (ms).
fn fresh_line_reply_token(value: &serde_json::Value, now: u64) -> Option<String> {
    let token = value.pointer("/event/replyToken")?.as_str()?.trim();
    let at = value.pointer("/event/timestamp")?.as_u64()? / 1000;
    (!token.is_empty() && now.saturating_sub(at) < LINE_REPLY_TOKEN_FRESH_SECS)
        .then(|| token.to_owned())
}

/// LINE's retry key for one logical send: a UUID derived from its stable
/// idempotency key, so a retried push carries the same key and LINE sends
/// it once.
fn line_retry_key(idempotency_key: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"oneiron.line-retry-key.v1\0");
    hasher.update(idempotency_key.as_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
    // An RFC 4122 version-4 shape: LINE takes any UUID in hex form.
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    )
}

impl OutboundExecutionSink for ServedChannelSink<'_> {
    fn execute(&mut self, request: &OutboundExecutionRequest<'_>) -> OutboundExecutionOutcome {
        match (
            request.intent.channel.as_str(),
            request.intent.verb.as_str(),
        ) {
            ("slack", "send") => self.slack_post(request),
            (LINE_CHANNEL, "send") => self.line_send(request, LineMode::ReplyOrPush),
            (LINE_CHANNEL, "reply") => self.line_send(request, LineMode::Reply),
            (LINE_CHANNEL, "push") => self.line_send(request, LineMode::Push),
            _ => OutboundExecutionOutcome::failed("no_served_transport_for_channel"),
        }
    }
}

/// The served sink a host keeps past one borrow of its vault: a connector
/// event responder's. Each send builds its client and runs on a thread of
/// its own, so its blocking HTTPS calls never run on, and its client is
/// never dropped inside, the async runtime the responder is called from.
pub struct OwnedServedChannelSink {
    vault: Arc<Vault>,
    /// The LINE account plan's monthly push allowance.
    line_push_allowance: u32,
}

impl OwnedServedChannelSink {
    #[must_use]
    pub fn new(vault: Arc<Vault>, line_push_allowance: u32) -> Self {
        Self {
            vault,
            line_push_allowance,
        }
    }
}

impl OutboundExecutionSink for OwnedServedChannelSink {
    fn execute(&mut self, request: &OutboundExecutionRequest<'_>) -> OutboundExecutionOutcome {
        let vault = self.vault.as_ref();
        let allowance = self.line_push_allowance;
        std::thread::scope(|scope| {
            scope
                .spawn(|| match ServedChannelSink::new(vault) {
                    Ok(sink) => sink.with_line_push_allowance(allowance).execute(request),
                    Err(_) => OutboundExecutionOutcome::failed("served_send_client_unavailable"),
                })
                .join()
        })
        // A send that panicked may have reached the provider.
        .unwrap_or_else(|_| {
            OutboundExecutionOutcome::failed("served_send_panicked").with_possible_delivery()
        })
    }
}
