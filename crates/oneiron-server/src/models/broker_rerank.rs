//! A `key_secret` provider's rerank leg (L9-12): each batch a rerank call
//! sends is one credential-broker call of [`Shape::Rerank`], as a chat call
//! is ([`super::broker`]) and a media exchange is ([`super::broker_media`]).
//! The exact request is built and checked as the broker will check it before
//! anything connects. Only then does the call connect, read the key at the
//! custody door and hand the broker the key with that one request. The
//! broker adds the Bearer auth, buffers the reply up to
//! [`oneiron_broker::MAX_BODY`] (a longer one is refused whole, never cut),
//! and strips every form of the key from its body and headers before it
//! comes back. The body, the scores and the settlement are the direct
//! transport's ([`super::rerank`]).
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use oneiron::llm::{BrokerIsolation, DispatchRelease};
use oneiron::{BudgetLease, FatalLlmError, LlmError, LlmResult, RetryableLlmError};
use oneiron_broker::{BrokerClient, CallHeader, Isolation, Shape};
use serde_json::Value as JsonValue;

use super::broker::{BrokerSite, KeyDoor, REPLY_MARGIN, answered, call_with_key_released, join};
use super::http::{JsonReply, is_cloud_node};
use super::rerank::RERANK_PATH;
use crate::config::models::ProviderConfig;

const JSON: &str = "application/json";

/// One `key_secret` provider's rerank requests over the broker.
pub(super) struct BrokerRerank {
    /// The provider's `https://host[:port]`.
    origin: String,
    /// The base URL's path under the origin, with no trailing `/`.
    prefix: String,
    /// The provider's extra headers, names lowercase.
    headers: BTreeMap<String, String>,
    secret: String,
    client: BrokerClient,
    keys: Arc<dyn KeyDoor>,
}

impl BrokerRerank {
    /// The rerank leg of `key_secret` provider `provider`, over the broker
    /// at `site`, its key read at `keys`.
    pub(super) fn new(
        provider: &ProviderConfig,
        site: Option<&Result<BrokerSite, String>>,
        keys: Option<&Arc<dyn KeyDoor>>,
    ) -> anyhow::Result<Self> {
        let site = site
            .ok_or_else(|| anyhow::anyhow!("no credential broker was made"))?
            .as_ref()
            .map_err(|error| anyhow::anyhow!("{error}"))?;
        let secret = provider
            .key_secret
            .clone()
            .ok_or_else(|| anyhow::anyhow!("the provider names no key_secret"))?;
        let keys = keys
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("this server has no vault custody door"))?;
        let client = site.client(Duration::from_secs(provider.timeout_secs) + REPLY_MARGIN)?;
        let url = reqwest::Url::parse(&provider.base_url)?;
        Ok(Self {
            origin: url.origin().ascii_serialization(),
            prefix: url.path().trim_end_matches('/').to_owned(),
            headers: provider
                .headers
                .iter()
                .map(|(name, value)| (name.to_ascii_lowercase(), value.clone()))
                .collect(),
            secret,
            client,
            keys,
        })
    }

    /// What a call can fail on before anything is sent, short of the
    /// broker's own answer, as a chat call's preflight checks it: a broker to
    /// send through (the same-user child starts here at its first call), and
    /// a key the custody door would hand over.
    pub(super) fn ready(&self) -> LlmResult<()> {
        if let Err(error) = self.client.ready() {
            tracing::warn!(%error, "no credential broker to send rerank calls through");
            return Err(RetryableLlmError::StreamCut.into());
        }
        self.keys.check(&self.secret).map_err(|_| {
            tracing::warn!(
                reason = "key_custody_refused",
                "the custody door would refuse a reranker provider key"
            );
            LlmError::from(FatalLlmError::Auth)
        })
    }

    /// How the broker this provider sends through is kept apart.
    pub(super) fn isolation(&self) -> BrokerIsolation {
        match self.client.isolation() {
            Isolation::SeparateUser => BrokerIsolation::SeparateUser,
            Isolation::SameUser => BrokerIsolation::SameUser,
        }
    }

    /// The call frame's header for one batch's `body`, naming `wire_model`,
    /// and the exact bytes it carries, checked as the broker will check
    /// them. `call` is the broker's call id; the digest does not cover it.
    fn build(
        &self,
        wire_model: &str,
        body: &JsonValue,
        call: &str,
    ) -> LlmResult<(CallHeader, Vec<u8>)> {
        let bytes = serde_json::to_vec(body).map_err(|_| invalid())?;
        let mut headers = self.headers.clone();
        headers.insert("content-type".to_owned(), JSON.to_owned());
        let header = CallHeader::new(
            call.to_owned(),
            Shape::Rerank,
            self.origin.clone(),
            join(&self.prefix, RERANK_PATH),
            headers.into_iter().collect(),
            wire_model.to_owned(),
            is_cloud_node(),
            &bytes,
        );
        header.check(&bytes).map_err(|_| invalid())?;
        Ok((header, bytes))
    }

    /// Sends one batch's `body` as the call `lease` admitted: checked as
    /// the broker will check it, then the key read at the door and the one
    /// broker call, each physical send released by the lease's own checks.
    /// The provider's status, its headers (names lowercase) and its reply
    /// as JSON, read as the direct transport reads one: an empty body is
    /// null, and a body that does not parse is null on an error status and
    /// no answer otherwise.
    pub(super) async fn post_json(
        &self,
        wire_model: &str,
        body: &JsonValue,
        lease: &BudgetLease,
    ) -> LlmResult<JsonReply> {
        let (header, bytes) = self.build(wire_model, body, lease.id())?;
        // As the chat leg's send: a lease with release checks runs them after
        // the key is read and before each physical send, and counts that send.
        let check: DispatchRelease<'_> = &|| lease.check_dispatch_release();
        let gated = lease.has_dispatch_release();
        let reply = call_with_key_released(
            &self.client,
            &self.keys,
            &self.secret,
            &header,
            &bytes,
            gated.then_some(check),
            gated.then_some(lease),
        )
        .await?;
        let (status, headers) = answered(reply.outcome)?;
        let headers = headers
            .into_iter()
            .map(|(name, value)| (name.to_ascii_lowercase(), value))
            .collect();
        let body = if reply.body.is_empty() {
            JsonValue::Null
        } else {
            match serde_json::from_slice(&reply.body) {
                Ok(body) => body,
                Err(_) if !(200..300).contains(&status) => JsonValue::Null,
                Err(_) => return Err(FatalLlmError::EmptyResponse.into()),
            }
        };
        Ok(JsonReply {
            status,
            headers,
            body,
        })
    }
}

fn invalid() -> LlmError {
    FatalLlmError::InvalidRequest.into()
}
