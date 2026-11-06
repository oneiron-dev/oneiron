//! APNs alert delivery through a live T0 key and the normal outbound ledger.

mod address;
mod session;

use std::fmt;
use std::io::Read;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use super::{MAX_REPLY_BYTES, ServedChannelSink};
use crate::channel_identity::ChannelIdentityState;
use crate::outbound::{OutboundExecutionOutcome, OutboundExecutionRequest};
use crate::outbound_intent_ledger::ProviderWaitKind;
use crate::{EntityId, Error, Result};
pub use address::ApnsDeviceAddress;

/// The existing owner secret door must permit this effector for the key.
pub const APNS_EFFECTOR: &str = "apns.push";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApnsEnvironment {
    Sandbox,
    Production,
}

impl ApnsEnvironment {
    const fn endpoint(self) -> &'static str {
        match self {
            Self::Sandbox => "https://api.sandbox.push.apple.com",
            Self::Production => "https://api.push.apple.com",
        }
    }
}

/// Public account metadata only. The Apple .p8 key is an existing immutable
/// SECRET record, admitted afresh by the T0 door for every provider request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApnsAppConfig {
    pub id: String,
    pub team_id: String,
    pub key_id: String,
    pub topic: String,
    pub environment: ApnsEnvironment,
    pub signing_key_ref: String,
}

impl ApnsAppConfig {
    pub fn validate(&self) -> Result<()> {
        if self.id.is_empty()
            || self.team_id.is_empty()
            || self.key_id.is_empty()
            || self.topic.is_empty()
            || reqwest::header::HeaderValue::from_str(&self.topic).is_err()
        {
            return Err(Error::InvalidConfig(
                "invalid APNs application metadata".to_owned(),
            ));
        }
        EntityId::from_hex(&self.signing_key_ref)?;
        Ok(())
    }
}

pub(super) struct ApnsApplication {
    config: ApnsAppConfig,
    secret: EntityId,
    session: Mutex<Option<session::AuthSession>>,
}

impl fmt::Debug for ApnsApplication {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.debug_struct("ApnsApplication")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl ApnsApplication {
    pub(super) fn new(config: ApnsAppConfig) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            secret: EntityId::from_hex(&config.signing_key_ref)?,
            config,
            session: Mutex::new(None),
        })
    }

    pub(super) fn id(&self) -> &str {
        &self.config.id
    }
}

impl ServedChannelSink<'_> {
    pub(super) fn apns_push(
        &self,
        request: &OutboundExecutionRequest<'_>,
    ) -> OutboundExecutionOutcome {
        let device = match self.apns_device(request.intent.target.as_str()) {
            Ok(Some(device)) => device,
            _ => return OutboundExecutionOutcome::failed("apns_device_unresolvable"),
        };
        let Some(application) = self.transports.apns_application(&device.application) else {
            return OutboundExecutionOutcome::failed("apns_application_unconfigured");
        };
        if application.config.environment != device.environment
            || application.config.topic != device.topic
        {
            return OutboundExecutionOutcome::failed("apns_application_binding_changed");
        }
        let Some(text) = self.text(request) else {
            return OutboundExecutionOutcome::failed("content_unresolvable");
        };
        let mut body = serde_json::json!({"aps": {"alert": text}});
        if let Some(level) = request.apns_interruption_level {
            let label = if level
                == crate::delivery_window::DeliveryWindowApnsInterruptionLevel::TimeSensitive
            {
                "time-sensitive"
            } else {
                level.as_str()
            };
            body["aps"]["interruption-level"] = serde_json::Value::String(label.to_owned());
        }
        let mut outcome = None;
        let _door = self.vault.inject_secret_record_at_door(
            &application.secret,
            APNS_EFFECTOR,
            &mut |key| {
                let (client, token) = session::credentials(
                    &application.session,
                    &application.config,
                    key,
                    crate::unix_seconds_now(),
                )?;
                outcome = Some(apns_send(&client, &token, &device, &body));
                Ok(())
            },
        );
        outcome.unwrap_or_else(|| OutboundExecutionOutcome::failed("apns_credential_unavailable"))
    }

    fn apns_device(&self, target: &str) -> Result<Option<ApnsDeviceAddress>> {
        let Some(id) = ApnsDeviceAddress::target_identity(target) else {
            return Ok(None);
        };
        let Some(identity) = self.vault.get_channel_identity(&id)? else {
            return Ok(None);
        };
        if identity.channel() != "apns" || identity.state() != ChannelIdentityState::Active {
            return Ok(None);
        }
        ApnsDeviceAddress::parse(identity.address_or_handle()).map(Some)
    }
}

fn apns_send(
    client: &reqwest::blocking::Client,
    token: &str,
    device: &ApnsDeviceAddress,
    body: &serde_json::Value,
) -> OutboundExecutionOutcome {
    let url = format!(
        "{}/3/device/{}",
        device.environment.endpoint(),
        device.device_token
    );
    let response = match client
        .post(url)
        .version(reqwest::Version::HTTP_2)
        .bearer_auth(token)
        .header("apns-topic", &device.topic)
        .header("apns-push-type", "alert")
        .json(body)
        .send()
    {
        Ok(response) => response,
        Err(error) if error.is_connect() => {
            return OutboundExecutionOutcome::failed("apns_unreachable");
        }
        Err(_) => {
            return OutboundExecutionOutcome::failed("apns_no_reply").with_possible_delivery();
        }
    };
    if response.version() != reqwest::Version::HTTP_2 {
        return OutboundExecutionOutcome::failed("apns_reply_not_http2").with_possible_delivery();
    }
    let status = response.status().as_u16();
    let id = response
        .headers()
        .get("apns-id")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    if status == 200 {
        return OutboundExecutionOutcome::delivered_to_channel(
            id.map_or_else(|| "apns:accepted".to_owned(), |id| format!("apns:{id}")),
        );
    }
    let retry_after = response
        .headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let mut bytes = Vec::new();
    let reply = if response
        .take(MAX_REPLY_BYTES)
        .read_to_end(&mut bytes)
        .is_ok()
    {
        serde_json::from_slice::<serde_json::Value>(&bytes).ok()
    } else {
        None
    };
    let mut outcome = OutboundExecutionOutcome::failed(format!("apns_http_{status}"));
    if let Some(id) = id {
        outcome = outcome.with_receipt_field("apns_id", id);
    }
    if let Some(reason) = reply
        .as_ref()
        .and_then(|reply| reply.get("reason"))
        .and_then(serde_json::Value::as_str)
    {
        outcome = outcome.with_receipt_field("apns_reason", reason);
    }
    if let Some(timestamp) = reply
        .as_ref()
        .and_then(|reply| reply.get("timestamp"))
        .and_then(serde_json::Value::as_u64)
    {
        outcome = outcome.with_receipt_field("apns_timestamp", timestamp.to_string());
    }
    if status == 429 {
        outcome = outcome.with_provider_wait(ProviderWaitKind::RateLimit);
        if let Some(value) = retry_after {
            outcome = outcome.with_receipt_field("retry_after", value);
        }
    }
    outcome
}
