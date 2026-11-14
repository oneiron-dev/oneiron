//! Moved from `crates/oneiron/src/outbound/served_sink/apns/mod.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::outbound::served_sink::apns::address::ApnsDeviceAddress;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;
use std::fmt;
use std::io::Read;
use std::sync::Mutex;

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
pub mod address;
