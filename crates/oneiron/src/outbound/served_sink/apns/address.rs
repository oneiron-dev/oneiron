//! A registered device's complete APNs address, separate from send authority.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

use super::ApnsEnvironment;
use crate::{EntityId, Error, Result};

const ADDRESS_PREFIX: &str = "apns-address:";
const TARGET_PREFIX: &str = "apns-device:";

/// Store this complete address in an `apns` ChannelIdentity. Its assignment
/// key is immutable; rotating a token or changing its app creates a new address.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApnsDeviceAddress {
    pub application: String,
    pub environment: ApnsEnvironment,
    pub topic: String,
    pub device_token: String,
}

impl ApnsDeviceAddress {
    /// The canonical opaque address accepted by the existing owner-controlled
    /// channel-identity provision door. No provider credential is in this value.
    pub fn address(&self) -> Result<String> {
        self.validate()?;
        let mut address = self.clone();
        address.device_token.make_ascii_lowercase();
        let bytes = serde_json::to_vec(&address)
            .map_err(|_| Error::InvalidClaimBody("APNs address encoding failed"))?;
        let address = format!("{ADDRESS_PREFIX}{}", URL_SAFE_NO_PAD.encode(bytes));
        if address.len()
            > crate::write_envelope::channel_identity::keys::MAX_ADDRESS_OR_HANDLE_BYTES
        {
            return Err(Error::InvalidClaimBody(
                "APNs device address exceeds channel-identity address bound",
            ));
        }
        Ok(address)
    }

    /// The normal outbound target of the identity returned by that provision.
    /// This ref is routing data; it supplies no actor, Grant or sender identity.
    #[must_use]
    pub fn target(identity: EntityId) -> String {
        format!("{TARGET_PREFIX}{}", identity.to_hex())
    }

    pub(super) fn target_identity(target: &str) -> Option<EntityId> {
        EntityId::from_hex(target.strip_prefix(TARGET_PREFIX)?).ok()
    }

    pub(super) fn parse(address: &str) -> Result<Self> {
        let invalid = || Error::InvalidClaimBody("invalid APNs device address");
        let encoded = address.strip_prefix(ADDRESS_PREFIX).ok_or_else(invalid)?;
        let bytes = URL_SAFE_NO_PAD.decode(encoded).map_err(|_| invalid())?;
        let device: Self = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
        if device.address()? != address {
            return Err(invalid());
        }
        Ok(device)
    }

    fn validate(&self) -> Result<()> {
        if self.application.is_empty()
            || self.topic.is_empty()
            || reqwest::header::HeaderValue::from_str(&self.topic).is_err()
            || self.device_token.is_empty()
            || self.device_token.len() % 2 != 0
            || !self
                .device_token
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(Error::InvalidClaimBody("invalid APNs device address"));
        }
        Ok(())
    }
}
