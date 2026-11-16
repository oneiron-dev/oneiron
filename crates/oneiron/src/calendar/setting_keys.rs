//! The catalogue keys `calendar` declares (DESIGN 15-setting-primitive, stage 1): the host's
//! iMIP mail submission transport.

use serde::{Deserialize, Serialize};

use super::connectors::door::{CalendarImipTransportConfig, validate_endpoint};
use crate::error::{Error, Result};
use crate::setting::{Kind, SettingValue};

/// The longest custody name an iMIP transport may carry, in bytes.
const SECRET_REF_MAX_BYTES: usize = 256;

/// The host's iMIP mail submission endpoint and the custody name of its credential, or none: no
/// invite leaves by mail until the owner installs one. The credential's bytes stay in custody
/// (ARCH-0069); the setting holds only its name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(transparent)]
pub(crate) struct ImipTransport(pub(crate) Option<CalendarImipTransportConfig>);

impl SettingValue for ImipTransport {
    fn check(self) -> Result<Self> {
        if let Some(config) = &self.0 {
            validate_endpoint(&config.endpoint)
                .map_err(|error| Error::InvalidConfig(error.message))?;
            if config.secret_ref.is_empty()
                || config.secret_ref.len() > SECRET_REF_MAX_BYTES
                || config.secret_ref.chars().any(char::is_control)
            {
                return Err(Error::InvalidConfig(
                    "secret_ref must be a bounded custody name".into(),
                ));
            }
        }
        Ok(self)
    }
}

fn no_transport() -> ImipTransport {
    ImipTransport(None)
}

crate::setting::setting_keys! {
    /// The host's iMIP mail submission endpoint and the custody name of its credential. It
    /// grants no invite consent and no sending identity. None until the owner installs one.
    pub(crate) IMIP_TRANSPORT: ImipTransport = "calendar.imip_transport" {
        kind: Kind::new(no_transport).strictest(no_transport),
    };
}
