//! A registered device's complete APNs address, separate from send authority.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

use super::ApnsEnvironment;
use crate::{EntityId, Error, Result};

#[doc(hidden)]
pub use oneiron_records::outbound::served_sink::apns::address::ApnsDeviceAddress;
#[doc(hidden)]
use oneiron_records::outbound::served_sink::apns::address::{ADDRESS_PREFIX, TARGET_PREFIX};
