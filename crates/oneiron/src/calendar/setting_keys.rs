//! The catalogue keys `calendar` declares (DESIGN 15-setting-primitive, stages 1 and 4): the
//! host's iMIP mail submission transport, and the owner's CalDAV seats and ICS feeds, one item
//! each.

use serde::{Deserialize, Serialize};

use super::connectors::door::{
    CalendarImipTransportConfig, CalendarSeatSetup, is_seat_ref, seat_setup_changed_in_txn,
    validate_endpoint,
};
use super::ingest::IcsFeedPollConfig;
use super::ingest::feed_door::{ics_feed_changed_in_txn, is_feed_system};
use crate::error::{Error, Result};
use crate::setting::{ItemDomain, Kind, SettingValue};

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

fn no_seat() -> Option<CalendarSeatSetup> {
    None
}

fn no_feed() -> Option<IcsFeedPollConfig> {
    None
}

crate::setting::setting_keys! {
    /// The host's iMIP mail submission endpoint and the custody name of its credential. It
    /// grants no invite consent and no sending identity. None until the owner installs one.
    pub(crate) IMIP_TRANSPORT: ImipTransport = "calendar.imip_transport" {
        kind: Kind::new(no_transport).strictest(no_transport),
    };
    /// One CalDAV seat the owner installed, keyed by its seat ref: the discovery endpoint and the
    /// seat's config (the custody name of its credential, its system, its collection and its poll
    /// cadence). An installed seat never changes: a new configuration takes a new seat ref.
    pub(crate) CONNECTOR_SEAT: Option<CalendarSeatSetup> = "calendar.connector_seat" {
        kind: Kind::new(no_seat).strictest(no_seat),
        item: Some(ItemDomain { name: "calendar seat refs", admits: is_seat_ref }),
        on_change: Some(seat_setup_changed_in_txn),
    };
    /// One ICS feed the owner installed, keyed by its system: the custody name of its URL and its
    /// poll cadence. It grants no import consent. An installed feed never changes: a new
    /// configuration takes a new system. Installing one starts its poll chain.
    pub(crate) ICS_FEED: Option<IcsFeedPollConfig> = "calendar.ics_feed" {
        kind: Kind::new(no_feed).strictest(no_feed),
        item: Some(ItemDomain { name: "ICS feed systems", admits: is_feed_system }),
        on_change: Some(ics_feed_changed_in_txn),
    };
}
