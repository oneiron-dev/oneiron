//! The setting keys `web_connector` declares (Setting stage 1): the crate's build script lists
//! each row in the setting catalogue.

use super::setting::WebConnectorSetting;
use crate::setting::{Kind, Restore};

crate::setting::setting_keys! {
    /// Which provider serves the vault's web calls (`connector.web.*`), on whose key: the
    /// deploy's backend key (only a provider whose terms allow it), the owner's custody secret,
    /// or an installed hub connector. Unset: Tavily on the backend key (CONN-1 A). The server
    /// reads it at each web call.
    pub(crate) WEB_CONNECTOR: WebConnectorSetting = "connectors.web" {
        kind: Kind::new(WebConnectorSetting::default),
        restore: Restore::Content,
    };
}
