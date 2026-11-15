//! The setting keys `web_connector` declares (Setting stage 1): the crate's build script lists
//! each row in the setting catalogue.
//!
//! The two result caps (owner ruling PACK-SETTINGS-ALL = B) bound how much of a search hit's
//! snippet and of a fetched page the server's own providers hand back. Each default is the
//! shipped cap. The owner changes a value; an agent's change waits on the owner's approval.
//! Direction: neither cap has a safe side (the text comes from the open web into the vault's own
//! run), so neither has an order, and a row that does not decode reads as the shipped cap.

use serde::{Deserialize, Serialize};

use super::setting::WebConnectorSetting;
use super::{FETCH_CONTENT_MAX_CHARS, SNIPPET_MAX_CHARS, WebResultLimits};
use crate::error::{Error, Result};
use crate::setting::{Kind, Restore, SettingValue};

/// A web result's length cap in characters: at least 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(transparent)]
pub(crate) struct WebResultMaxChars(pub(crate) u32);

impl SettingValue for WebResultMaxChars {
    fn check(self) -> Result<Self> {
        if self.0 >= 1 {
            Ok(self)
        } else {
            Err(Error::InvalidConfig(
                "a web result keeps at least one character".to_owned(),
            ))
        }
    }
}

fn chars(cap: usize) -> WebResultMaxChars {
    WebResultMaxChars(u32::try_from(cap).unwrap_or(u32::MAX))
}

fn shipped_snippet_max_chars() -> WebResultMaxChars {
    chars(SNIPPET_MAX_CHARS)
}

fn shipped_fetch_max_chars() -> WebResultMaxChars {
    chars(FETCH_CONTENT_MAX_CHARS)
}

crate::setting::setting_keys! {
    /// Which provider serves the vault's web calls (`connector.web.*`), on whose key: the
    /// deploy's backend key (only a provider whose terms allow it), the owner's custody secret,
    /// or an installed hub connector. Unset: Tavily on the backend key (CONN-1 A). The server
    /// reads it at each web call.
    pub(crate) WEB_CONNECTOR: WebConnectorSetting = "connectors.web" {
        kind: Kind::new(WebConnectorSetting::default),
        restore: Restore::Content,
    };
    /// The most characters of one search hit's snippet a web search hands back (default 300, as
    /// Afterglow's `search_web` cuts it). The server reads it at each search its own provider
    /// serves; a hub connector's reply stands as it came. No order: the text comes from the open
    /// web into the vault's own run.
    pub(crate) WEB_SNIPPET_MAX_CHARS: WebResultMaxChars = "connectors.web.snippet_max_chars" {
        kind: Kind::new(shipped_snippet_max_chars).strictest(shipped_snippet_max_chars),
    };
    /// The most characters of one fetched page's text a web fetch hands back (default 50,000).
    /// A provider that reads the page itself is asked for at most as many (Exa's
    /// `maxCharacters`). The server reads it at each fetch its own provider or reader serves; a
    /// hub connector's reply stands as it came. No order: the text comes from the open web into
    /// the vault's own run.
    pub(crate) WEB_FETCH_MAX_CHARS: WebResultMaxChars = "connectors.web.fetch_max_chars" {
        kind: Kind::new(shipped_fetch_max_chars).strictest(shipped_fetch_max_chars),
    };
}

impl crate::Vault {
    /// The vault's caps on a web call's results (`connectors.web.snippet_max_chars` and
    /// `connectors.web.fetch_max_chars`), or the shipped caps when the owner set none. The
    /// server reads them for every web call its own providers serve.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn web_result_limits(&self) -> Result<WebResultLimits> {
        let txn = self.store.env.read_txn()?;
        let snippet = WEB_SNIPPET_MAX_CHARS
            .read_in_txn(self, &txn, &[], None)?
            .value
            .0;
        let fetch = WEB_FETCH_MAX_CHARS
            .read_in_txn(self, &txn, &[], None)?
            .value
            .0;
        Ok(WebResultLimits {
            snippet_max_chars: usize::try_from(snippet).unwrap_or(usize::MAX),
            fetch_max_chars: usize::try_from(fetch).unwrap_or(usize::MAX),
        })
    }
}
