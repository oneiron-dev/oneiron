//! The OAuth access token one Sheets send presents (FIX 4862), read from the
//! stored grant inside the custody door that released it.
//!
//! A grant that carries a refresh token and its OAuth client (what the Google
//! code exchange stores) is exchanged at Google's token endpoint for a fresh
//! access token on each send, so the hour an access token lives never runs
//! out mid-use. A grant without one presents its stored access token, and
//! bare text is the access token. Nothing here is persisted or logged.

use std::time::Duration;

use serde::Deserialize;
use zeroize::{Zeroize, Zeroizing};

use crate::connector_key::ProviderConnectionChecks;
use crate::error::{Error, Result};

/// The client a refresh exchange runs on: HTTPS only, no redirects, a 15 s
/// timeout.
pub(super) fn refresh_client() -> Result<reqwest::blocking::Client> {
    reqwest::blocking::Client::builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|_| Error::InvalidConfig("sheets refresh client setup failed".to_owned()))
}

/// The access token the stored grant `value` presents, refreshed when the
/// grant can be.
pub(super) fn access_token(
    client: &reqwest::blocking::Client,
    value: &[u8],
) -> Result<Zeroizing<String>> {
    if let Some(fresh) = ProviderConnectionChecks::refresh_stored_google_grant(client, value)? {
        return Ok(fresh);
    }
    let unusable =
        || Error::InvalidConfig("sheets credential is not a usable access token".to_owned());
    let text = std::str::from_utf8(value).map_err(|_| unusable())?.trim();
    let access_token = if text.starts_with('{') {
        let grant: StoredAccess = serde_json::from_str(text).map_err(|_| unusable())?;
        Zeroizing::new(
            grant
                .access_token
                .as_deref()
                .map_or("", str::trim)
                .to_owned(),
        )
    } else {
        Zeroizing::new(text.to_owned())
    };
    if access_token.is_empty() {
        return Err(unusable());
    }
    Ok(access_token)
}

/// The access token a stored grant holds, wiped on drop. Its other fields
/// are skipped unread.
#[derive(Deserialize)]
struct StoredAccess {
    #[serde(default)]
    access_token: Option<String>,
}

impl Drop for StoredAccess {
    fn drop(&mut self) {
        self.access_token.zeroize();
    }
}
