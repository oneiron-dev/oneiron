//! Moved from `crates/oneiron/src/authority/oauth_server/clients.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::authority::oauth_server::OAUTH_CIMD_TTL_SECS;
use reqwest::Url;
use serde::Deserialize;
use serde::Serialize;

/// One client that may sign in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OAuthClientRecord {
    /// The client ID it signs in with: the vault's own for a registered client, the metadata
    /// document's URL for the other.
    pub client_id: String,
    /// The name it gave, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,
    /// The redirect URIs it may name, each one [`oauth_redirect_uri_admitted`] admits.
    pub redirect_uris: Vec<String>,
    pub source: OAuthClientSource,
    /// When it was first registered or its document first fetched (Unix seconds).
    pub registered_at: u64,
}

/// How a client became known.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OAuthClientSource {
    /// Registered at `/oauth/register`.
    Registered,
    /// Read from the metadata document its `client_id` names.
    MetadataDocument {
        /// The BLAKE3 hash of the document's bytes (hex64).
        document_hash: String,
        /// When the document was last fetched (Unix seconds).
        fetched_at: u64,
    },
}

impl OAuthClientRecord {
    /// Whether `redirect_uri` is one this client listed: the exact string, or, for a loopback
    /// http URI, the same one on any port (RFC 8252 §7.3; CALLS, FIX 4902: an engine call).
    #[must_use]
    pub fn admits_redirect_uri(&self, redirect_uri: &str) -> bool {
        self.redirect_uris
            .iter()
            .any(|listed| redirect_uri_matches(listed, redirect_uri))
    }

    /// Whether the client may sign in at `now` without fetching anything: always for a
    /// registered client; for a metadata-document one, until [`OAUTH_CIMD_TTL_SECS`] past the
    /// last fetch.
    #[must_use]
    pub fn is_fresh_at(&self, now: u64) -> bool {
        match &self.source {
            OAuthClientSource::Registered => true,
            OAuthClientSource::MetadataDocument { fetched_at, .. } => {
                now < fetched_at.saturating_add(OAUTH_CIMD_TTL_SECS)
            }
        }
    }

    /// The name the owner reads: the one the client gave, else its client ID.
    #[must_use]
    pub fn display_name(&self) -> &str {
        self.client_name.as_deref().unwrap_or(&self.client_id)
    }

    /// The host the owner reads beside the name: a metadata-document client's `client_id` host;
    /// for a registered one, `redirect_uri`'s host, or its scheme when it names none (a native
    /// app's private-use scheme).
    #[must_use]
    pub fn display_host(&self, redirect_uri: &str) -> String {
        let named = match self.source {
            OAuthClientSource::MetadataDocument { .. } => self.client_id.as_str(),
            OAuthClientSource::Registered => redirect_uri,
        };
        match Url::parse(named) {
            Ok(url) => url
                .host_str()
                .map_or_else(|| url.scheme().to_owned(), str::to_owned),
            Err(_) => String::new(),
        }
    }
}

/// An http URL on a loopback host.
pub fn is_loopback_http(url: &Url) -> bool {
    url.scheme() == "http" && matches!(url.host_str(), Some("127.0.0.1" | "[::1]" | "localhost"))
}

/// Whether the asked redirect URI is the listed one: the same string, or the same loopback http
/// URI on another port.
pub fn redirect_uri_matches(listed: &str, asked: &str) -> bool {
    if listed == asked {
        return true;
    }
    let (Ok(listed), Ok(asked)) = (Url::parse(listed), Url::parse(asked)) else {
        return false;
    };
    is_loopback_http(&listed)
        && is_loopback_http(&asked)
        && listed.host_str() == asked.host_str()
        && listed.path() == asked.path()
        && listed.query() == asked.query()
        && asked.fragment().is_none()
}
