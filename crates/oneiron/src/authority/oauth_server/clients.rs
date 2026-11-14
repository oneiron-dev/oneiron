//! The apps that may sign in, in one table: ones registered at `/oauth/register` (RFC 7591), and
//! ones known by the client ID metadata document their https `client_id` names (CIMD, at the
//! draft canon pins). DCR sits beside CIMD (ARCH-0028:90). Only public clients are admitted:
//! every client proves its code with PKCE, never with a secret.

use std::collections::BTreeSet;

use reqwest::Url;
use serde::{Deserialize, Serialize};

use super::rows::{CLIENTS, FAMILIES, REQUESTS, client_key};
use super::{
    OAUTH_CIMD_TTL_SECS, OAUTH_CLIENT_NAME_MAX_CHARS, OAUTH_CLIENTS_MAX, OAUTH_REDIRECT_URIS_MAX,
    OAUTH_URI_MAX_BYTES,
};
use crate::error::Result;
use crate::{EntityId, Vault};

/// The grant types a client may register: the two this vault serves.
const GRANT_TYPES: [&str; 2] = ["authorization_code", "refresh_token"];

#[doc(hidden)]
pub use oneiron_records::authority::oauth_server::clients::{OAuthClientRecord, OAuthClientSource};
#[doc(hidden)]
use oneiron_records::authority::oauth_server::clients::{is_loopback_http, redirect_uri_matches};

/// What an app asks to register with (RFC 7591 §2): the fields this vault reads. Every other
/// field of its request is ignored.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OAuthClientRegistration {
    pub redirect_uris: Vec<String>,
    pub client_name: Option<String>,
    pub token_endpoint_auth_method: Option<String>,
    pub grant_types: Option<Vec<String>>,
    pub response_types: Option<Vec<String>>,
}

/// Why a registration, or a metadata document, is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OAuthRegistrationRefusal {
    /// A redirect URI is missing, too many, or not one [`oauth_redirect_uri_admitted`] admits.
    InvalidRedirectUri,
    /// A name too long, a client secret method, or a grant or response type this vault does not
    /// serve.
    InvalidClientMetadata,
    /// The clients table holds [`OAUTH_CLIENTS_MAX`] clients.
    RegistryFull,
}

impl OAuthRegistrationRefusal {
    /// Its error code: RFC 7591 §3.2.2's two, and `temporarily_unavailable` for a full table.
    #[must_use]
    pub const fn error_code(self) -> &'static str {
        match self {
            Self::InvalidRedirectUri => "invalid_redirect_uri",
            Self::InvalidClientMetadata => "invalid_client_metadata",
            Self::RegistryFull => "temporarily_unavailable",
        }
    }
}

/// Whether this vault admits `uri` as a client's redirect URI (CALLS, FIX 4902: an engine call;
/// canon names no DCR policy detail): at most [`OAUTH_URI_MAX_BYTES`], with no fragment and no
/// user info, and either https with a host, http on a loopback host (`127.0.0.1`, `[::1]` or
/// `localhost`, RFC 8252 §7.3), or a native app's private-use scheme in reverse-domain form, a
/// scheme with a `.` in it (RFC 8252 §7.1).
#[must_use]
pub fn oauth_redirect_uri_admitted(uri: &str) -> bool {
    if uri.len() > OAUTH_URI_MAX_BYTES {
        return false;
    }
    let Ok(url) = Url::parse(uri) else {
        return false;
    };
    if url.fragment().is_some() || !url.username().is_empty() || url.password().is_some() {
        return false;
    }
    match url.scheme() {
        "https" => url.host_str().is_some_and(|host| !host.is_empty()),
        "http" => is_loopback_http(&url),
        scheme => scheme.contains('.'),
    }
}

/// Whether `client_id` is a client ID metadata document URL this vault fetches (CALLS, FIX 4902:
/// an engine call; canon pins draft-00): at most [`OAUTH_URI_MAX_BYTES`], https with a host and
/// a path past `/`, no query, fragment, user info or dot segment, and spelled as the URL parser
/// spells it.
#[must_use]
pub fn oauth_client_id_is_metadata_url(client_id: &str) -> bool {
    if client_id.len() > OAUTH_URI_MAX_BYTES || !client_id.starts_with("https://") {
        return false;
    }
    let Ok(url) = Url::parse(client_id) else {
        return false;
    };
    url.scheme() == "https"
        && url.host_str().is_some_and(|host| !host.is_empty())
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && url.path() != "/"
        && url.as_str() == client_id
        && !client_id
            .split('/')
            .any(|segment| segment == "." || segment == "..")
}

/// The metadata a registration or a metadata document gives, checked against what this vault
/// serves.
fn check_client_metadata(
    redirect_uris: &[String],
    client_name: Option<&str>,
    token_endpoint_auth_method: Option<&str>,
    grant_types: Option<&[String]>,
    response_types: Option<&[String]>,
) -> std::result::Result<(), OAuthRegistrationRefusal> {
    if redirect_uris.is_empty()
        || redirect_uris.len() > OAUTH_REDIRECT_URIS_MAX
        || !redirect_uris
            .iter()
            .all(|uri| oauth_redirect_uri_admitted(uri))
    {
        return Err(OAuthRegistrationRefusal::InvalidRedirectUri);
    }
    let name_admitted = client_name.is_none_or(|name| {
        !name.trim().is_empty()
            && name.chars().count() <= OAUTH_CLIENT_NAME_MAX_CHARS
            && !name.chars().any(char::is_control)
    });
    let public = token_endpoint_auth_method.is_none_or(|method| method == "none");
    let grants = grant_types.is_none_or(|types| {
        types
            .iter()
            .all(|grant| GRANT_TYPES.contains(&grant.as_str()))
    });
    let responses =
        response_types.is_none_or(|types| types.iter().all(|response| response == "code"));
    if name_admitted && public && grants && responses {
        Ok(())
    } else {
        Err(OAuthRegistrationRefusal::InvalidClientMetadata)
    }
}

/// The fields of a client ID metadata document this vault reads; every other is ignored.
#[derive(Deserialize)]
struct MetadataDocument {
    client_id: String,
    #[serde(default)]
    client_name: Option<String>,
    #[serde(default)]
    redirect_uris: Vec<String>,
    #[serde(default)]
    token_endpoint_auth_method: Option<String>,
    #[serde(default)]
    grant_types: Option<Vec<String>>,
    #[serde(default)]
    response_types: Option<Vec<String>>,
}

impl Vault {
    /// Registers a public client (RFC 7591) with a fresh client ID, or says why not. Its
    /// redirect URIs, name, auth method, grant types and response types are checked as a
    /// metadata document's are.
    ///
    /// # Errors
    /// A store failure.
    pub fn register_oauth_client(
        &self,
        registration: &OAuthClientRegistration,
        now: u64,
    ) -> Result<std::result::Result<OAuthClientRecord, OAuthRegistrationRefusal>> {
        if let Err(refusal) = check_client_metadata(
            &registration.redirect_uris,
            registration.client_name.as_deref(),
            registration.token_endpoint_auth_method.as_deref(),
            registration.grant_types.as_deref(),
            registration.response_types.as_deref(),
        ) {
            return Ok(Err(refusal));
        }
        let record = OAuthClientRecord {
            client_id: EntityId::now().to_hex(),
            client_name: registration.client_name.clone(),
            redirect_uris: registration.redirect_uris.clone(),
            source: OAuthClientSource::Registered,
            registered_at: now,
        };
        self.with_write_txn_grouped(|txn| {
            if !self.make_oauth_client_room_in_txn(txn, now)? {
                return Ok(Err(OAuthRegistrationRefusal::RegistryFull));
            }
            CLIENTS.put(&self.store, txn, &client_key(&record.client_id), &record)?;
            Ok(Ok(record))
        })
    }

    /// Whether the clients table has room for one more client at `now`, made in the caller's
    /// writer when it is full: a client that holds no live token family and no pending sign-in
    /// yields its slot, the oldest registered first, so open registration can never fill the
    /// table for good (review #6508). Only a table full of clients in use has no room. An engine
    /// call (CALLS, FIX 4902).
    fn make_oauth_client_room_in_txn(&self, txn: &mut heed::RwTxn<'_>, now: u64) -> Result<bool> {
        let clients = CLIENTS.scan(&self.store, txn)?;
        if clients.len() < OAUTH_CLIENTS_MAX {
            return Ok(true);
        }
        let in_use = self.oauth_clients_in_use_in_txn(txn, now)?;
        let unused = clients
            .into_iter()
            .filter(|(_, client)| !in_use.contains(&client.client_id))
            .min_by_key(|(_, client)| client.registered_at);
        let Some((key, _)) = unused else {
            return Ok(false);
        };
        CLIENTS.delete(&self.store, txn, &key)?;
        Ok(true)
    }

    /// The client IDs in use at `now`: each one a standing token family (not revoked, not lapsed)
    /// or a request still within its lifetime names. A client in use never yields its slot in
    /// the clients table, and the sweep of lapsed rows keeps its row.
    pub(super) fn oauth_clients_in_use_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        now: u64,
    ) -> Result<BTreeSet<String>> {
        let mut in_use = BTreeSet::new();
        for (_, family) in FAMILIES.scan(&self.store, txn)? {
            if !family.revoked && now < family.expires_at {
                in_use.insert(family.client_id);
            }
        }
        for (_, request) in REQUESTS.scan(&self.store, txn)? {
            if now < request.expires_at {
                in_use.insert(request.client_id);
            }
        }
        Ok(in_use)
    }

    /// The client `client_id` names, as last stored; `None` for one this vault does not know. A
    /// metadata-document client may be stale ([`OAuthClientRecord::is_fresh_at`]).
    ///
    /// # Errors
    /// A store failure.
    pub fn oauth_client(&self, client_id: &str) -> Result<Option<OAuthClientRecord>> {
        let txn = self.store.env.read_txn()?;
        Ok(CLIENTS
            .get(&self.store, &txn, &client_key(client_id))?
            .filter(|record| record.client_id == client_id))
    }

    /// Stores the client whose metadata document `document` is, fetched from `client_id` at
    /// `now`: a JSON object that names `client_id` as its own and lists redirect URIs, checked
    /// as a registration is. `None` for a document that is none of that, for a `client_id` that
    /// is no metadata URL ([`oauth_client_id_is_metadata_url`]), or for a new client past
    /// [`OAUTH_CLIENTS_MAX`].
    ///
    /// # Errors
    /// A store failure.
    pub fn store_oauth_metadata_client(
        &self,
        client_id: &str,
        document: &[u8],
        now: u64,
    ) -> Result<Option<OAuthClientRecord>> {
        if !oauth_client_id_is_metadata_url(client_id) {
            return Ok(None);
        }
        let Ok(metadata) = serde_json::from_slice::<MetadataDocument>(document) else {
            return Ok(None);
        };
        if metadata.client_id != client_id
            || check_client_metadata(
                &metadata.redirect_uris,
                metadata.client_name.as_deref(),
                metadata.token_endpoint_auth_method.as_deref(),
                metadata.grant_types.as_deref(),
                metadata.response_types.as_deref(),
            )
            .is_err()
        {
            return Ok(None);
        }
        let key = client_key(client_id);
        let document_hash = blake3::hash(document).to_hex().to_string();
        self.with_write_txn_grouped(|txn| {
            let known = CLIENTS
                .get(&self.store, txn, &key)?
                .filter(|record| record.client_id == client_id);
            if known.is_none() && !self.make_oauth_client_room_in_txn(txn, now)? {
                return Ok(None);
            }
            let record = OAuthClientRecord {
                client_id: client_id.to_owned(),
                client_name: metadata.client_name,
                redirect_uris: metadata.redirect_uris,
                source: OAuthClientSource::MetadataDocument {
                    document_hash,
                    fetched_at: now,
                },
                registered_at: known.map_or(now, |known| known.registered_at),
            };
            CLIENTS.put(&self.store, txn, &key, &record)?;
            Ok(Some(record))
        })
    }
}
