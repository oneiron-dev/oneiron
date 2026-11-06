//! Google's code exchange, called with values held inside admitted credential doors.

use std::io::Read as _;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use super::{GOOGLE_TOKEN_URL, MAX_CHECK_REPLY_BYTES, ProviderConnectionChecks, invalid};
use crate::Result;

/// A host's completed Google sign-in, borrowed only for its token exchange.
/// The host must validate its sign-in state before admitting the code.
pub struct GoogleAuthorizationCode<'a> {
    pub client_id: &'a str,
    pub client_secret: &'a str,
    pub code: &'a str,
    /// Exactly the redirect URI used to obtain this code, including loopback URIs.
    pub redirect_uri: &'a str,
    /// The verifier used by the host's sign-in, when it used PKCE.
    pub code_verifier: Option<&'a str>,
}

/// A Gmail grant ready for ordinary credential custody, never an API reply.
pub struct GoogleAuthorizationGrant {
    bytes: Zeroizing<Vec<u8>>,
    refreshable: bool,
}

impl GoogleAuthorizationGrant {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn has_refresh_token(&self) -> bool {
        self.refreshable
    }
}

impl ProviderConnectionChecks {
    /// Exchanges a confidential Google web client's code at the fixed token
    /// endpoint. Call only inside the credential doors that admitted its values.
    /// No credential is logged or persisted by this method.
    pub fn exchange_google_authorization_code(
        &self,
        code: GoogleAuthorizationCode<'_>,
    ) -> Result<GoogleAuthorizationGrant> {
        let mut form = vec![
            ("grant_type", "authorization_code"),
            ("client_id", code.client_id),
            ("client_secret", code.client_secret),
            ("code", code.code),
            ("redirect_uri", code.redirect_uri),
        ];
        if let Some(verifier) = code.code_verifier {
            form.push(("code_verifier", verifier));
        }
        let response = self
            .client
            .post(GOOGLE_TOKEN_URL)
            .form(&form)
            .send()
            .map_err(|_| invalid("Google's code exchange could not reach the provider"))?;
        let success = response.status().is_success();
        let mut body = Zeroizing::new(Vec::new());
        response
            .take(MAX_CHECK_REPLY_BYTES + 1)
            .read_to_end(&mut body)
            .map_err(|_| invalid("Google's code exchange reply is unreadable"))?;
        if body.len() as u64 > MAX_CHECK_REPLY_BYTES {
            return Err(invalid("Google's code exchange reply exceeds its bound"));
        }
        if !success {
            return Err(invalid("Google refused the authorization code"));
        }
        let reply: TokenReply = serde_json::from_slice(&body)
            .map_err(|_| invalid("Google's code exchange reply is not JSON"))?;
        let access_token = reply
            .access_token
            .as_deref()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| invalid("Google returned no access token"))?;
        let refresh_token = reply
            .refresh_token
            .as_deref()
            .filter(|value| !value.is_empty());
        let grant = StoredGrant {
            access_token,
            refresh_token,
            client_id: code.client_id,
            client_secret: code.client_secret,
        };
        let bytes = serde_json::to_vec(&grant)
            .map_err(|_| invalid("the Google grant could not be encoded"))?;
        Ok(GoogleAuthorizationGrant {
            bytes: Zeroizing::new(bytes),
            refreshable: refresh_token.is_some(),
        })
    }
}

#[derive(Deserialize)]
struct TokenReply {
    #[serde(default)]
    access_token: Option<String>,
    #[serde(default)]
    refresh_token: Option<String>,
}

impl Drop for TokenReply {
    fn drop(&mut self) {
        self.access_token.zeroize();
        self.refresh_token.zeroize();
    }
}

#[derive(Serialize)]
struct StoredGrant<'a> {
    access_token: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<&'a str>,
    client_id: &'a str,
    client_secret: &'a str,
}
