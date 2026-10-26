//! LC cloud #97's wire, as fixed at cloud 519cfa1e0 (RFC 8628 device grant,
//! refresh rotation, RFC 7009 revoke, the registration status resource):
//! its constants, its exact reply shapes, and the token set the client keeps
//! in custody. Every reply that carries a token or a code is wiped when it
//! drops. Nothing here names a deployment value: those are the pins'.

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

/// The fixed public client (§8): routing only, never owner proof.
pub(crate) const CLIENT_ID: &str = "oneiron-native-v1";
/// The one scope (§8).
pub(crate) const SCOPE: &str = "cp:registration:read";
/// The device grant (§3).
pub(crate) const DEVICE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";
/// The refresh grant (§4).
pub(crate) const REFRESH_GRANT: &str = "refresh_token";
/// The audience is the issuer plus this path (§1).
pub(crate) const REGISTRATION_PATH: &str = "/oauth/registration";
/// The locator document under the issuer (§1).
pub(crate) const AUTH_MD_PATH: &str = "/auth.md";
/// The protected-resource metadata of the audience, under the issuer (§1).
pub(crate) const RESOURCE_METADATA_PATH: &str =
    "/.well-known/oauth-protected-resource/oauth/registration";
/// An access token lives exactly this long (§6).
pub(crate) const ACCESS_LIFETIME_SECS: u64 = 300;
/// The local clock skew allowed on `iat` (§6, CALLS G7_LOCAL_CLOCK).
pub(crate) const CLOCK_SKEW_SECS: u64 = 60;
/// What each `slow_down` adds to a device flow's interval, for good (§3).
pub(crate) const SLOW_DOWN_SECS: u64 = 5;

/// `POST /oauth/device_authorization`'s 200, exactly (§2).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DeviceAuthorization {
    pub(crate) device_code: String,
    pub(crate) user_code: String,
    pub(crate) verification_uri: String,
    pub(crate) expires_in: u64,
    pub(crate) interval: u64,
}

impl Drop for DeviceAuthorization {
    fn drop(&mut self) {
        self.device_code.zeroize();
    }
}

/// `POST /oauth/token`'s 200, exactly, for both grants (§3, §4).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TokenReply {
    pub(crate) access_token: String,
    pub(crate) token_type: String,
    pub(crate) expires_in: u64,
    pub(crate) refresh_token: String,
    pub(crate) scope: String,
}

impl Drop for TokenReply {
    fn drop(&mut self) {
        self.access_token.zeroize();
        self.refresh_token.zeroize();
    }
}

impl TokenReply {
    /// Whether the reply is the wire's five-field shape: a bearer access
    /// token of the fixed lifetime and scope, and a new refresh token.
    pub(crate) fn on_wire(&self) -> bool {
        self.token_type == "Bearer"
            && self.expires_in == ACCESS_LIFETIME_SECS
            && self.scope == SCOPE
            && !self.access_token.is_empty()
            && self.refresh_token.starts_with("ort_")
    }
}

/// An OAuth error reply (§2): its code, and the optional description the
/// owner is shown verbatim and nothing parses.
#[derive(Deserialize)]
pub(crate) struct ErrorReply {
    pub(crate) error: String,
    #[serde(default)]
    pub(crate) error_description: Option<String>,
}

/// `GET A`'s 200, exactly (§7).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RegistrationStatus {
    pub(crate) iss: String,
    pub(crate) sub: String,
    pub(crate) aud: String,
    pub(crate) scope: String,
    pub(crate) expires_at: u64,
}

/// What a slot holds: the current refresh token and access token, and when
/// the access token stops (§10). Its own JSON, in custody alone.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TokenSet {
    pub(crate) refresh_token: String,
    pub(crate) access_token: String,
    pub(crate) access_expires_at: u64,
}

impl Drop for TokenSet {
    fn drop(&mut self) {
        self.refresh_token.zeroize();
        self.access_token.zeroize();
    }
}

impl TokenSet {
    /// The set a verified token reply makes, its access token stopping at
    /// `expires_at`.
    pub(crate) fn of(reply: &TokenReply, expires_at: u64) -> Self {
        Self {
            refresh_token: reply.refresh_token.clone(),
            access_token: reply.access_token.clone(),
            access_expires_at: expires_at,
        }
    }

    /// The bytes a slot stores, in one buffer sized up front so no partial
    /// copy is left behind, wiped on drop.
    pub(crate) fn encode(&self) -> Result<Zeroizing<Vec<u8>>, Failure> {
        let room = self.refresh_token.len() + self.access_token.len() + 128;
        let mut bytes = Zeroizing::new(Vec::with_capacity(room));
        serde_json::to_writer(&mut *bytes, self)
            .map_err(|_| Failure::OffWire("the token set did not encode".to_owned()))?;
        Ok(bytes)
    }

    /// The set slot bytes `bytes` hold; `None` for any other bytes.
    pub(crate) fn decode(bytes: &[u8]) -> Option<Self> {
        serde_json::from_slice(bytes).ok()
    }
}

/// Why an act did not reach a verified answer.
#[derive(Debug)]
pub(crate) enum Failure {
    /// The pins are absent or invalid: this feature alone is off.
    NotConfigured(String),
    /// Any 503 (§9): cloud registration unavailable, with the issuer's
    /// optional description, verbatim.
    Unavailable(Option<String>),
    /// The issuer answered this OAuth error code.
    Refused(String),
    /// An answer off the fixed wire, or one the pins do not verify.
    OffWire(String),
    /// No answer, or one cut short: whether the issuer acted is unknown.
    Lost,
    /// The engine refused or failed.
    Engine(oneiron::Error),
}

impl Failure {
    /// The owner's words for it: never a token, a code or a parsed
    /// description.
    pub(crate) fn reason(&self) -> String {
        match self {
            Self::NotConfigured(reason) | Self::OffWire(reason) => reason.clone(),
            Self::Unavailable(_) => "cloud registration unavailable".to_owned(),
            Self::Refused(code) => format!("the issuer answered {code}"),
            Self::Lost => "no answer came back; whether the issuer acted is unknown".to_owned(),
            Self::Engine(error) => format!("the vault refused: {error}"),
        }
    }
}

impl From<oneiron::Error> for Failure {
    fn from(error: oneiron::Error) -> Self {
        Self::Engine(error)
    }
}
