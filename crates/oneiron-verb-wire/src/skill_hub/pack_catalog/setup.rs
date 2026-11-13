//! Moved from `crates/oneiron/src/skill_hub/pack_catalog/setup.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

pub const MAX_SETUP_TOKEN_BYTES: usize = 64;

pub const MAX_SETUP_REF_BYTES: usize = 256;

pub const MAX_SETUP_LABEL_BYTES: usize = 256;

pub const MAX_SETUP_TEXT_BYTES: usize = 1024;

pub const MAX_SETUP_LINK_BYTES: usize = 512;

/// An account the owner must hold with a provider. Display text and a
/// sign-up link only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PackSetupAccount {
    pub id: String,
    pub label: String,
    /// Where to make one: an `https://` link the owner opens. The engine
    /// never fetches it.
    #[serde(default)]
    pub sign_up: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
}

/// One connection the pack makes to a provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PackSetupConnection {
    pub id: String,
    pub label: String,
    /// The account (by id) this connection signs in to.
    #[serde(default)]
    pub account: Option<String>,
    pub auth: PackSetupAuth,
    /// The connector-key connector this connection governs, when the owner
    /// binds one; its qualification is the connection's real check.
    #[serde(default)]
    pub connector: Option<String>,
    /// Custody names the owner stores this connection's credentials under,
    /// through the owner secrets door. The first one is the credential the
    /// connection check presents.
    #[serde(default)]
    pub secrets: Vec<PackSetupSecret>,
    pub permissions: Vec<PackSetupPermission>,
    /// The host check that proves this connection: a name the host maps to
    /// its own read-only provider call, never a URL.
    pub verify: String,
}

/// How a connection signs in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PackSetupAuth {
    Oauth,
    ApiKey,
    BotToken,
    AppPassword,
    Session,
    Webhook,
    /// Nothing to sign in to: the host checks a guest it runs itself.
    Local,
}

impl PackSetupAuth {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Oauth => "oauth",
            Self::ApiKey => "api_key",
            Self::BotToken => "bot_token",
            Self::AppPassword => "app_password",
            Self::Session => "session",
            Self::Webhook => "webhook",
            Self::Local => "local",
        }
    }

    /// The sign-in method in plain words.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Oauth => "Sign in with the provider (OAuth)",
            Self::ApiKey => "An API key you create",
            Self::BotToken => "A bot token from an app you install",
            Self::AppPassword => "An app password you create",
            Self::Session => "A signed-in browser session",
            Self::Webhook => "A webhook signing value",
            Self::Local => "Nothing to sign in to; it runs on this host",
        }
    }
}

/// One credential's custody name. Never its value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PackSetupSecret {
    /// The custody name the owner registers it under.
    pub name: String,
    pub label: String,
    /// The effector its custody binding must cover with read, the same one
    /// the pack's use path presents.
    pub effector: String,
    /// Where the owner finds it, in plain words.
    #[serde(default)]
    pub hint: Option<String>,
    /// The connection is ready without it: it serves only an optional
    /// permission, and is stored when the owner allows that.
    #[serde(default)]
    pub optional: bool,
}

impl PackSetupConnection {
    /// Whether every credential the connection needs is stored, by the
    /// connection's state read in declared order; an optional one may be
    /// absent.
    #[must_use]
    pub fn required_secrets_stored(&self, stored: &[super::PackSetupSecretState]) -> bool {
        self.secrets.iter().all(|declared| {
            declared.optional
                || stored
                    .iter()
                    .any(|state| state.name == declared.name && state.stored)
        })
    }
}

/// One permission a connection asks for, shown to the owner like an app
/// install shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PackSetupPermission {
    pub id: String,
    /// The provider's own name for it (an OAuth scope), compared with what
    /// the provider reports at the connection check.
    #[serde(default)]
    pub scope: Option<String>,
    /// The PACK.md grant this permission serves.
    #[serde(default)]
    pub grant: Option<String>,
    /// What it lets the pack do, in plain words.
    pub what: String,
    /// What could go wrong, in plain words.
    pub risk: String,
    pub level: PackSetupRisk,
    /// The connection still works when the owner declines it.
    #[serde(default)]
    pub optional: bool,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum PackSetupRisk {
    Low,
    Medium,
    High,
}

impl PackSetupRisk {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
}

impl PackSetupConnection {
    /// The permissions the connection cannot work without.
    pub fn required(&self) -> impl Iterator<Item = &PackSetupPermission> {
        self.permissions
            .iter()
            .filter(|permission| !permission.optional)
    }

    #[must_use]
    pub fn permission(&self, id: &str) -> Option<&PackSetupPermission> {
        self.permissions
            .iter()
            .find(|permission| permission.id == id)
    }
}

/// A lowercase name: ASCII lowercase, digits, `.`, `_` and `-`.
pub fn token(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
        })
}

/// Printable ASCII without blanks, as provider scopes and custody names are.
pub fn graphic(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && value.bytes().all(|b| b.is_ascii_graphic())
}

/// Display text: not blank, bounded, no control characters.
pub fn text(value: &str, max: usize) -> bool {
    !value.trim().is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}

pub fn https_link(value: &str) -> bool {
    value
        .strip_prefix("https://")
        .is_some_and(|rest| !rest.is_empty())
        && graphic(value, MAX_SETUP_LINK_BYTES)
}
