//! The typed `setup` key of PACK.md (OF-378): the accounts a pack needs, the
//! connections it makes and how each signs in, every permission a connection
//! asks for in plain words with its risk, and the custody NAMES its
//! credentials go under. Declaration only: it grants nothing, it carries no
//! credential value (the source scans refuse one), and it never activates a
//! pack. The guided session that walks an owner through it lives in
//! `setup_session`; grants and checks live in `connector_key::setup`.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::{PackKind, invalid};
use crate::error::Result;
use crate::skill_hub::HubFile;

/// Most accounts one pack may ask the owner to hold.
pub const MAX_SETUP_ACCOUNTS: usize = 16;
/// Most connections one pack may declare.
pub const MAX_SETUP_CONNECTIONS: usize = 16;
/// Most permissions one connection may ask for.
pub const MAX_SETUP_PERMISSIONS: usize = 32;
/// Most credentials one connection may name.
pub const MAX_SETUP_SECRETS: usize = 8;
const MAX_SETUP_TOKEN_BYTES: usize = 64;
const MAX_SETUP_REF_BYTES: usize = 256;
const MAX_SETUP_LABEL_BYTES: usize = 256;
const MAX_SETUP_TEXT_BYTES: usize = 1024;
const MAX_SETUP_LINK_BYTES: usize = 512;

/// What a pack needs before it can work, as its PACK.md declares it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackSetup {
    /// The bundled skill folder, `skills/<skill>/SKILL.md`, that walks the
    /// owner through this setup. It is read from the exact source, so the
    /// instructions are there while the pack is still a Candidate.
    pub skill: String,
    #[serde(default)]
    pub accounts: Vec<PackSetupAccount>,
    #[serde(default)]
    pub connections: Vec<PackSetupConnection>,
}

/// An account the owner must hold with a provider. Display text and a
/// sign-up link only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackSetupAuth {
    Oauth,
    ApiKey,
    BotToken,
    AppPassword,
    Session,
    Webhook,
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
        }
    }
}

/// One credential's custody name. Never its value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
}

/// One permission a connection asks for, shown to the owner like an app
/// install shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
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

impl PackSetup {
    /// Parses and validates the one-line JSON `setup` value of a PACK.md.
    pub(super) fn parse(value: &str, kind: PackKind, grants: &BTreeSet<String>) -> Result<Self> {
        let setup: Self = serde_json::from_str(value)
            .map_err(|_| invalid("setup must be a typed JSON object"))?;
        setup.validate(kind, grants)?;
        Ok(setup)
    }

    #[must_use]
    pub fn connection(&self, id: &str) -> Option<&PackSetupConnection> {
        self.connections.iter().find(|connection| connection.id == id)
    }

    /// Every connection one of whose permissions serves `grant`.
    pub fn connections_for_grant<'a>(
        &'a self,
        grant: &'a str,
    ) -> impl Iterator<Item = &'a PackSetupConnection> + 'a {
        self.connections.iter().filter(move |connection| {
            connection
                .permissions
                .iter()
                .any(|permission| permission.grant.as_deref() == Some(grant))
        })
    }

    /// The setup skill's instruction file in the exact source.
    #[must_use]
    pub fn skill_path(&self) -> String {
        format!("skills/{}/SKILL.md", self.skill)
    }

    fn validate(&self, kind: PackKind, grants: &BTreeSet<String>) -> Result<()> {
        if kind == PackKind::Agent {
            return Err(invalid("agent pack cannot declare runtime powers"));
        }
        if !token(&self.skill, MAX_SETUP_TOKEN_BYTES) {
            return Err(invalid("setup skill must name a bundled skill folder"));
        }
        if self.accounts.is_empty() && self.connections.is_empty() {
            return Err(invalid("setup declares no account and no connection"));
        }
        if self.accounts.len() > MAX_SETUP_ACCOUNTS || self.connections.len() > MAX_SETUP_CONNECTIONS
        {
            return Err(invalid("setup declares too many accounts or connections"));
        }
        let mut accounts = BTreeSet::new();
        for account in &self.accounts {
            if !token(&account.id, MAX_SETUP_TOKEN_BYTES)
                || !accounts.insert(account.id.as_str())
                || !text(&account.label, MAX_SETUP_LABEL_BYTES)
                || account
                    .note
                    .as_deref()
                    .is_some_and(|note| !text(note, MAX_SETUP_TEXT_BYTES))
                || account.sign_up.as_deref().is_some_and(|link| !https_link(link))
            {
                return Err(invalid("invalid or duplicate setup account"));
            }
        }
        let mut connections = BTreeSet::new();
        let mut secrets = BTreeSet::new();
        for connection in &self.connections {
            if !token(&connection.id, MAX_SETUP_TOKEN_BYTES)
                || !connections.insert(connection.id.as_str())
                || !text(&connection.label, MAX_SETUP_LABEL_BYTES)
                || !token(&connection.verify, MAX_SETUP_REF_BYTES)
                || connection
                    .account
                    .as_deref()
                    .is_some_and(|account| !accounts.contains(account))
                || connection
                    .connector
                    .as_deref()
                    .is_some_and(|connector| !token(connector, MAX_SETUP_REF_BYTES))
            {
                return Err(invalid("invalid or duplicate setup connection"));
            }
            if connection.secrets.len() > MAX_SETUP_SECRETS {
                return Err(invalid("setup connection names too many credentials"));
            }
            for secret in &connection.secrets {
                if !graphic(&secret.name, crate::secret_custody::SECRET_NAME_MAX_BYTES)
                    || !secrets.insert(secret.name.as_str())
                    || !text(&secret.label, MAX_SETUP_LABEL_BYTES)
                    || !graphic(&secret.effector, MAX_SETUP_REF_BYTES)
                    || secret
                        .hint
                        .as_deref()
                        .is_some_and(|hint| !text(hint, MAX_SETUP_TEXT_BYTES))
                {
                    return Err(invalid("invalid or duplicate setup credential name"));
                }
            }
            if connection.permissions.is_empty()
                || connection.permissions.len() > MAX_SETUP_PERMISSIONS
            {
                return Err(invalid(
                    "a setup connection asks for no permission or too many",
                ));
            }
            let mut permissions = BTreeSet::new();
            let mut scopes = BTreeSet::new();
            for permission in &connection.permissions {
                if !token(&permission.id, MAX_SETUP_TOKEN_BYTES)
                    || !permissions.insert(permission.id.as_str())
                    || !text(&permission.what, MAX_SETUP_TEXT_BYTES)
                    || !text(&permission.risk, MAX_SETUP_TEXT_BYTES)
                    || permission.scope.as_deref().is_some_and(|scope| {
                        !graphic(scope, MAX_SETUP_REF_BYTES) || !scopes.insert(scope)
                    })
                {
                    return Err(invalid("invalid or duplicate setup permission"));
                }
                if permission
                    .grant
                    .as_deref()
                    .is_some_and(|grant| !grants.contains(grant))
                {
                    return Err(invalid(
                        "a setup permission serves a grant the pack does not request",
                    ));
                }
            }
        }
        Ok(())
    }

    /// The setup skill must ship in the same exact source.
    pub(super) fn validate_files(&self, files: &[HubFile]) -> Result<()> {
        let path = self.skill_path();
        if !files.iter().any(|file| file.path == path) {
            return Err(invalid("setup skill is absent from the pack source"));
        }
        Ok(())
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
        self.permissions.iter().find(|permission| permission.id == id)
    }
}

/// A lowercase name: ASCII lowercase, digits, `.`, `_` and `-`.
fn token(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
        })
}

/// Printable ASCII without blanks, as provider scopes and custody names are.
fn graphic(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && value.bytes().all(|b| b.is_ascii_graphic())
}

/// Display text: not blank, bounded, no control characters.
fn text(value: &str, max: usize) -> bool {
    !value.trim().is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}

fn https_link(value: &str) -> bool {
    value
        .strip_prefix("https://")
        .is_some_and(|rest| !rest.is_empty())
        && graphic(value, MAX_SETUP_LINK_BYTES)
}
