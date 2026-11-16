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

#[doc(hidden)]
use oneiron_verb_wire::skill_hub::pack_catalog::setup::{
    MAX_SETUP_LABEL_BYTES, MAX_SETUP_REF_BYTES, MAX_SETUP_TEXT_BYTES, MAX_SETUP_TOKEN_BYTES,
    graphic, https_link, text, token,
};
#[doc(hidden)]
pub use oneiron_verb_wire::skill_hub::pack_catalog::setup::{
    PackSetupAccount, PackSetupAuth, PackSetupConnection, PackSetupPermission, PackSetupRisk,
    PackSetupSecret,
};

/// What a pack needs before it can work, as its PACK.md declares it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
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
        self.connections
            .iter()
            .find(|connection| connection.id == id)
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
        let mut accounts = BTreeSet::new();
        for account in &self.accounts {
            if !token(&account.id, MAX_SETUP_TOKEN_BYTES)
                || !accounts.insert(account.id.as_str())
                || !text(&account.label, MAX_SETUP_LABEL_BYTES)
                || account
                    .note
                    .as_deref()
                    .is_some_and(|note| !text(note, MAX_SETUP_TEXT_BYTES))
                || account
                    .sign_up
                    .as_deref()
                    .is_some_and(|link| !https_link(link))
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
            if connection.permissions.is_empty() {
                return Err(invalid("a setup connection asks for no permission"));
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
