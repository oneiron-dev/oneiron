//! The `git_push` Grant capability (FIX 6867, owner ruling G1-PUSH = D, as
//! the owner refined it 10-21): raw git push into a vault's `/git` endpoint
//! is its own kind of Grant, separate from a vault write grant, on explicitly
//! named repos.
//!
//! A FEDERATION_GRANT row is one of two kinds ([`FederationGrantKind`]):
//! `Access`, every grant before this one (a role and a six-axis Scope), and
//! `GitPush`, which confers one thing only: pushing to the repos its
//! [`GitPushBounds`] name. A GitPush grant carries no membership, read,
//! write, admin or agent standing and parents no delegation; an Access
//! grant, top scope included, never implies push. The Grant check is the
//! whole policy: the owner mints it to whichever person or agent he names,
//! and an admission reads only the Grant, never the holder's class.
//!
//! The bounds grammar (CALLS "FIX 6867 git_push bounds"): a nonempty set of
//! explicit repos, each a CODE anchor (the CODE_ARTIFACT whose stored
//! repo_ref is the repo) and the PROJECT it belongs to, granted whole. There
//! is no wildcard, no all-repos value and no ref or path narrowing; the
//! Grant's own optional expiry is the only time bound (none: until revoked).
//! Which served repository an anchor is, the engine resolves from the stored
//! records and the served Git store's identity, never from a URL, a path or
//! a commit string a caller names.

use std::collections::BTreeSet;

use rmpv::Value;
use serde::{Deserialize, Serialize};

use crate::EntityId;

/// The one verb a GitPush Grant's Scope lists, and the capability a refused
/// push names as missing.
pub const GIT_PUSH_VERB: &str = "git_push";

/// The wire and body spelling of [`FederationGrantKind::GitPush`]. An
/// `Access` grant writes no kind at all, so every earlier body and act keeps
/// its bytes.
pub const GRANT_KIND_GIT_PUSH: &str = "git_push";

/// What one FEDERATION_GRANT confers.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum FederationGrantKind {
    /// A role and a six-axis Scope: every grant before G1-PUSH.
    #[default]
    Access,
    /// Raw git push to the named repos, and nothing else.
    GitPush,
}

impl FederationGrantKind {
    /// The kind a body or act names: absent is `Access`, `git_push` is
    /// `GitPush`, anything else is no kind.
    #[must_use]
    pub fn parse(value: Option<&str>) -> Option<Self> {
        match value {
            None => Some(Self::Access),
            Some(GRANT_KIND_GIT_PUSH) => Some(Self::GitPush),
            Some(_) => None,
        }
    }
}

/// One repo a GitPush Grant names: the CODE anchor and its PROJECT.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct GitPushRepo {
    /// The CODE anchor (32 hex): a live CODE_ARTIFACT whose stored repo_ref
    /// is the served repository.
    #[schemars(with = "String")]
    pub repo: EntityId,
    /// The live PROJECT (32 hex) the anchor belongs to.
    #[schemars(with = "String")]
    pub project: EntityId,
}

/// The repos one GitPush Grant names, each whole.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GitPushBounds {
    /// The explicit repos; at least one, no wildcard.
    pub repos: BTreeSet<GitPushRepo>,
}

/// The bounds name no repo.
const NO_REPOS: &str = "a git_push grant names at least one explicit repo";

impl GitPushBounds {
    /// Checks the grammar: at least one explicit repo. The store checks (a
    /// live anchor in a live PROJECT, a served store) are the engine's.
    ///
    /// # Errors
    /// The reason text of the rule the bounds break.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.repos.is_empty() {
            return Err(NO_REPOS);
        }
        Ok(())
    }

    /// The PROJECTs the bounds name: a GitPush Grant's audience.
    #[must_use]
    pub fn projects(&self) -> BTreeSet<EntityId> {
        self.repos.iter().map(|repo| repo.project).collect()
    }
}

/// The canonical MessagePack key order of one repo in [`git_push_bounds_value`].
const GIT_PUSH_REPO_KEYS: [&str; 2] = ["repo", "project"];

/// The one MessagePack form of [`GitPushBounds`], on the FEDERATION_GRANT
/// body and in the owner's signed mint act alike: an array of two-key maps
/// in [`GIT_PUSH_REPO_KEYS`] order, ascending, ids as lower hex.
#[must_use]
pub fn git_push_bounds_value(bounds: &GitPushBounds) -> Value {
    Value::Array(
        bounds
            .repos
            .iter()
            .map(|repo| {
                Value::Map(vec![
                    (
                        Value::from(GIT_PUSH_REPO_KEYS[0]),
                        Value::from(repo.repo.to_hex()),
                    ),
                    (
                        Value::from(GIT_PUSH_REPO_KEYS[1]),
                        Value::from(repo.project.to_hex()),
                    ),
                ])
            })
            .collect(),
    )
}

/// Decodes [`git_push_bounds_value`]'s form, fail-closed: exactly its keys in
/// order, canonical lower-hex ids, strictly ascending repos, and bounds that
/// pass [`GitPushBounds::validate`]. `None` for anything else; each codec
/// maps that to its own refusal.
#[must_use]
pub fn decode_git_push_bounds_value(value: &Value) -> Option<GitPushBounds> {
    let Value::Array(items) = value else {
        return None;
    };
    let id = |value: &Value| {
        let hex = value.as_str()?;
        EntityId::from_hex(hex).ok().filter(|id| id.to_hex() == hex)
    };
    let mut repos = BTreeSet::new();
    let mut last: Option<GitPushRepo> = None;
    for item in items {
        let Value::Map(entries) = item else {
            return None;
        };
        if entries.len() != GIT_PUSH_REPO_KEYS.len()
            || entries
                .iter()
                .zip(GIT_PUSH_REPO_KEYS)
                .any(|((key, _), expected)| key.as_str() != Some(expected))
        {
            return None;
        }
        let repo = GitPushRepo {
            repo: id(&entries[0].1)?,
            project: id(&entries[1].1)?,
        };
        if last.is_some_and(|prior| prior >= repo) {
            return None;
        }
        last = Some(repo);
        repos.insert(repo);
    }
    let bounds = GitPushBounds { repos };
    bounds.validate().ok()?;
    Some(bounds)
}
