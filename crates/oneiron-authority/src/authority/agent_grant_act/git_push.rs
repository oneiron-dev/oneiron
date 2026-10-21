//! The owner's mint of a `git_push` Grant in his one signed Grant act (FIX
//! 6867, G1-PUSH): the same `AgentGrantAct` record, signer and fold as an
//! agent Grant, with two more keys on a GitPush mint only.
//!
//! A GitPush mint appends `grant_kind` (`"git_push"`) and `git_push_bounds`
//! (the repo set, in the codec the Grant body uses) after the seven mint
//! keys; an Access mint writes neither, so every earlier act keeps its
//! bytes. The two forms never mix: a GitPush mint carries no PR1
//! `repo_bounds`, its Scope lists exactly the `git_push` verb, and a revoke
//! carries neither key.

use rmpv::Value;

use crate::error::Result;
use crate::federation::git_push::{
    GIT_PUSH_VERB, GRANT_KIND_GIT_PUSH, decode_git_push_bounds_value, git_push_bounds_value,
};
use crate::federation::{FederationGrantKind, GitPushBounds, Scope, ScopeAxis};

use super::super::{OP_KEY_ACT, OP_KEY_KIND, invalid_authority};

/// The key naming a mint's Grant kind; absent on an Access mint.
pub(super) const KEY_GRANT_KIND: &str = "grant_kind";
/// The key carrying a GitPush mint's repo set.
const KEY_GIT_PUSH_BOUNDS: &str = "git_push_bounds";

/// The GitPush mint form: the seven mint keys, `grant_kind` and
/// `git_push_bounds`.
pub(super) const AGENT_GRANT_ACT_GIT_PUSH_KEYS: [&str; 9] = [
    OP_KEY_KIND,
    OP_KEY_ACT,
    "machine",
    "grant",
    "member",
    "scope",
    "expires_at",
    KEY_GRANT_KIND,
    KEY_GIT_PUSH_BOUNDS,
];

/// The entries a mint of `kind` appends after its seven keys: none for an
/// Access mint, the kind and the repo set for a GitPush mint.
pub(super) fn mint_entries(
    kind: FederationGrantKind,
    bounds: Option<&GitPushBounds>,
) -> Vec<(Value, Value)> {
    match (kind, bounds) {
        (FederationGrantKind::GitPush, Some(bounds)) => vec![
            (
                Value::from(KEY_GRANT_KIND),
                Value::from(GRANT_KIND_GIT_PUSH),
            ),
            (
                Value::from(KEY_GIT_PUSH_BOUNDS),
                git_push_bounds_value(bounds),
            ),
        ],
        _ => Vec::new(),
    }
}

/// Whether the act's entries carry the GitPush form.
pub(super) fn carried(entries: &[(Value, Value)]) -> bool {
    entries
        .iter()
        .any(|(key, _)| key.as_str() == Some(KEY_GRANT_KIND))
}

/// The kind and repo set a mint's entries name, fail-closed: no kind is
/// Access with no set; `git_push` needs its set whole; any other kind, or a
/// set without a kind, is no act.
pub(super) fn decode_mint_kind(
    entries: &[(Value, Value)],
) -> Result<(FederationGrantKind, Option<GitPushBounds>)> {
    let find = |name: &str| {
        entries
            .iter()
            .find_map(|(key, value)| (key.as_str() == Some(name)).then_some(value))
    };
    let kind = match find(KEY_GRANT_KIND) {
        None => None,
        Some(value) => Some(value.as_str().ok_or_else(invalid_authority)?),
    };
    let kind = FederationGrantKind::parse(kind).ok_or_else(invalid_authority)?;
    let bounds = find(KEY_GIT_PUSH_BOUNDS)
        .map(|value| decode_git_push_bounds_value(value).ok_or_else(invalid_authority))
        .transpose()?;
    if (kind == FederationGrantKind::GitPush) != bounds.is_some() {
        return Err(invalid_authority());
    }
    Ok((kind, bounds))
}

/// A mint's kind agrees with the rest of it: a GitPush mint names its repo
/// set, carries no PR1 repo bounds and lists exactly the `git_push` verb;
/// an Access mint names no repo set and never lists `git_push`.
pub(super) fn validate_mint(
    scope: &Scope,
    kind: FederationGrantKind,
    git_push_bounds: Option<&GitPushBounds>,
    has_repo_bounds: bool,
) -> Result<()> {
    let names_push =
        matches!(&scope.verbs, ScopeAxis::Some(verbs) if verbs.contains(GIT_PUSH_VERB));
    let only_push =
        names_push && matches!(&scope.verbs, ScopeAxis::Some(verbs) if verbs.len() == 1);
    let consistent = match (kind, git_push_bounds) {
        (FederationGrantKind::GitPush, Some(bounds)) => {
            only_push && !has_repo_bounds && bounds.validate().is_ok()
        }
        // The agent Grant mint never gains the push verb: only the owner's
        // git_push mint confers it.
        (FederationGrantKind::Access, None) => !names_push,
        _ => false,
    };
    if consistent {
        Ok(())
    } else {
        Err(invalid_authority())
    }
}
