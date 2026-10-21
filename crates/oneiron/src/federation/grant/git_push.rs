//! The `grant_kind` and `git_push_bounds` keys of the FEDERATION_GRANT body
//! (FIX 6867, G1-PUSH): a GitPush grant's kind and repo set, in the one
//! codec its signed mint act uses too
//! (`oneiron_authority::federation::git_push`). An Access grant writes
//! neither key, so every earlier body encodes exactly as before.
//!
//! A GitPush body has one shape: the Delegate envelope with the owner as its
//! delegator, no owner-agent mark, no PR1 repo bounds and no guest payload,
//! a vault scope, and the exact Scope [`git_push_scope`] builds from its
//! repo set (the `git_push` verb, its PROJECTs as audience, every other axis
//! bottom), so no reader of the six axes can find standing in it.

use std::collections::BTreeSet;

use oneiron_authority::federation::git_push::{
    GRANT_KIND_GIT_PUSH, decode_git_push_bounds_value, git_push_bounds_value,
};
use rmpv::Value;

use super::{
    FEDERATION_GRANT_BODY_KEYS, FederationGrant, FederationGrantPreset, FederationGrantRole,
    FederationGrantScope,
};
use crate::error::Result;
use crate::federation::codec::{invalid_grant, optional_value};
use crate::federation::{
    FederationGrantKind, GIT_PUSH_VERB, GitPushBounds, Scope, ScopeAxis, ScopeId,
};

const KEY_GRANT_KIND: &str = FEDERATION_GRANT_BODY_KEYS[11];

const KEY_GIT_PUSH_BOUNDS: &str = FEDERATION_GRANT_BODY_KEYS[12];

impl FederationGrant {
    /// Whether this is a git_push grant, which confers no standing but
    /// raw git push to its repos (G1-PUSH). Every other grant kind stands
    /// as it did.
    #[must_use]
    pub fn is_git_push(&self) -> bool {
        self.kind == FederationGrantKind::GitPush
    }
}

/// The exact Scope a GitPush grant over `bounds` stores: the `git_push` verb
/// and the bounds' PROJECTs as its audience, every other axis bottom.
#[must_use]
pub(crate) fn git_push_scope(bounds: &GitPushBounds) -> Scope {
    Scope {
        audience: bounds.projects().into_iter().map(ScopeId).collect(),
        verbs: ScopeAxis::Some(BTreeSet::from([GIT_PUSH_VERB.to_owned()])),
        ..Scope::default()
    }
}

/// The body entries of `grant`'s kind: none for an Access grant.
pub(super) fn body_entries(grant: &FederationGrant) -> Vec<(Value, Value)> {
    match (grant.kind, &grant.git_push_bounds) {
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

/// The kind and repo set a body carries; a malformed value refuses the body.
pub(super) fn decode_body_entries(
    entries: &[(Value, Value)],
) -> Result<(FederationGrantKind, Option<GitPushBounds>)> {
    let kind = optional_value(entries, KEY_GRANT_KIND)
        .map(|value| value.as_str().ok_or_else(invalid_grant))
        .transpose()?;
    let kind = FederationGrantKind::parse(kind).ok_or_else(invalid_grant)?;
    let bounds = optional_value(entries, KEY_GIT_PUSH_BOUNDS)
        .map(|value| decode_git_push_bounds_value(value).ok_or_else(invalid_grant))
        .transpose()?;
    Ok((kind, bounds))
}

/// A GitPush grant has its one shape, and an Access grant names no repo set
/// and never lists the `git_push` verb.
pub(super) fn validate(grant: &FederationGrant) -> Result<()> {
    let names_push = matches!(&grant.authority_scope.verbs,
        ScopeAxis::Some(verbs) if verbs.contains(GIT_PUSH_VERB));
    let valid = match (grant.kind, &grant.git_push_bounds) {
        (FederationGrantKind::Access, None) => !names_push,
        (FederationGrantKind::GitPush, Some(bounds)) => {
            bounds.validate().is_ok()
                && grant.role == FederationGrantRole::Delegate
                && grant.preset == FederationGrantPreset::Delegate
                && grant.delegated_by.is_some()
                && !grant.owner_agent
                && grant.repo_bounds.is_none()
                && grant.guest.is_none()
                && matches!(grant.scope, FederationGrantScope::Vault { .. })
                && grant.authority_scope == git_push_scope(bounds)
        }
        _ => false,
    };
    if valid { Ok(()) } else { Err(invalid_grant()) }
}
