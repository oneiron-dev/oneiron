//! The `repo_bounds` key of the FEDERATION_GRANT body (FIX 6867): the repo
//! bounds an owner gave his agent, in the one codec its signed mint act uses
//! too (`oneiron_authority::federation::repo_scope`). Only an owner's agent
//! grant carries the key, and only when he gave bounds; every other body,
//! and an agent grant without bounds, encodes exactly as before.

use oneiron_authority::federation::repo_scope::{decode_repo_bounds_value, repo_bounds_value};
use rmpv::Value;

use super::{FEDERATION_GRANT_BODY_KEYS, FederationGrant};
use crate::error::Result;
use crate::federation::RepoAccessBounds;
use crate::federation::codec::{invalid_grant, optional_value};

const KEY_REPO_BOUNDS: &str = FEDERATION_GRANT_BODY_KEYS[10];

/// The body entry of `grant`'s repo bounds, when it carries any.
pub(super) fn body_entry(grant: &FederationGrant) -> Option<(Value, Value)> {
    grant
        .repo_bounds
        .as_ref()
        .map(|bounds| (Value::from(KEY_REPO_BOUNDS), repo_bounds_value(bounds)))
}

/// The repo bounds a body carries; a malformed value refuses the body.
pub(super) fn decode_body_entry(entries: &[(Value, Value)]) -> Result<Option<RepoAccessBounds>> {
    optional_value(entries, KEY_REPO_BOUNDS)
        .map(|value| decode_repo_bounds_value(value).ok_or_else(invalid_grant))
        .transpose()
}

/// Repo bounds ride an owner's agent grant only, and only in their grammar.
pub(super) fn validate(grant: &FederationGrant) -> Result<()> {
    match &grant.repo_bounds {
        Some(bounds) if !grant.owner_agent || bounds.validate().is_err() => Err(invalid_grant()),
        _ => Ok(()),
    }
}
