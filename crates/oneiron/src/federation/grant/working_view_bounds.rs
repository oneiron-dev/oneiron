//! The `working_view_bounds` key of the FEDERATION_GRANT body (row 6
//! WORKING-VIEW-EDIT, ruling CODECUSTODY-VIEW-BUILD Q1 = A): the one owner
//! working view, and its account, an owner's agent grant edits, in the one
//! codec his signed mint act uses too
//! (`oneiron_authority::federation::working_view_bounds`). Only an owner's
//! Access agent grant with repo bounds carries the key, and only when he
//! bound it to a view; every other body encodes exactly as before and
//! decodes as naming none. The bound narrows the repo bounds: the view edit
//! door admits the grant for that view alone, and every other repo door
//! refuses it.

use oneiron_authority::federation::{
    WorkingViewEditBounds, decode_working_view_bounds_value, working_view_bounds_value,
};
use rmpv::Value;

use super::FederationGrant;
use crate::error::Result;
use crate::federation::FederationGrantKind;
use crate::federation::codec::{invalid_grant, optional_value};

pub(super) const KEY_WORKING_VIEW_BOUNDS: &str =
    oneiron_authority::federation::KEY_WORKING_VIEW_BOUNDS;

/// The body entry of `grant`'s working view bound, when it names one.
pub(super) fn body_entry(grant: &FederationGrant) -> Option<(Value, Value)> {
    grant.working_view_bounds.as_ref().map(|bounds| {
        (
            Value::from(KEY_WORKING_VIEW_BOUNDS),
            working_view_bounds_value(bounds),
        )
    })
}

/// The working view bound a body names; none when the key is absent. A
/// malformed value refuses the body.
pub(super) fn decode_body_entry(
    entries: &[(Value, Value)],
) -> Result<Option<WorkingViewEditBounds>> {
    optional_value(entries, KEY_WORKING_VIEW_BOUNDS)
        .map(|value| decode_working_view_bounds_value(value).ok_or_else(invalid_grant))
        .transpose()
}

/// A working view bound rides an owner's Access agent grant with repo
/// bounds only: it narrows them, and is nothing without them.
pub(super) fn validate(grant: &FederationGrant) -> Result<()> {
    if grant.working_view_bounds.is_some()
        && (!grant.owner_agent
            || grant.kind != FederationGrantKind::Access
            || grant.repo_bounds.is_none())
    {
        return Err(invalid_grant());
    }
    Ok(())
}
