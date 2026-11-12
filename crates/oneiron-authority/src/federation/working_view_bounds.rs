//! The owner working view an agent Grant edits (row 6 WORKING-VIEW-EDIT,
//! ruling CODECUSTODY-VIEW-BUILD Q1 = A), in the one codec the Grant body and
//! the owner's signed mint act both use.
//!
//! The bound narrows a Grant's repo bounds to one owner working view of that
//! repo in one account. The view edit door admits the Grant for that view's
//! files under the bounds' editable globs, the bound taking the place of the
//! ref; every other repo door refuses it. The key rides an owner's Access
//! agent Grant with repo bounds only, and only when he named a view; every
//! other body and act writes no key, so each earlier one keeps its bytes. Its
//! value is the map `{view, account}` in that order, two ids as lower hex.

use rmpv::Value;

use crate::entity_id::EntityId;

/// The key that carries a Grant's or a mint act's working view bound; absent
/// when it names none.
pub const KEY_WORKING_VIEW_BOUNDS: &str = "working_view_bounds";

/// The keys of a bound's value, in their canonical order.
const WORKING_VIEW_BOUNDS_KEYS: [&str; 2] = ["view", "account"];

/// The one owner working view a Grant edits: the view, and the account (the
/// owner's PERSON) whose view it is.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    serde::Serialize,
    serde::Deserialize,
    schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct WorkingViewEditBounds {
    /// The working view's id (32 hex), as `vault.code.views.materialize`
    /// answered it.
    #[schemars(with = "String")]
    pub view: EntityId,
    /// The account the view lives in (32 hex): the owner PERSON who made it.
    #[schemars(with = "String")]
    pub account: EntityId,
}

/// The canonical value of a bound: `{view, account}`.
#[must_use]
pub fn working_view_bounds_value(bounds: &WorkingViewEditBounds) -> Value {
    Value::Map(vec![
        (
            Value::from(WORKING_VIEW_BOUNDS_KEYS[0]),
            Value::from(bounds.view.to_hex()),
        ),
        (
            Value::from(WORKING_VIEW_BOUNDS_KEYS[1]),
            Value::from(bounds.account.to_hex()),
        ),
    ])
}

/// Decodes [`working_view_bounds_value`]'s form, fail-closed: exactly its two
/// keys in order, each a canonical lower-hex id, nothing else.
#[must_use]
pub fn decode_working_view_bounds_value(value: &Value) -> Option<WorkingViewEditBounds> {
    let Value::Map(entries) = value else {
        return None;
    };
    let [(view_key, view), (account_key, account)] = entries.as_slice() else {
        return None;
    };
    if view_key.as_str() != Some(WORKING_VIEW_BOUNDS_KEYS[0])
        || account_key.as_str() != Some(WORKING_VIEW_BOUNDS_KEYS[1])
    {
        return None;
    }
    let id = |value: &Value| {
        let hex = value.as_str()?;
        EntityId::from_hex(hex).ok().filter(|id| id.to_hex() == hex)
    };
    Some(WorkingViewEditBounds {
        view: id(view)?,
        account: id(account)?,
    })
}
