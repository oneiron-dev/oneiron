//! The REST shapes of the row-less `/v1/owner` routes under `/packs` (FIX 11611 part D):
//! one [`super::bind`] per route, called from [`super::merge_owner_rest_shapes`].

use serde_json::Value;

/// Binds each route's REST shapes.
pub(super) fn merge(spec: &mut Value) {
    let _ = spec;
}
