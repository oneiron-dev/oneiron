//! The REST shapes of the row-less `/v1/owner` routes from `/backups` through
//! `/owner-signing-keys` that parts A to C left unbound (FIX 11613, 11617):
//! one [`super::bind`] per route, called from [`super::merge_owner_rest_shapes`].

use serde_json::Value;

/// Binds each route's REST shapes.
pub(super) fn merge(spec: &mut Value) {
    let _ = spec;
}
