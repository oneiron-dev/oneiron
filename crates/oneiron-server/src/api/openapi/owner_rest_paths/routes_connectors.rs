//! The REST shapes of the row-less `/v1/owner/connectors` routes for a staged
//! slate (FIX 11677): one [`super::bind`] per route, called from
//! [`super::merge_owner_rest_shapes`].

use serde_json::Value;

use super::bind;
use crate::api::owner_routes::connector_admission_routes::schema::{
    accept_request_body_schema, admitted_slate_schema,
};

/// Binds each route's REST shapes.
pub(super) fn merge(spec: &mut Value) {
    bind(
        spec,
        "/v1/owner/connectors/slate/staged/accept",
        "post",
        accept_request_body_schema(),
        admitted_slate_schema(),
        &[],
    );
}
