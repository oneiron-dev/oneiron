//! The REST shapes of the row-less `/v1/owner/connectors` routes for a staged
//! slate (FIX 11677) and the GOV-10 charter (FIX 11680): one
//! [`super::bind`] per route, called from [`super::merge_owner_rest_shapes`].

use serde_json::Value;

use super::{bind, bind_answer};
use crate::api::owner_routes::connector_admission_routes::schema::{
    accept_request_body_schema, admitted_slate_schema, approve_charter_body_schema,
    charter_view_schema, discard_charter_body_schema, propose_charter_body_schema,
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
    bind_answer(
        spec,
        "/v1/owner/connectors/charter",
        "get",
        charter_view_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/connectors/charter/propose",
        "post",
        propose_charter_body_schema(),
        charter_view_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/connectors/charter/approve",
        "post",
        approve_charter_body_schema(),
        charter_view_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/connectors/charter/discard",
        "post",
        discard_charter_body_schema(),
        charter_view_schema(),
        &[],
    );
}
