//! The REST shapes of the owner's review of Connect guests' proposals
//! (FIX 3684): one bind per route, called from
//! [`super::merge_owner_rest_shapes`].

use serde_json::Value;

use crate::api::owner_routes::federation_connect_routes::{
    connect_proposal_ref_body_schema, connect_proposal_schema, connect_proposals_schema,
};

/// Binds each route's REST shapes.
pub(super) fn merge(spec: &mut Value) {
    super::bind_answer(
        spec,
        "/v1/owner/federation/connect/proposals",
        "get",
        connect_proposals_schema(),
        &[],
    );
    super::bind(
        spec,
        "/v1/owner/federation/connect/proposals/accept",
        "post",
        connect_proposal_ref_body_schema(),
        connect_proposal_schema(),
        &[],
    );
    super::bind(
        spec,
        "/v1/owner/federation/connect/proposals/reject",
        "post",
        connect_proposal_ref_body_schema(),
        connect_proposal_schema(),
        &[],
    );
}
