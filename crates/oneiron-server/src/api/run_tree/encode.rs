//! The run tree's JSON (FIX 11107): the flat table [`super::projection`]
//! projects, written through its derived encoding. A table nests no node in
//! another, so no tree of any depth deepens the call stack, and no depth or
//! count limits it.

use axum::http::header;
use axum::response::{IntoResponse, Response};

use super::CoreRunTreeInterventionResponse;
use super::projection::core_run_tree;

/// A JSON body already written, served as `application/json`.
pub(super) fn raw_json(body: String) -> Response {
    ([(header::CONTENT_TYPE, "application/json")], body).into_response()
}

/// The core run-tree response for `tree`: `{"nodes":[...],"roots":[...],"repairs":[...]}`.
pub(super) fn run_tree_json(tree: oneiron::RunTree) -> serde_json::Result<String> {
    serde_json::to_string(&core_run_tree(tree))
}

/// An intervention response with `tree`, its fresh snapshot, when it has
/// one, in its `tree` field.
pub(super) fn intervention_json(
    mut response: CoreRunTreeInterventionResponse,
    tree: Option<oneiron::RunTree>,
) -> serde_json::Result<String> {
    response.tree = tree.map(core_run_tree);
    serde_json::to_string(&response)
}
