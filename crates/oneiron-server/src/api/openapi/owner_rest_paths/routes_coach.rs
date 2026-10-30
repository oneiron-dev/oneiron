//! The REST shape of `PUT /v1/owner/coach/training-checkpoints` (FIX 12086):
//! a raw byte body, not JSON, with the manifest that names its files in one
//! request header. Called from [`super::merge_owner_rest_shapes`].

use serde_json::{Value, json};

use crate::api::owner_routes::proactivity_routes::schema::{
    CHECKPOINT_HEADER, checkpoint_manifest_schema, pinned_checkpoint_schema,
};

const PATH: &str = "/v1/owner/coach/training-checkpoints";

/// Binds the route's answer and refusals, then its byte body and manifest
/// header in place of the JSON body [`super::bind`] writes.
pub(super) fn merge(spec: &mut Value) {
    super::bind_answer(
        spec,
        PATH,
        "put",
        pinned_checkpoint_schema(),
        &[
            (
                "400",
                "The manifest header is missing or malformed, a file name or source is refused, the body ended before its files or ran past them, or a file's BLAKE3 differs from the manifest's: nothing was kept.",
            ),
            (
                "409",
                "The vault's disk has no room for the body past the free-space reserve uploads keep (`disk_capacity`): nothing was kept.",
            ),
        ],
    );
    let Some(operation) = spec
        .get_mut("paths")
        .and_then(|paths| paths.get_mut(PATH))
        .and_then(|item| item.get_mut("put"))
    else {
        return;
    };
    operation["requestBody"] = json!({
        "required": true,
        "description": "The checkpoint's files as raw bytes, back to back, in the manifest's order.",
        "content": {"application/octet-stream": {"schema": {"type": "string", "format": "binary"}}}
    });
    operation["parameters"] = json!([{
        "name": CHECKPOINT_HEADER,
        "in": "header",
        "required": true,
        "description": "The checkpoint's manifest as JSON: its model, and each file's name, kind, source, BLAKE3 (64 hex) and length in body order.",
        "content": {"application/json": {"schema": checkpoint_manifest_schema()}}
    }]);
}
