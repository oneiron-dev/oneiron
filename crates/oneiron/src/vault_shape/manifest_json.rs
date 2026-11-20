//! A policy manifest's JSON form (FIX 2760): the same MessagePack body as a
//! document a seed author can write by hand. A map whose keys are all text
//! reads as an object in its own key order, an array as an array, and text,
//! booleans, nil, integers and 64-bit floats as themselves. The form is
//! offered only where it is lossless: written back, it encodes to exactly
//! the stored bytes. A body holding binary, an extension, a 32-bit float, a
//! non-text or repeated map key, or a number encoded wider than its value
//! needs has no JSON form, and its hex stays the only one.
use super::seed::hex;
use super::{ShapeRow, ShapeSeed};
use crate::serialize::{json_to_msgpack_value, msgpack_value_to_exact_json};
use oneiron_contracts::msgpack;
use serde_json::Value as Json;

/// The JSON form of the manifest `body`, when writing it back gives exactly
/// `body`; else none. The write-back is what refuses a 32-bit float: its JSON
/// number writes back as a 64-bit float.
pub(super) fn manifest_json(body: &[u8]) -> Option<Json> {
    let value = msgpack::decode(body).ok()?;
    let json = msgpack_value_to_exact_json(&value)?;
    (manifest_from_json(&json) == body).then_some(json)
}

/// The MessagePack bytes a manifest's JSON form writes.
pub(super) fn manifest_from_json(json: &Json) -> Vec<u8> {
    msgpack::encode(&json_to_msgpack_value(json))
}

impl ShapeSeed {
    /// This seed, each manifest row that states its body by its JSON form
    /// alone given the hex that form writes. A row stating its hex keeps
    /// it: the hex is the authority.
    pub(super) fn with_manifest_bodies(mut self) -> Self {
        for row in &mut self.rows {
            if let ShapeRow::Manifest {
                body,
                json: Some(json),
                ..
            } = row
                && body.is_empty()
            {
                *body = hex(&manifest_from_json(json));
            }
        }
        self
    }
}
