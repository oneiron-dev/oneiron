//! The CRDT map key of an edge in a window document. `sync::bridge`
//! re-exports [`format_edge_key`] at its old path.

use crate::edge::EdgeKind;
use crate::entity_id::EntityId;

/// Formats an edge key for CRDT map: `{src_hex}:{kind:02}:{tgt_hex}`.
pub fn format_edge_key(src: &EntityId, kind: EdgeKind, tgt: &EntityId) -> String {
    format!("{}:{:02}:{}", src.to_hex(), kind as u8, tgt.to_hex())
}
