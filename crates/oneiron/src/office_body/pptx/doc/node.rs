//! One tree node's meta map: its model identity, kind, name, binding,
//! placeholder, preset, payload (a table's in root `tables`) and one key per
//! geometry field, each written only where it changed.

use super::{
    BINDING, EXTENT, FLIP_H, FLIP_V, ID, KIND, NAME, OFFSET, PAYLOAD, PLACEHOLDER, PRESET,
    ROTATION, identity, json, put, put_json, string, table,
};
use crate::error::Result;
use loro::LoroMap;
use oneiron_docedit::live::{DeckNode, GeometryProps, NodeId, NodeKind, NodePayload};

pub(super) fn sync_meta(meta: &LoroMap, id: NodeId, node: &DeckNode) -> Result<()> {
    put(meta, ID, id.0.to_string())?;
    put_json(meta, KIND, &node.kind)?;
    put_json(meta, NAME, &node.name)?;
    put_json(meta, BINDING, &node.binding)?;
    put_json(meta, PLACEHOLDER, &node.placeholder)?;
    put_json(meta, PRESET, &node.preset)?;
    match &node.payload {
        Some(NodePayload::Table(_)) => put(meta, PAYLOAD, table::MARK.to_owned())?,
        payload => put_json(meta, PAYLOAD, payload)?,
    }
    put_json(meta, OFFSET, &node.geometry.offset)?;
    put_json(meta, EXTENT, &node.geometry.extent)?;
    put_json(meta, ROTATION, &node.geometry.rotation)?;
    put_json(meta, FLIP_H, &node.geometry.flip_h)?;
    put_json(meta, FLIP_V, &node.geometry.flip_v)
}

pub(super) fn root() -> DeckNode {
    DeckNode {
        kind: NodeKind::Root,
        parent: None,
        children: Vec::new(),
        name: None,
        binding: None,
        geometry: GeometryProps::default(),
        placeholder: None,
        preset: None,
        payload: None,
    }
}

/// A tree node's model identity and node; a table frame's table is its
/// `tables` entry.
pub(super) fn node_of(
    meta: &LoroMap,
    parent: NodeId,
    tables: &LoroMap,
) -> Result<(NodeId, DeckNode)> {
    let id = identity(meta)?;
    let payload = match string(meta, PAYLOAD).as_deref() {
        Some(table::MARK) => Some(NodePayload::Table(table::read(tables, id)?)),
        _ => json(meta, PAYLOAD)?,
    };
    Ok((
        id,
        DeckNode {
            kind: json(meta, KIND)?,
            parent: Some(parent),
            children: Vec::new(),
            name: json(meta, NAME)?,
            binding: json(meta, BINDING)?,
            geometry: GeometryProps {
                offset: json(meta, OFFSET)?,
                extent: json(meta, EXTENT)?,
                rotation: json(meta, ROTATION)?,
                flip_h: json(meta, FLIP_H)?,
                flip_v: json(meta, FLIP_V)?,
            },
            placeholder: json(meta, PLACEHOLDER)?,
            preset: json(meta, PRESET)?,
            payload,
        },
    ))
}
