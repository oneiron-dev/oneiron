//! Raw native-map inputs, before source admission or native ordering.

use loro::{ContainerID, ContainerType, ID, JsonMapOp, JsonOpContent, VersionVector};

use super::super::EntityDoc;
use super::codec::SkillStateFact;
use super::prepare::{CURRENT, ROOT, read_fact};
use crate::error::{Error, Result};

/// These are observed operations, not admitted operations. A delete must also
/// reach source validation; a later insert cannot hide it from the validator.
pub(super) enum NativeMapWrite {
    Insert(SkillStateFact),
    Delete,
}

pub(super) struct NativeMapMutation {
    pub(super) id: ID,
    pub(super) change: ID,
    pub(super) dependencies: Vec<ID>,
    pub(super) write: NativeMapWrite,
}

pub(super) struct NativeMapFloor {
    pub(super) frontier: Vec<u8>,
    /// Explicit absence at this retained floor is distinct from no floor.
    pub(super) fact: Option<SkillStateFact>,
}

/// An ephemeral inventory, never stored as a second native operation ledger.
/// Decoded witnesses here have no source, carrier-standing or ACK authority.
pub(super) struct NativeMapInventory {
    pub(super) current: Option<SkillStateFact>,
    pub(super) floor: Option<NativeMapFloor>,
    pub(super) mutations: Vec<NativeMapMutation>,
}

fn malformed() -> Error {
    Error::CorruptedIndex("native SKILL state map operation")
}

/// Inspect every retained raw write, including values hidden by later LWW
/// writes. The shallow floor is read separately from its actual causal state.
/// Nothing in this function grants admission to any of these values.
pub(super) fn inspect(doc: &EntityDoc) -> Result<NativeMapInventory> {
    let current = read_fact(doc)?;
    let floor = if doc.doc.is_shallow() {
        let frontier = doc.doc.shallow_since_frontiers().encode();
        let at_floor = doc.fork(&frontier)?;
        Some(NativeMapFloor {
            frontier,
            fact: read_fact(&at_floor)?,
        })
    } else {
        None
    };
    let start = if floor.is_some() {
        doc.doc.shallow_since_vv().to_vv()
    } else {
        VersionVector::default()
    };
    // Native source coordinates must use actual peer ids, not the JSON peer
    // table's compressed indexes.
    let schema = doc
        .doc
        .export_json_updates_without_peer_compression(&start, &doc.doc.oplog_vv());
    let mut mutations = Vec::new();
    for change in schema.changes {
        for op in change.ops {
            let ContainerID::Root {
                name,
                container_type,
            } = &op.container
            else {
                continue;
            };
            if name.as_str() != ROOT {
                continue;
            }
            if *container_type != ContainerType::Map {
                return Err(malformed());
            }
            let write = match op.content {
                JsonOpContent::Map(JsonMapOp::Insert { key, value }) if key == CURRENT => {
                    let loro::LoroValue::Binary(bytes) = value else {
                        return Err(malformed());
                    };
                    NativeMapWrite::Insert(SkillStateFact::decode(bytes.as_slice())?)
                }
                JsonOpContent::Map(JsonMapOp::Delete { key }) if key == CURRENT => {
                    NativeMapWrite::Delete
                }
                _ => return Err(malformed()),
            };
            mutations.push(NativeMapMutation {
                id: ID {
                    peer: change.id.peer,
                    counter: op.counter,
                },
                change: change.id,
                dependencies: change.deps.clone(),
                write,
            });
        }
    }
    Ok(NativeMapInventory {
        current,
        floor,
        mutations,
    })
}
