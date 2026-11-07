//! The state reading of a shallow or state-only Loro snapshot (FIX 6442).
//! Such a snapshot holds no history before its cut: the values written
//! there stand only in its state at the cut. A shallow export at the same
//! cut writes that state and every kept change's message as they stand, a
//! scrub commit only adds a change, and the vendored root-map join rebuilds
//! no text container, so no no-one form of a document that names an actor
//! can be written. One that names no one is its own no-one form. This reads
//! every place a family's actor could stand, through the family's own
//! codec: each change kept after the cut as a history split reads it, and
//! the state at the head and at the cut, each root map's values as the codec
//! reads a map insertion and each root text as the insertion and marks that
//! would write it.

use super::{LoroActorCodec, SHALLOW, STATE_NOT_HEAD, Slice, history, import_blob, split_history};
use crate::store::checkpoint_payload::rows::Unresolved;
use ::loro::{
    ContainerID, ContainerType, JsonOp, JsonOpContent, JsonTextOp, LoroDoc, LoroMap, LoroText,
    LoroValue, TextDelta, ValueOrContainer,
};

/// Refuses the shallow or state-only snapshot `bytes` unless it names no
/// one through `codec`: every change it keeps after its cut, its state at
/// its head, and its state at its cut, which holds the values written
/// before the cut that no kept change shows. A snapshot whose state is not
/// its head refuses as `STATE_NOT_HEAD`; one that names an actor, holds a
/// nested container or a root of another kind holding anything, as
/// `SHALLOW`; a carrier the codec does not read, by the codec's reason.
pub(crate) fn shallow_names_no_one<C: LoroActorCodec>(
    bytes: &[u8],
    codec: &C,
) -> std::result::Result<(), Unresolved> {
    let doc = LoroDoc::new();
    import_blob(&doc, bytes).map_err(|_| Unresolved::Undecodable)?;
    if !doc.is_shallow() {
        return Err(Unresolved::Undecodable);
    }
    if doc.state_frontiers() != doc.oplog_frontiers() {
        return Err(Unresolved::ActorSplit(STATE_NOT_HEAD));
    }
    let kept = history(&doc, &Slice::ShallowSnapshot);
    let (_, atoms) = split_history(&kept, codec).map_err(Unresolved::ActorSplit)?;
    if !atoms.is_empty() {
        return Err(Unresolved::ActorSplit(SHALLOW));
    }
    state_names_no_one(&doc, codec)?;
    let cut = doc.shallow_since_frontiers();
    doc.checkout(&cut).map_err(|_| Unresolved::Undecodable)?;
    state_names_no_one(&doc, codec)
}

/// Refuses the state `doc` stands at unless it names no one through
/// `codec`. A document's value shows one root per name, so each name is
/// read as every kind a root of it may be: its map's values, its text, and
/// its list, movable list and tree, which must hold nothing. A counter
/// holds only a number.
fn state_names_no_one<C: LoroActorCodec>(
    doc: &LoroDoc,
    codec: &C,
) -> std::result::Result<(), Unresolved> {
    let LoroValue::Map(roots) = doc.get_value() else {
        return Err(Unresolved::Undecodable);
    };
    for name in roots.keys() {
        let name = name.as_str();
        let map_id = root(name, ContainerType::Map);
        map_names_no_one(&map_id, &doc.get_map(&map_id), codec)?;
        let text_id = root(name, ContainerType::Text);
        for op in text_ops(&text_id, &doc.get_text(&text_id)) {
            codec.keep_op(&op).map_err(Unresolved::ActorSplit)?;
        }
        let empty = doc.get_list(name).is_empty()
            && doc.get_movable_list(name).is_empty()
            && doc.get_tree(name).is_empty();
        if !empty {
            return Err(Unresolved::ActorSplit(SHALLOW));
        }
    }
    Ok(())
}

/// The root container `name` of kind `kind`.
fn root(name: &str, kind: ContainerType) -> ContainerID {
    ContainerID::Root {
        name: name.into(),
        container_type: kind,
    }
}

/// Refuses the values of the map `map` (container `id`) unless each reads
/// through `codec` as a map insertion that names no one.
fn map_names_no_one<C: LoroActorCodec>(
    id: &ContainerID,
    map: &LoroMap,
    codec: &C,
) -> std::result::Result<(), Unresolved> {
    let mut entries = Vec::new();
    map.for_each(|key, value| {
        entries.push((key.to_owned(), value));
    });
    for (key, value) in entries {
        let ValueOrContainer::Value(value) = value else {
            return Err(Unresolved::ActorSplit(SHALLOW));
        };
        let split = codec.split_map_insert(id, &key, &value);
        if !split.map_err(Unresolved::ActorSplit)?.actors.is_empty() {
            return Err(Unresolved::ActorSplit(SHALLOW));
        }
    }
    Ok(())
}

/// The operations that would write what the text `text` (container `id`)
/// holds: one insertion of its whole string, then one mark for each style
/// each of its runs carries. An empty text has none.
fn text_ops(id: &ContainerID, text: &LoroText) -> Vec<JsonOp> {
    if text.is_empty() {
        return Vec::new();
    }
    let op = |content: JsonTextOp| JsonOp {
        content: JsonOpContent::Text(content),
        container: id.clone(),
        counter: 0,
    };
    let mut ops = vec![op(JsonTextOp::Insert {
        pos: 0,
        text: text.to_string(),
    })];
    let mut start: u32 = 0;
    for run in text.to_delta() {
        let TextDelta::Insert { insert, attributes } = run else {
            continue;
        };
        let len = u32::try_from(insert.chars().count()).unwrap_or(u32::MAX);
        let end = start.saturating_add(len);
        for (style_key, style_value) in attributes.into_iter().flatten() {
            ops.push(op(JsonTextOp::Mark {
                start,
                end,
                style_key,
                style_value,
                info: 0,
            }));
        }
        start = end;
    }
    ops
}
