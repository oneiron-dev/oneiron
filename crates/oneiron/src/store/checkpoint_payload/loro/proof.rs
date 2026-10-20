//! The typed equality of two Loro histories a join's proof compares
//! (FIX 6072, Engine R1): change by change and operation by operation, never
//! as rendered text or as JSON that would read a byte string as a list.

use ::loro::{
    ID, JsonChange, JsonListOp, JsonMapOp, JsonMovableListOp, JsonOp, JsonOpContent, JsonTextOp,
    JsonTreeOp,
};

use super::super::corrupt;
use crate::error::Result;

/// Proves two typed histories the same: the same changes by id, each with
/// the same timestamp, dependencies, Lamport value and message (`None` is
/// not the empty message), and the same operations, each with its counter,
/// container and complete typed payload. Only the order changes are listed
/// in, and the order of a change's dependencies, may differ; two changes
/// with one id refuse. An operation kind with no typed equality here (a
/// counter, a future kind) is never the same.
pub(crate) fn prove_loro_equivalent(expected: &[JsonChange], actual: &[JsonChange]) -> Result<()> {
    let expected = by_id(expected)?;
    let actual = by_id(actual)?;
    let mut pairs = expected.iter().zip(&actual);
    if expected.len() == actual.len() && pairs.all(|(a, b)| same_change(a, b)) {
        Ok(())
    } else {
        Err(corrupt())
    }
}

fn by_id(changes: &[JsonChange]) -> Result<Vec<&JsonChange>> {
    let mut sorted: Vec<&JsonChange> = changes.iter().collect();
    sorted.sort_by_key(|change| (change.id.peer, change.id.counter));
    let mut pairs = sorted.windows(2);
    if pairs.any(|pair| matches!(pair, [first, second] if first.id == second.id)) {
        return Err(corrupt());
    }
    Ok(sorted)
}

fn sorted_ids(ids: &[ID]) -> Vec<(u64, i32)> {
    let mut sorted: Vec<(u64, i32)> = ids.iter().map(|id| (id.peer, id.counter)).collect();
    sorted.sort_unstable();
    sorted
}

fn same_change(a: &JsonChange, b: &JsonChange) -> bool {
    a.id == b.id
        && a.timestamp == b.timestamp
        && a.lamport == b.lamport
        && a.msg == b.msg
        && sorted_ids(&a.deps) == sorted_ids(&b.deps)
        && a.ops.len() == b.ops.len()
        && a.ops.iter().zip(&b.ops).all(|(a, b)| same_op(a, b))
}

fn same_op(a: &JsonOp, b: &JsonOp) -> bool {
    a.counter == b.counter && a.container == b.container && same_content(&a.content, &b.content)
}

fn same_content(a: &JsonOpContent, b: &JsonOpContent) -> bool {
    match (a, b) {
        (JsonOpContent::List(a), JsonOpContent::List(b)) => same_list(a, b),
        (JsonOpContent::MovableList(a), JsonOpContent::MovableList(b)) => same_movable(a, b),
        (JsonOpContent::Map(a), JsonOpContent::Map(b)) => same_map(a, b),
        (JsonOpContent::Text(a), JsonOpContent::Text(b)) => same_text(a, b),
        (JsonOpContent::Tree(a), JsonOpContent::Tree(b)) => same_tree(a, b),
        _ => false,
    }
}

fn same_list(a: &JsonListOp, b: &JsonListOp) -> bool {
    match (a, b) {
        (
            JsonListOp::Insert { pos, value },
            JsonListOp::Insert {
                pos: other_pos,
                value: other_value,
            },
        ) => pos == other_pos && value == other_value,
        (
            JsonListOp::Delete { pos, len, start_id },
            JsonListOp::Delete {
                pos: other_pos,
                len: other_len,
                start_id: other_start,
            },
        ) => pos == other_pos && len == other_len && start_id == other_start,
        _ => false,
    }
}

fn same_movable(a: &JsonMovableListOp, b: &JsonMovableListOp) -> bool {
    match (a, b) {
        (
            JsonMovableListOp::Insert { pos, value },
            JsonMovableListOp::Insert {
                pos: other_pos,
                value: other_value,
            },
        ) => pos == other_pos && value == other_value,
        (
            JsonMovableListOp::Delete { pos, len, start_id },
            JsonMovableListOp::Delete {
                pos: other_pos,
                len: other_len,
                start_id: other_start,
            },
        ) => pos == other_pos && len == other_len && start_id == other_start,
        (
            JsonMovableListOp::Move { from, to, elem_id },
            JsonMovableListOp::Move {
                from: other_from,
                to: other_to,
                elem_id: other_elem,
            },
        ) => from == other_from && to == other_to && elem_id == other_elem,
        (
            JsonMovableListOp::Set { elem_id, value },
            JsonMovableListOp::Set {
                elem_id: other_elem,
                value: other_value,
            },
        ) => elem_id == other_elem && value == other_value,
        _ => false,
    }
}

fn same_map(a: &JsonMapOp, b: &JsonMapOp) -> bool {
    match (a, b) {
        (
            JsonMapOp::Insert { key, value },
            JsonMapOp::Insert {
                key: other_key,
                value: other_value,
            },
        ) => key == other_key && value == other_value,
        (JsonMapOp::Delete { key }, JsonMapOp::Delete { key: other_key }) => key == other_key,
        _ => false,
    }
}

fn same_text(a: &JsonTextOp, b: &JsonTextOp) -> bool {
    match (a, b) {
        (
            JsonTextOp::Insert { pos, text },
            JsonTextOp::Insert {
                pos: other_pos,
                text: other_text,
            },
        ) => pos == other_pos && text == other_text,
        (
            JsonTextOp::Delete { pos, len, start_id },
            JsonTextOp::Delete {
                pos: other_pos,
                len: other_len,
                start_id: other_start,
            },
        ) => pos == other_pos && len == other_len && start_id == other_start,
        (
            JsonTextOp::Mark {
                start,
                end,
                style_key,
                style_value,
                info,
            },
            JsonTextOp::Mark {
                start: other_start,
                end: other_end,
                style_key: other_key,
                style_value: other_value,
                info: other_info,
            },
        ) => {
            start == other_start
                && end == other_end
                && style_key == other_key
                && style_value == other_value
                && info == other_info
        }
        (JsonTextOp::MarkEnd, JsonTextOp::MarkEnd) => true,
        _ => false,
    }
}

fn same_tree(a: &JsonTreeOp, b: &JsonTreeOp) -> bool {
    match (a, b) {
        (
            JsonTreeOp::Create {
                target,
                parent,
                fractional_index,
            },
            JsonTreeOp::Create {
                target: other_target,
                parent: other_parent,
                fractional_index: other_index,
            },
        )
        | (
            JsonTreeOp::Move {
                target,
                parent,
                fractional_index,
            },
            JsonTreeOp::Move {
                target: other_target,
                parent: other_parent,
                fractional_index: other_index,
            },
        ) => target == other_target && parent == other_parent && fractional_index == other_index,
        (
            JsonTreeOp::Delete { target },
            JsonTreeOp::Delete {
                target: other_target,
            },
        ) => target == other_target,
        _ => false,
    }
}
