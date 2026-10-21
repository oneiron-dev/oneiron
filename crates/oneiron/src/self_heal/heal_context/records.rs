//! How a heal's context renders what it read (OF-418 L2, L10): the source order of a
//! walk's links, a code run's replay record, and a stored body, each whole.

use std::collections::{BTreeMap, BTreeSet};

use base64::Engine as _;
use serde_json::{Value, json};

use crate::code_run::{CodeRunOutputKind, CodeRunReplayRecord};
use crate::entity_id::bytes_to_hex_lower;

/// `nodes` in source order: each before the nodes its `links` name, ties by id, and
/// then, by id, those on a link cycle or reached only through one, which it also returns.
pub(super) fn source_order<T: Ord + Copy>(
    nodes: &[T],
    links: &[(T, T, &'static str)],
) -> (Vec<T>, Vec<T>) {
    let mut incoming: BTreeMap<T, usize> = nodes.iter().map(|node| (*node, 0)).collect();
    let mut out: BTreeMap<T, Vec<T>> = BTreeMap::new();
    for (from, to, _) in links {
        if incoming.contains_key(from)
            && let Some(count) = incoming.get_mut(to)
        {
            *count += 1;
            out.entry(*from).or_default().push(*to);
        }
    }
    let mut ready: BTreeSet<T> = incoming
        .iter()
        .filter(|(_, count)| **count == 0)
        .map(|(node, _)| *node)
        .collect();
    let mut order = Vec::with_capacity(nodes.len());
    while let Some(node) = ready.pop_first() {
        order.push(node);
        for to in out.get(&node).into_iter().flatten() {
            if let Some(count) = incoming.get_mut(to) {
                *count -= 1;
                if *count == 0 {
                    ready.insert(*to);
                }
            }
        }
    }
    let cyclic: Vec<T> = incoming
        .into_iter()
        .filter(|(_, count)| *count > 0)
        .map(|(node, _)| node)
        .collect();
    order.extend(&cyclic);
    (order, cyclic)
}

/// A code run's replay record as data (OF-418 L10): its bridge calls whole, its step
/// checkpoints, its outputs' manifests with their recorded previews, and its result
/// names. The live run's credential binding stays out; output bodies are read only
/// through the owner's result doors.
pub(super) fn code_run_value(record: &CodeRunReplayRecord) -> Value {
    let calls: Vec<Value> = record
        .bridge_calls
        .iter()
        .map(|call| {
            json!({
                "seq": call.seq,
                "effect": call.effect.as_str(),
                "request": msgpack_value(&call.request),
                "outcome": msgpack_value(&call.outcome),
                "started_at_ms": call.started_at_ms,
                "finished_at_ms": call.finished_at_ms,
                "action_digest": call.action_digest,
            })
        })
        .collect();
    let checkpoints: Vec<Value> = record
        .step_checkpoints
        .iter()
        .map(|checkpoint| {
            json!({
                "seq": checkpoint.seq,
                "label": checkpoint.label,
                "state_hash": bytes_to_hex_lower(&checkpoint.state_hash),
                "created_at_ms": checkpoint.created_at_ms,
            })
        })
        .collect();
    let outputs: Vec<Value> = record
        .outputs
        .iter()
        .map(|output| {
            json!({
                "handle": output.handle,
                "path": output.path,
                "blake3": bytes_to_hex_lower(&output.raw_blake3),
                "bytes": output.raw_len,
                "kind": match output.kind {
                    CodeRunOutputKind::Text => "text",
                    CodeRunOutputKind::Binary => "binary",
                },
                "lines": output.lines,
                "complete": output.complete,
                "preview": {
                    "codec": output.preview.codec,
                    "text": output.preview.text,
                    "truncated": output.preview.truncated,
                },
            })
        })
        .collect();
    let bindings: Vec<Value> = record
        .bindings
        .iter()
        .map(|binding| json!({ "name": binding.name, "handle": binding.handle }))
        .collect();
    json!({
        "run": record.run_id.to_hex(),
        "frozen_unix_ms": record.determinism.frozen_unix_ms,
        "bridge_calls": calls,
        "step_checkpoints": checkpoints,
        "outputs": outputs,
        "bindings": bindings,
    })
}

/// A stored body as data: its whole MessagePack as JSON, else its bytes as base64.
pub(super) fn body_value(body: &[u8]) -> Value {
    let mut cursor = std::io::Cursor::new(body);
    match rmpv::decode::read_value(&mut cursor) {
        Ok(value) if cursor.position() == body.len() as u64 => msgpack_value(&value),
        _ => json!({ "base64": base64::engine::general_purpose::STANDARD.encode(body) }),
    }
}

/// A MessagePack value as JSON or, where JSON cannot hold it (a map keyed by other
/// than strings), its encoded bytes as base64.
fn msgpack_value(value: &rmpv::Value) -> Value {
    serde_json::to_value(value).unwrap_or_else(|_| {
        let mut bytes = Vec::new();
        let _ = rmpv::encode::write_value(&mut bytes, value);
        json!({ "base64": base64::engine::general_purpose::STANDARD.encode(bytes) })
    })
}
