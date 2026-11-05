//! Core half of `store::checkpoint_payload::loro::proof`: its store-layer items live in `oneiron_store::checkpoint_payload::loro::proof` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::checkpoint_payload::loro::proof::*;

use super::super::corrupt;
use crate::error::Result;
use ::loro::{
    ID, JsonChange, JsonListOp, JsonMapOp, JsonMovableListOp, JsonOp, JsonOpContent, JsonTextOp,
    JsonTreeOp,
};

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
