//! Wiping owners for what a mask plan copies (FIX 1101). A plan runs on a
//! copy of the batch's ops, or of a row's parts, with a stand-in for each
//! secret, and keeps each value it found keyed by its bytes; the copy, the
//! values, the trees a body decodes to and every allocation a masked copy
//! replaces hold the secret too. Each is wiped where it ends: when its owner
//! drops, on every path (a refusal, a mint that fails, a plan that places
//! nothing), and before a masked copy takes an old allocation's place. No
//! `BatchOp` wipes itself: only the plan's own copies do, and what the
//! caller handed in is left as it was until the mask writes its handles.

use std::collections::HashMap;
use std::ops::{Deref, DerefMut};

use rmpv::Value;
use zeroize::Zeroize;

use super::side_row::SidePart;
use crate::batch::BatchOp;

/// `new` in `old`'s place, the old allocation wiped first.
pub(super) fn replace_wiped<T: Zeroize>(old: &mut T, new: T) {
    old.zeroize();
    *old = new;
}

/// Every byte of a value tree that can hold a secret: each string, byte
/// string and extension payload, and each map key, at any depth.
pub(crate) fn wipe_value(value: &mut Value) {
    match value {
        Value::String(text) => {
            let mut bytes = std::mem::replace(text, "".into()).into_bytes();
            bytes.zeroize();
        }
        Value::Binary(bytes) | Value::Ext(_, bytes) => bytes.zeroize(),
        Value::Array(items) => items.iter_mut().for_each(wipe_value),
        Value::Map(fields) => {
            for (key, member) in fields.iter_mut() {
                wipe_value(key);
                wipe_value(member);
            }
        }
        _ => {}
    }
}

/// Every byte of one batch op that can hold a secret: a put's body, a text
/// op's field values, a claim candidate's free values.
fn wipe_op(op: &mut BatchOp) {
    match op {
        BatchOp::Put { data, .. } => data.zeroize(),
        BatchOp::Text { fields, .. } => {
            for (_, value) in fields.iter_mut() {
                value.zeroize();
            }
        }
        BatchOp::ClaimCandidate { candidate, .. } => candidate.values_mut().for_each(wipe_value),
        _ => {}
    }
}

/// Every byte of one row part that can hold a secret.
pub(super) fn wipe_part(part: &mut SidePart) {
    match part {
        SidePart::Body(bytes) => bytes.zeroize(),
        SidePart::Text(text) => text.zeroize(),
        SidePart::Value(value) => wipe_value(value),
    }
}

/// A plan's copy of a batch's ops, wiped when it drops: the copy a mask
/// plans on before custody is minted, and the copy the door reads where the
/// owner ruled a value no secret.
pub(super) struct PlanOps(Vec<BatchOp>);

impl PlanOps {
    pub(super) fn of(ops: &[BatchOp]) -> Self {
        Self(ops.to_vec())
    }
}

impl Deref for PlanOps {
    type Target = [BatchOp];

    fn deref(&self) -> &[BatchOp] {
        &self.0
    }
}

impl DerefMut for PlanOps {
    fn deref_mut(&mut self) -> &mut [BatchOp] {
        &mut self.0
    }
}

impl Drop for PlanOps {
    fn drop(&mut self) {
        self.0.iter_mut().for_each(wipe_op);
    }
}

/// A plan's copy of a row's parts, wiped when it drops.
pub(super) struct PlanParts(Vec<SidePart>);

impl PlanParts {
    pub(super) fn of(parts: &[SidePart]) -> Self {
        Self(parts.to_vec())
    }
}

impl Deref for PlanParts {
    type Target = [SidePart];

    fn deref(&self) -> &[SidePart] {
        &self.0
    }
}

impl DerefMut for PlanParts {
    fn deref_mut(&mut self) -> &mut [SidePart] {
        &mut self.0
    }
}

impl Drop for PlanParts {
    fn drop(&mut self) {
        self.0.iter_mut().for_each(wipe_part);
    }
}

/// A value tree a body decoded to, wiped when it drops.
pub(super) struct PlanTree(pub(super) Value);

impl Drop for PlanTree {
    fn drop(&mut self) {
        wipe_value(&mut self.0);
    }
}

/// What a pass keeps by a secret's own bytes (the plan's handles, the
/// records it minted, what a writer lifted so far), each key wiped when it
/// drops. A key moves between owners, never copied out to a plain map.
pub(crate) struct PlanValues<T>(HashMap<Vec<u8>, T>);

impl<T> Default for PlanValues<T> {
    fn default() -> Self {
        Self(HashMap::new())
    }
}

impl<T: Clone> Clone for PlanValues<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T> PlanValues<T> {
    pub(super) fn get(&self, value: &[u8]) -> Option<&T> {
        self.0.get(value)
    }

    /// Keeps `item` for `value`. A value already held keeps its key, and
    /// the copy given is wiped.
    pub(super) fn insert(&mut self, mut value: Vec<u8>, item: T) {
        match self.0.get_mut(value.as_slice()) {
            Some(held) => {
                *held = item;
                value.zeroize();
            }
            None => {
                self.0.insert(value, item);
            }
        }
    }

    /// Every entry of `other`, moved in.
    pub(super) fn adopt(&mut self, mut other: Self) {
        for (value, item) in other.0.drain() {
            self.insert(value, item);
        }
    }

    /// The same keys, each with `item`'s part `pick` keeps; the keys move.
    pub(super) fn map<U>(mut self, pick: impl Fn(T) -> U) -> PlanValues<U> {
        let mut out = PlanValues(HashMap::with_capacity(self.0.len()));
        for (value, item) in self.0.drain() {
            out.0.insert(value, pick(item));
        }
        out
    }
}

impl<T> Drop for PlanValues<T> {
    fn drop(&mut self) {
        for (mut value, _) in self.0.drain() {
            value.zeroize();
        }
    }
}
