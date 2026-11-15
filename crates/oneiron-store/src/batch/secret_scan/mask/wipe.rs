//! Wiping owners for what a mask plan copies (FIX 1101). A plan runs on a
//! copy of the batch's ops, or of a row's parts, with a stand-in for each
//! secret, and keeps each value it found keyed by its bytes and its held
//! form; the copy, the values, the trees a body decodes to and every
//! allocation a masked copy replaces hold the secret too. Each is wiped
//! where it ends: when its owner drops, on every path (a refusal, a mint
//! that fails, a plan that places nothing), and before a masked copy takes
//! an old allocation's place. No `BatchOp` wipes itself: only the plan's own
//! copies do, and what the caller handed in is left as it was until the
//! mask writes its handles.

use std::collections::HashMap;
use std::ops::{Deref, DerefMut};

use rmpv::Value;
use zeroize::Zeroize;

use crate::batch::builder::ops::BatchOp;
use crate::file_secret_marks::HeldForm;

/// `new` in `old`'s place, the old allocation wiped first.
pub fn replace_wiped<T: Zeroize>(old: &mut T, new: T) {
    old.zeroize();
    *old = new;
}

/// Every byte of a value tree that can hold a secret: each string, byte
/// string and extension payload, and each map key, at any depth.
pub fn wipe_value(value: &mut Value) {
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

/// A plan's copy of a batch's ops, wiped when it drops: the copy a mask
/// plans on before custody is minted, and the copy the door reads where the
/// owner ruled a value no secret.
pub struct PlanOps(pub Vec<BatchOp>);

impl PlanOps {
    pub fn of(ops: &[BatchOp]) -> Self {
        Self(ops.to_vec())
    }

    pub fn from_owned(ops: Vec<BatchOp>) -> Self {
        Self(ops)
    }

    pub fn into_ops(mut self) -> Vec<BatchOp> {
        std::mem::take(&mut self.0)
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

/// A value tree a body decoded to, wiped when it drops.
pub struct PlanTree(pub Value);

impl Drop for PlanTree {
    fn drop(&mut self) {
        wipe_value(&mut self.0);
    }
}

/// What a pass keeps by a secret's own bytes and the form custody holds them
/// in (the plan's handles, the records it minted, what a writer lifted so
/// far), each key wiped when it drops. The same bytes held two ways are two
/// values: the text "7" and the number 55, which encodes to the same byte,
/// each take their own record, so each key restores its own form (FIX
/// SEALED-SAME-BYTES-RAW-AND-ENCODED-ONE-HANDLE). A key moves between
/// owners, never copied out to a plain map.
pub struct PlanValues<T>(HashMap<Vec<u8>, Vec<(HeldForm, T)>>);

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
    /// What is kept for `value` held as `held`.
    pub fn get(&self, value: &[u8], held: HeldForm) -> Option<&T> {
        self.0
            .get(value)?
            .iter()
            .find(|(form, _)| *form == held)
            .map(|(_, item)| item)
    }

    /// Keeps `item` for `value` held as `held`. A value already held keeps
    /// its key, and the copy given is wiped.
    pub fn insert(&mut self, mut value: Vec<u8>, held: HeldForm, item: T) {
        match self.0.get_mut(value.as_slice()) {
            Some(forms) => {
                value.zeroize();
                keep_form(forms, held, item);
            }
            None => {
                self.0.insert(value, vec![(held, item)]);
            }
        }
    }

    /// Every entry of `other`, moved in.
    pub fn adopt(&mut self, mut other: Self) {
        for (mut value, forms) in other.0.drain() {
            match self.0.get_mut(value.as_slice()) {
                Some(kept) => {
                    value.zeroize();
                    for (held, item) in forms {
                        keep_form(kept, held, item);
                    }
                }
                None => {
                    self.0.insert(value, forms);
                }
            }
        }
    }

    /// The same keys, each with `item`'s part `pick` keeps; the keys move.
    pub fn map<U>(mut self, pick: impl Fn(T) -> U) -> PlanValues<U> {
        let mut out = PlanValues(HashMap::with_capacity(self.0.len()));
        for (value, forms) in self.0.drain() {
            let forms = forms
                .into_iter()
                .map(|(held, item)| (held, pick(item)))
                .collect();
            out.0.insert(value, forms);
        }
        out
    }
}

/// `item` kept for one value held as `held`, in place of what was kept for
/// that form.
fn keep_form<T>(forms: &mut Vec<(HeldForm, T)>, held: HeldForm, item: T) {
    match forms.iter_mut().find(|(form, _)| *form == held) {
        Some((_, kept)) => *kept = item,
        None => forms.push((held, item)),
    }
}

impl<T> Drop for PlanValues<T> {
    fn drop(&mut self) {
        for (mut value, _) in self.0.drain() {
            value.zeroize();
        }
    }
}
