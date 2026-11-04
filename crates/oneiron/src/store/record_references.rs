//! Named record-reference values and pure pointer traversal.

use std::collections::BTreeSet;

use oneiron_contracts::memory::MemoryError;
use serde_json::Value;

/// One ref a write names, at the concrete pointer of its slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NamedRecordRef {
    /// The slot's concrete JSON pointer (`/edges/2/target_ref`).
    pub(crate) pointer: String,
    /// The ref as the caller wrote it.
    pub(crate) reference: String,
}

/// Why a write's named refs were not admitted.
#[derive(Debug)]
pub(crate) enum ReferenceRefusal {
    /// The ref at `pointer` names no record the writer may read: invented,
    /// missing and unreadable are this one refusal.
    Unresolved { pointer: String },
    /// The writer's read itself failed, so no ref was judged.
    Read(MemoryError),
}

/// The one reference walk: each ref in `refs` judged by `resolves`, the
/// writer's own read wherever it reads (a [`Memory`] lane, or a scoped read
/// in the final write's own snapshot). A ref named twice is judged once. The
/// first ref that does not resolve answers its slot's pointer; a read that
/// fails answers its error and judges nothing further. Invented, missing and
/// unreadable are one `false` from `resolves`.
pub(crate) fn validate_record_references_with<'r, E>(
    refs: &'r [NamedRecordRef],
    mut resolves: impl FnMut(&str) -> Result<bool, E>,
) -> Result<Option<&'r str>, E> {
    let mut judged = BTreeSet::new();
    for named in refs {
        if !judged.insert(named.reference.as_str()) {
            continue;
        }
        if !resolves(&named.reference)? {
            return Ok(Some(named.pointer.as_str()));
        }
    }
    Ok(None)
}

/// The string refs `input` holds at `pointers`, in pointer order. A slot that
/// is absent, null or not a string names no ref; `*` takes every item of an
/// array, and its concrete index goes into the slot's pointer.
pub(crate) fn record_references_at(input: &Value, pointers: &[&str]) -> Vec<NamedRecordRef> {
    let mut refs = Vec::new();
    for pointer in pointers {
        let segments: Vec<&str> = pointer.split('/').skip(1).collect();
        collect_at(input, &segments, String::new(), &mut refs);
    }
    refs
}

fn collect_at(value: &Value, segments: &[&str], at: String, refs: &mut Vec<NamedRecordRef>) {
    let Some((head, rest)) = segments.split_first() else {
        if let Value::String(reference) = value {
            refs.push(NamedRecordRef {
                pointer: at,
                reference: reference.clone(),
            });
        }
        return;
    };
    if *head == "*" {
        if let Value::Array(items) = value {
            for (index, item) in items.iter().enumerate() {
                collect_at(item, rest, format!("{at}/{index}"), refs);
            }
        }
        return;
    }
    if let Some(child) = value.as_object().and_then(|members| members.get(*head)) {
        collect_at(child, rest, format!("{at}/{head}"), refs);
    }
}
