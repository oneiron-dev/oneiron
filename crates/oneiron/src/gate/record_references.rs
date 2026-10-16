//! OF-063: one check that every record a write names resolves for its writer.
//!
//! The owner's ruling (2026-10-17): check that the records an AI says it
//! created, or cites, really exist; refuse invented ones and log the refusal.
//!
//! A verb-table row declares its typed ref slots as JSON pointers (`refs` in
//! `scripts/sdk/agent-verbs.json`, where `*` takes every item of an array).
//! The row's generated engine fn calls [`admit_row_references`] before the
//! engine call, so every door that reaches the row (the HTTP facade, the MCP
//! dispatch, code mode and the SDK) meets this check once, and no door
//! carries a second, hand-written one.
//!
//! Every named ref must resolve under the WRITER's own scoped read. An
//! invented ref, a missing record and a record the writer may not read are
//! one refusal, so the writer learns nothing it could not read. The refusal
//! names the field pointer, never the ref, and it is receipted on its own
//! write ([`crate::receipt::ReceiptKind::ReferenceRefusal`]) before the
//! caller hears it. The refused write never runs.
//!
//! Only typed slots are read here: free text is never parsed for refs.

use std::collections::BTreeSet;

use serde_json::Value;

use crate::memory::{
    MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_INVENTED_REFERENCE, MEMORY_CODE_NOT_FOUND, Memory,
    MemoryError, MemoryResult,
};
use crate::receipt::{ReferenceRefusalFacts, record_reference_refusal};

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

/// Checks that every ref in `refs` resolves under `read`, the writer's own
/// scoped read. The first ref that does not is the refusal; a ref named twice
/// is read once.
pub(crate) fn validate_record_references(
    read: &Memory<'_>,
    refs: &[NamedRecordRef],
) -> Result<(), ReferenceRefusal> {
    let mut judged = BTreeSet::new();
    for named in refs {
        if !judged.insert(named.reference.as_str()) {
            continue;
        }
        let resolves = match read.get_entity(&named.reference) {
            Ok(result) => result.value.is_some(),
            Err(error)
                if error.code == MEMORY_CODE_NOT_FOUND || error.code == MEMORY_CODE_BAD_REQUEST =>
            {
                false
            }
            Err(error) => return Err(ReferenceRefusal::Read(error)),
        };
        if !resolves {
            return Err(ReferenceRefusal::Unresolved {
                pointer: named.pointer.clone(),
            });
        }
    }
    Ok(())
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

/// The generated check one verb-table row with `refs` runs before its engine
/// call: every ref `input` names at `pointers` must resolve for `memory`'s
/// writer. A refusal is receipted on its own write, naming the actor, `row`,
/// the field pointer and the time, and only then returned as
/// [`MEMORY_CODE_INVENTED_REFERENCE`]; if the receipt cannot be written the
/// store's error is returned instead, never a refusal claiming it was logged.
pub(crate) fn admit_row_references<T: serde::Serialize>(
    memory: &Memory<'_>,
    row: &'static str,
    input: &T,
    pointers: &[&str],
) -> MemoryResult<()> {
    let value = serde_json::to_value(input).map_err(|_| {
        MemoryError::bad_request("the verb input could not be read for the records it names")
    })?;
    let refs = record_references_at(&value, pointers);
    match validate_record_references(memory, &refs) {
        Ok(()) => Ok(()),
        Err(ReferenceRefusal::Read(error)) => Err(error),
        Err(ReferenceRefusal::Unresolved { pointer }) => {
            record_reference_refusal(
                memory.vault(),
                &ReferenceRefusalFacts {
                    actor: memory.actor(),
                    actor_class: memory.actor_class(),
                    row,
                    field: pointer.clone(),
                },
            )?;
            Err(invented_reference(&pointer))
        }
    }
}

/// The refusal a write naming an unresolved record ref gets: the field
/// pointer, never the ref.
pub(crate) fn invented_reference(pointer: &str) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_INVENTED_REFERENCE,
        format!(
            "the record named at `{pointer}` does not resolve for this writer; the write was refused and the refusal receipted"
        ),
        &[
            "Name only records this writer can read, by the ref the engine issued (a short id or a 32-hex id).",
            "A missing record and one this writer may not read give this same refusal.",
        ],
    )
}
