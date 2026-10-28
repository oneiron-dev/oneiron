//! Who drafted an amended proposal: the executor identity at revision and
//! the task type, as the attempt the proposal came from was stamped (FIX 9812).
//!
//! The stamp is the one the attempt froze when its run began
//! (`AttemptRecord::executor_model`, copied onto its terminal pack receipt).
//! It is never re-derived later from whatever model serves then. A proposal no
//! attempt names, and a stamp that does not read as `id@revision`, has an
//! unknown executor: recorded as unknown, never refused and never guessed.

use crate::Vault;
use crate::error::Result;
use crate::learning::TypeRef;

/// The executor key of a receipt that carries no executor stamp. It holds no
/// `@`, so no stamped `id@revision` can collide with it.
pub(in crate::edit_distance) const UNKNOWN_EXECUTOR: &str = "unknown";

/// Longest executor stamp accepted: the attempt queue's own bound.
const MAX_EXECUTOR_BYTES: usize = 256;

/// The executor and task type the evidence door records for one amendment:
/// the named attempt's stamps first, then what the host stamped, each kept
/// only when it reads as one.
///
/// # Errors
///
/// Storage errors reading the attempt's pack receipt.
pub(super) fn evidence_origin(
    vault: &Vault,
    attempt_receipt: Option<&str>,
    executor: Option<&str>,
    type_ref: Option<&TypeRef>,
) -> Result<(Option<String>, Option<TypeRef>)> {
    let (attempt_executor, attempt_type) = match attempt_receipt {
        Some(receipt) => attempt_origin(vault, receipt)?,
        None => (None, None),
    };
    let executor = attempt_executor.or_else(|| executor.and_then(usable_executor));
    let type_ref = attempt_type.or_else(|| {
        type_ref
            .filter(|type_ref| type_ref.validate().is_ok())
            .cloned()
    });
    Ok((executor, type_ref))
}

/// The executor and task type the attempt behind `attempt_receipt` was
/// stamped with, each `None` where its terminal pack receipt records none.
fn attempt_origin(
    vault: &Vault,
    attempt_receipt: &str,
) -> Result<(Option<String>, Option<TypeRef>)> {
    let Some(receipt) = crate::receipt::attempt_pack_receipt(vault, attempt_receipt)? else {
        return Ok((None, None));
    };
    let executor = receipt.executor_model().and_then(usable_executor);
    let type_ref = receipt
        .task_type_ref()
        .map(|stamp| TypeRef::from(&stamp))
        .or_else(|| {
            receipt
                .pack_attribution_fields()
                .ok()
                .map(|fields| fields.type_ref)
        });
    Ok((executor, type_ref))
}

/// `stamp` as an executor identity at revision, or `None` when it does not
/// read as one.
fn usable_executor(stamp: &str) -> Option<String> {
    let usable = stamp.len() <= MAX_EXECUTOR_BYTES
        && !stamp.chars().any(char::is_control)
        && stamp
            .rsplit_once('@')
            .is_some_and(|(id, revision)| !id.is_empty() && !revision.is_empty());
    usable.then(|| stamp.to_owned())
}
