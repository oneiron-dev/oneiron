//! A named short ref whose row a legal order keeps from use (FIX 5226): the
//! single hydrate answers the order's own refusal, and a batch answers it in
//! that ref's slot while every other slot answers as before.

use super::{
    CoreBatchShortIdHydrateItem, CoreShortIdHydrateError, CoreShortIdHydrateErrorKind,
    CoreShortIdHydrateOutcome, core_engine_error,
};
use crate::error::ApiError;

/// The one row a named hydrate found: the row, or its absence as before; a
/// row a legal order keeps from use answers that order's refusal, as the
/// engine's error map projects it (409 `INVALID_STATE`, the order's state).
pub(super) fn named_row(
    slots: Vec<oneiron::claim::NamedSlot>,
) -> Result<Option<oneiron::claim::ReadRow>, ApiError> {
    match slots.into_iter().next() {
        Some(Err(refusal)) => Err(core_engine_error("core short hydrate failed", refusal)),
        Some(Ok(row)) => Ok(row),
        None => Ok(None),
    }
}

/// A batch item whose ref a legal order keeps from use: its outcome, and the
/// order's own refusal as its message.
pub(super) fn item(reference: String, refusal: &oneiron::Error) -> CoreBatchShortIdHydrateItem {
    CoreBatchShortIdHydrateItem {
        reference,
        outcome: CoreShortIdHydrateOutcome::UseRestricted,
        result: None,
        error: Some(CoreShortIdHydrateError {
            kind: CoreShortIdHydrateErrorKind::UseRestricted,
            message: refusal.to_string(),
            field: Some("ref".to_owned()),
        }),
    }
}
