//! The ask a run branch holds under a handle, a handle the side-row wall
//! masked included (blind review round 1 of #9803).

use std::sync::Arc;

use super::RunAsk;
use crate::batch::secret_scan::{admitted_from_known, named_tree};
use crate::error::Result;
use crate::store::known_value_index::KnownValues;

/// The ask `asks` holds under `handle`: as written, or as the side-row wall
/// stored it, a value base custody holds read as its record's handle in the
/// handle too (blind review round 1 of #9803). `known` gives the values
/// custody holds now, read only when no ask holds `handle` as written; two
/// values custody holds apart stay two handles ([`admitted_from_known`]).
pub(super) fn held_ask<'a>(
    asks: &'a [RunAsk],
    handle: &str,
    known: impl FnOnce() -> Result<Option<Arc<KnownValues>>>,
) -> Result<Option<&'a RunAsk>> {
    if let Some(ask) = asks.iter().find(|ask| ask.handle == handle) {
        return Ok(Some(ask));
    }
    if asks.is_empty() {
        return Ok(None);
    }
    let known = known()?;
    let offered = named_tree(&handle)?;
    for ask in asks {
        if admitted_from_known(&named_tree(&ask.handle)?, &offered, || Ok(known.clone()))? {
            return Ok(Some(ask));
        }
    }
    Ok(None)
}
