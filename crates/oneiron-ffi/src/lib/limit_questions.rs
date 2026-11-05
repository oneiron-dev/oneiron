//! The host's own engine-limit questions for a raw-opened vault (FIX 75).
//!
//! A raw open installs one fresh [`NativeLimitQuestions`] on its fresh vault
//! and measures the opened width once; bound and engine-shared handles carry
//! none. The C getter below reads the latest crossing per row as JSON.

use std::{
    collections::BTreeMap,
    sync::{Mutex, PoisonError},
};

use oneiron::limit_ask::{EngineLimit, LimitAsk};

use super::alloc::buffer_from_vec;
use super::guard::{ffi_guard, write_out};
use super::types::{OneironBuffer, OneironStatus, OneironVault};

/// The latest engine-limit crossing per row for one raw-opened vault.
///
/// Each row keeps only its latest `(bound, measured)`; no actor, query,
/// body, credential, time or history is kept.
pub(super) struct NativeLimitQuestions {
    last: Mutex<BTreeMap<EngineLimit, (u64, u64)>>,
}

impl NativeLimitQuestions {
    /// A collector that has asked nothing yet.
    pub(super) fn new() -> Self {
        Self {
            last: Mutex::new(BTreeMap::new()),
        }
    }

    /// The latest crossing per asked row, in [`EngineLimit::ALL`] order.
    /// The read does not clear.
    pub(super) fn snapshot(&self) -> Vec<(EngineLimit, u64, u64)> {
        let last = self.last.lock().unwrap_or_else(PoisonError::into_inner);
        EngineLimit::ALL
            .iter()
            .filter_map(|row| {
                last.get(row)
                    .map(|(bound, measured)| (*row, *bound, *measured))
            })
            .collect()
    }
}

impl LimitAsk for NativeLimitQuestions {
    fn crossed(&self, row: EngineLimit, bound: u64, measured: u64) {
        self.last
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(row, (bound, measured));
    }
}

/// The latest engine-limit questions this raw-opened vault asked, as UTF-8 JSON.
///
/// `out_available` is the collector fact: 1 when this handle opened its vault
/// raw and carries its questions, 0 on a bound handle or an engine-shared
/// handle, which carry none. `out_json` is the exact UTF-8 JSON array on a
/// carrying handle, `[]` when no row has been crossed yet, and the empty
/// buffer otherwise; a non-empty buffer is released with
/// `oneiron_buffer_free`. Each element is exactly
/// `{"row": <EngineLimit::key>, "bound": <u64>, "measured": <u64>}` in
/// [`EngineLimit::ALL`] order, with full `u64` digits (never narrowed
/// through a float). The read does not clear. The caller's JSON parser
/// chooses its own number precision; this side promises the digits only.
///
/// Both out pointers are initialized before anything is read or allocated.
/// A null `vault` with both outs writable is `NullArg`.
///
/// # Safety
///
/// `vault` is null or a live handle from `oneiron_vault_open`,
/// `oneiron_engine_vault` or `oneiron_vault_bind`, not freed during the
/// call. Each non-null out pointer is writable for the whole call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oneiron_vault_native_limit_questions(
    vault: *const OneironVault,
    out_available: *mut u8,
    out_json: *mut OneironBuffer,
) -> OneironStatus {
    ffi_guard(|| {
        if let Err(status) =
            write_out(out_available, 0).and_then(|()| write_out(out_json, OneironBuffer::empty()))
        {
            return status;
        }
        if vault.is_null() {
            return OneironStatus::NullArg;
        }
        // SAFETY: `vault` is a non-null handle previously returned by this
        // crate and not yet freed by `oneiron_vault_free`.
        let handle = unsafe { &*vault };
        let Some(questions) = handle.native_limit_questions.as_ref() else {
            return OneironStatus::Ok;
        };
        let result = (|| {
            let mut array = Vec::new();
            for (row, bound, measured) in questions.snapshot() {
                let mut question = serde_json::Map::with_capacity(3);
                question.insert(
                    "row".to_owned(),
                    serde_json::Value::String(row.key().to_owned()),
                );
                question.insert(
                    "bound".to_owned(),
                    serde_json::Value::Number(serde_json::Number::from(bound)),
                );
                question.insert(
                    "measured".to_owned(),
                    serde_json::Value::Number(serde_json::Number::from(measured)),
                );
                array.push(serde_json::Value::Object(question));
            }
            let bytes = serde_json::to_vec(&serde_json::Value::Array(array))
                .map_err(|_| OneironStatus::EngineError)?;
            write_out(out_available, 1)?;
            write_out(out_json, buffer_from_vec(bytes))
        })();
        result.map_or_else(|status| status, |()| OneironStatus::Ok)
    })
}
