//! The host's own engine-limit questions for a raw-opened vault (FIX 75).
//!
//! A raw open installs one fresh [`NativeLimitQuestions`] on its fresh vault
//! and measures the opened width once; bound and engine-shared vaults carry
//! none. The JNI getter below reads the latest crossing per row as JSON.

use std::{
    collections::BTreeMap,
    sync::{Mutex, MutexGuard, PoisonError},
};

use jni::{
    JNIEnv,
    objects::{JObject, JString},
    sys::jstring,
};
use oneiron::limit_ask::{EngineLimit, LimitAsk};

use super::{NativeVault, display, run};

/// The latest engine-limit crossing per row for one raw-opened vault.
///
/// Each row keeps only its latest `(bound, measured)`; no actor, query,
/// body, credential, time or history is kept.
pub(crate) struct NativeLimitQuestions {
    last: Mutex<BTreeMap<EngineLimit, (u64, u64)>>,
}

impl NativeLimitQuestions {
    /// A collector that has asked nothing yet.
    pub(crate) fn new() -> Self {
        Self {
            last: Mutex::new(BTreeMap::new()),
        }
    }

    /// The latest crossing per asked row, in [`EngineLimit::ALL`] order.
    /// The read does not clear.
    pub(crate) fn snapshot(&self) -> Vec<(EngineLimit, u64, u64)> {
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

/// The latest engine-limit questions this raw-opened vault asked, as a JSON
/// array string: `null` on a bound vault or an engine-shared vault, which
/// carry none, `[]` when no row has been crossed yet. Each element is exactly
/// `{"row": <EngineLimit::key>, "bound": <u64>, "measured": <u64>}` in
/// [`EngineLimit::ALL`] order, with full `u64` digits (never narrowed
/// through a float). The read does not clear. The caller's JSON parser
/// chooses its own number precision; this side promises the digits only.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_oneiron_EmbeddedVault_nativeLimitQuestionsNative(
    mut env: JNIEnv<'_>,
    object: JObject<'_>,
) -> jstring {
    run(&mut env, |env| {
        let json = {
            // SAFETY: the synchronized Kotlin instance alone owns this private
            // field; close takes it once and clears it before any later access.
            let vault: MutexGuard<'_, NativeVault> =
                unsafe { env.get_rust_field(&object, "nativeHandle") }.map_err(display)?;
            match vault.native_limit_questions.as_ref() {
                None => None,
                Some(questions) => {
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
                    Some(serde_json::to_string(&serde_json::Value::Array(array)).map_err(display)?)
                }
            }
        };
        match json {
            None => Ok(std::ptr::null_mut()),
            Some(json) => env.new_string(json).map(JString::into_raw).map_err(display),
        }
    })
}
