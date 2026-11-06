//! Original-value shared-env bootstrap outcome (L14 S58): engine-gated.
//!
//! [`NativeSharedBootstrapOutcome`] keeps the native import result and
//! committed flag independently, exactly as
//! [`oneiron_server::embedded::BlockingEngine::bootstrap_shared_env`]
//! answers them: the original `anyhow::Result<Arc<oneiron::Vault>>` beside
//! its `bool`. No synthesized path and no success on an inner `Err`: the
//! vault path reads only from a successful import, and a failed one raises
//! its native error instead.
//!
//! Error preservation is downcast-first, never the engine projection alone:
//! every new outer or inner `anyhow` failure is tried as the original
//! [`oneiron::MemoryError`] first (cloned, then `facade_error`); only when
//! it is not one does `engine_memory_error` project it. The existing
//! `engine_memory_error` constructs a NEW error and does not round-trip a
//! native payload, so it must never be the first mapping here. The outcome's
//! `error_json` reads the inner ORIGINAL `MemoryError` only (`None` on any
//! other inner failure or on success); the committed bit is independent.
//! Existing engine channels are unchanged.
//!
//! Entry input follows the `NativeClient::retry` template (`js_json` then a
//! typed decode); the entry's `vault_id` reads as a number or a decimal
//! string, as the native config does. Error output is a JSON STRING from the
//! original serde serialization, never a `Value`.

use std::sync::Arc;

use napi_derive::napi;
use oneiron_server::embedded::engine_memory_error;

use super::super::boundary::{boundary_error, facade_error};
use super::super::js_json::js_json;

/// One bootstrap's native import result and committed flag, kept
/// independently.
#[napi]
pub struct NativeSharedBootstrapOutcome {
    imported: anyhow::Result<Arc<oneiron::Vault>>,
    committed: bool,
}

impl NativeSharedBootstrapOutcome {
    /// The native import result beside its committed flag, both original.
    pub(super) fn from_native(
        imported: anyhow::Result<Arc<oneiron::Vault>>,
        committed: bool,
    ) -> Self {
        Self {
            imported,
            committed,
        }
    }
}

/// One native `SharedEnvConfig` entry from JavaScript, as the native config
/// reads it: `path`, `vault_id` as a number or a decimal string, `member`,
/// `home_url`, and `credential_file`.
pub(super) fn shared_env_entry(
    value: serde_json::Value,
) -> napi::Result<oneiron_server::config::SharedEnvConfig> {
    let value = js_json(value);
    serde_json::from_value(value).map_err(|error| {
        facade_error(oneiron::MemoryError::new(
            oneiron::memory::MEMORY_CODE_BAD_REQUEST,
            format!("the shared-env entry is not the documented shape: {error}"),
            &["Send {path, vault_id, member, home_url, credential_file}."],
        ))
    })
}

/// A new outer or inner engine `anyhow` failure as the facade's typed error:
/// the ORIGINAL native `MemoryError` when that is what failed, else the
/// engine projection. Only the new shared-env calls map through here.
pub(super) fn shared_engine_error(error: &anyhow::Error) -> napi::Error {
    match error.downcast_ref::<oneiron::MemoryError>() {
        Some(exact) => facade_error(exact.clone()),
        None => facade_error(engine_memory_error(error)),
    }
}

#[napi]
impl NativeSharedBootstrapOutcome {
    /// The native publication flag, including when a later step failed.
    #[napi]
    pub fn committed(&self) -> bool {
        self.committed
    }

    /// The actual registry-held vault's path on success. A failed import,
    /// credential update or insertion raises its native error instead; it
    /// never returns an empty or fabricated successful path.
    #[napi]
    pub fn vault_path(&self) -> napi::Result<String> {
        match &self.imported {
            Ok(vault) => Ok(vault.path().to_string_lossy().into_owned()),
            Err(error) => Err(shared_engine_error(error)),
        }
    }

    /// The outcome's inner native `MemoryError` as its complete serialized
    /// JSON text, read without consuming the outcome: `null` when the import
    /// succeeded or failed with another error. The identity is the exact
    /// downcast, never read from the words; a string, so no integer survives
    /// lossily as a JS number.
    #[napi]
    pub fn error_json(&self) -> napi::Result<Option<String>> {
        match &self.imported {
            Ok(_) => Ok(None),
            Err(error) => match error.downcast_ref::<oneiron::MemoryError>() {
                Some(exact) => {
                    let json = serde_json::to_string(exact).map_err(|error| {
                        boundary_error(format!("could not encode the bootstrap error: {error}"))
                    })?;
                    Ok(Some(json))
                }
                None => Ok(None),
            },
        }
    }
}
