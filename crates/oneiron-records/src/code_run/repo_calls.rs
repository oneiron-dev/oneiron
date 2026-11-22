//! Moved from `crates/oneiron/src/code_run/repo_calls.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use oneiron_base::error::Result;
use serde_json::Value;

/// A run repo row's closed input from its JSON.
pub fn typed<T: serde::de::DeserializeOwned>(input: Value) -> Result<T> {
    serde_json::from_value(input)
        .map_err(|_| Error::InvalidConfig("invalid typed component arguments".to_owned()))
}

/// A verb hook's rewrite of one row's input, decoded as the guest's is.
pub fn retyped<T: serde::de::DeserializeOwned>(args: &Value) -> std::result::Result<T, String> {
    serde_json::from_value(args.clone()).map_err(|error| error.to_string())
}
