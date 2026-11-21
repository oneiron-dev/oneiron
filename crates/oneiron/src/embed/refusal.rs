//! The refusal an embed release answers, readable in every build: the idle
//! publisher matches it with or without the `sync` feature, while only a
//! `sync` build asks the release (`release.rs`) that makes it.

use crate::error::Error;

/// The tool an embed refusal names.
pub(super) const REMOTE_EMBEDDER: &str = "embedder-remote";
/// The code of an embed refused for a row a device-local world keeps.
pub(super) const DEVICE_LOCAL_ROW: &str = "device_local_row";

/// Whether `error` is the refusal `Vault::release_embed_rows` answers: a
/// request that held a row a device-local world keeps, and was not sent.
#[must_use]
pub fn is_device_local_row_refusal(error: &Error) -> bool {
    matches!(
        error,
        Error::UpstreamToolFailure { tool, code }
            if *tool == REMOTE_EMBEDDER && code == DEVICE_LOCAL_ROW
    )
}
