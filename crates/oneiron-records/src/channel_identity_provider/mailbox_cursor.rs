//! Moved from `crates/oneiron/src/channel_identity_provider/mailbox_cursor.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use oneiron_base::error::Result;

pub const MAX_CURSOR_BYTES: usize = 256;

/// Reject malformed provider tokens on both sides of the wire, including
/// stored state that might otherwise be sent back to a provider.
///
/// # Errors
///
/// [`Error::InvalidConfig`] for a blank or overlong token.
pub fn validate_mailbox_cursor(cursor: &str) -> Result<()> {
    if cursor.trim().is_empty() || cursor.len() > MAX_CURSOR_BYTES {
        return Err(Error::InvalidConfig(
            "gmail page cursor must be non-empty and at most 256 bytes".to_owned(),
        ));
    }
    Ok(())
}
