//! Wire limit constants and ready byte.

/// Credentials fd carries exactly this many bytes: DEK(32) ‖ spawn-token(32).
pub const CREDENTIALS_LEN: usize = 64;

pub const DEK_LEN: usize = 32;

pub const TOKEN_LEN: usize = 32;

/// Wire limits. Violations are rejected, never truncated.
pub const MAX_CTL_LINE: usize = 64 * 1024;

pub const MAX_LEDGER_ENTRIES: usize = 128;

pub const MAX_REASON_TAG: usize = 64;

pub const MAX_WAKE_ID: usize = 128;

/// Ready byte written to the ready fd once both sockets are bound.
pub const READY_BYTE: u8 = 0x01;
