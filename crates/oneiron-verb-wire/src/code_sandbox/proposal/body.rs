//! Moved from `crates/oneiron/src/code_sandbox/proposal/body.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

/// One host buffer of a spool copy or a body read; never a size bound.
pub const READ_FRAME: usize = 1024 * 1024;
