//! Moved from `crates/oneiron/src/code_sandbox/proposal.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use oneiron_base::error::Result;
pub use oneiron_store::proposal_spool::ProposalSpoolClaim;
pub use oneiron_store::proposal_spool::ProposalSpoolFloor;
pub use oneiron_store::proposal_spool::SpoolAtFloor;
pub use oneiron_store::proposal_spool::SpoolFloorRefusal;

/// One comparison buffer while a write is lowered; never a size bound.
pub const LOWER_FRAME: usize = 1024 * 1024;

/// `len` zero bytes in memory reserved first: host memory that cannot hold
/// them refuses as [`out_of_memory`], before anything is read (FIX 8674).
pub fn zeroed(len: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(len).map_err(out_of_memory)?;
    bytes.resize(len, 0);
    Ok(bytes)
}

/// A reservation the host allocator could not make: the existing I/O error
/// of kind `OutOfMemory`, never a size limit of our own (FIX 8674).
pub fn out_of_memory(_: std::collections::TryReserveError) -> Error {
    Error::Io(std::io::Error::from(std::io::ErrorKind::OutOfMemory))
}
pub mod body;
