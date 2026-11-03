//! Window payload bounds and local commit origin values.

/// Shared 8 MB cap for decoded payloads: bulk-transfer decompression and
/// root-doc imports both refuse anything larger (decompression-bomb /
/// memory-exhaustion guard).
pub const MAX_DECODED_PAYLOAD_BYTES: usize = 8 * 1024 * 1024;

/// Origin for a local deletion tombstone whose durable LMDB carrier is
/// authored explicitly by the deletion TXN1, not Observer A. Observer B also
/// skips it, preserving the tombstone-first → local-purge ordering.
pub(crate) const DELETION_TOMBSTONE_ORIGIN: &str = "deletion_tombstone";
