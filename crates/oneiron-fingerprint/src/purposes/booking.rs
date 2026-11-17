//! Purposes of booking (`crates/oneiron/src/booking`).

purposes! {}

legacy_purposes! {
    /// The key a booking lifecycle receipt is kept under (`booking::lifecycle::storage`):
    /// plain BLAKE3, the tag's bytes (ending in a NUL), then for a confirm `confirm\0` and the
    /// hold token's digest; for a revision the scope's tag (`reschedule\0` with the target
    /// slot's start and end as u64 big-endian, or `cancel\0`) and the BOOKING's id. A retry
    /// under the same key replays the stored receipt.
    LIFECYCLE_RECEIPT_KEY = (Blake3, HashedFirst, "oneiron.booking.receipt.v1\0");
}
