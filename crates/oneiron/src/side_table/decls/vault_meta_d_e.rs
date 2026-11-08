// Declared `vault_meta` tables whose prefix starts with `d` or `e`, in prefix order.

side_tables! {
    /// FIX 7800: an owner-selected corrupt CLAIM's audited capture exception until its hard
    /// erase commits its receipt and sweep: the exact header seen, the signed repair event and
    /// whether a SoftErase has scrubbed the body since. No content. Key: id16 (claim).
    DELETION_CORRUPT_CAPTURE: VaultMeta b"deletion:corrupt_capture:" Named
        [restore: live] [family: structure] [tier: canonical];
    /// Public ceremony rate counter. Key: hex32 [/ string].
    ESIGN_PUBLIC_RATE: VaultMeta b"esign.public_rate.v1/" Raw
        [restore: content] [family: unclassified] [tier: canonical];
}
