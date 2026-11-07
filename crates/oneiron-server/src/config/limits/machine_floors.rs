//! The machine's own floors the `[limits]` defaults are sized from: its
//! open-file limit and its memory.

/// Half the descriptors this process may open, for sockets; the other half
/// stays for the vault, spools and git children, and the transfer rows are
/// held to what it leaves (`Transfers::new`). Raising the open-file limit
/// (`LimitNOFILE=`) raises it.
pub(super) fn descriptor_floor() -> usize {
    let limit = crate::machine::open_file_limit().unwrap_or(8_192);
    usize::try_from(limit / 2).unwrap_or(usize::MAX).max(64)
}

/// An eighth of the machine's memory for what LFS transfers hold in memory,
/// and as much for app-tier state kept between frames and for media replies,
/// each at least 256 MiB; 2 GiB when the platform does not say.
/// `limits.request_body_bytes`'s default: a 1024th of the machine's memory
/// (the least of its RAM and its container limit), the share the input-caps
/// plan gives one body read into a typed request, never under 64 MiB, the
/// facade's own body bound; 64 MiB when memory cannot be read.
pub(super) fn request_body_floor() -> u64 {
    const FLOOR: u64 = 64 * 1024 * 1024;
    crate::machine::memory_bytes().map_or(FLOOR, |memory| (memory / 1024).max(FLOOR))
}

pub(super) fn memory_floor() -> u64 {
    const MIB: u64 = 1024 * 1024;
    crate::machine::memory_bytes().map_or(2_048 * MIB, |memory| (memory / 8).max(256 * MIB))
}
