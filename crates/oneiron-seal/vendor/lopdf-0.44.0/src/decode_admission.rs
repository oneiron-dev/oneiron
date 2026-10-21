//! Memory admission for the buffers a decode allocates.
//!
//! Local patch, not upstream lopdf (see `crates/oneiron-seal/vendor/README.md`).
//! A caller hands a [`DecodeAdmission`] to [`crate::LoadOptions::decode_admission`]
//! or to [`crate::Stream::decompressed_content_admitted`]. Before the decode
//! allocates or grows a buffer it asks [`DecodeAdmission::admit`] for the full
//! size of that allocation. A refusal ends the decode and comes back as
//! [`crate::Error::DecodeAdmission`]; it never turns into a codec fallback, a
//! skipped object or a parse error. Without an admission every decode runs
//! exactly as upstream's.

use std::mem::size_of;

use thiserror::Error;

/// Asked before a decode allocates.
pub trait DecodeAdmission: Send + Sync {
    /// Admit one allocation of `bytes` bytes, made right after this returns
    /// `Ok`. Admissions are never released: an allocation that replaces a
    /// smaller one is admitted at its full size while the old one is still
    /// alive, and a codec's own working state is admitted before the codec is
    /// built.
    fn admit(&self, bytes: usize) -> Result<(), DecodeAdmissionError>;

    /// Observe the length of a finished decode's output. Never refuses.
    fn decoded(&self, _bytes: usize) {}
}

/// Why a decode could not have the memory it asked for.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DecodeAdmissionError {
    /// The machine cannot hold the allocation. `available` is 0 when the
    /// allocator itself, or the address space, refused an allocation the
    /// admission had passed.
    #[error("decode needs {needed} bytes of memory but {available} bytes are available")]
    MemoryFloor { needed: u64, available: u64 },
    /// The decode's deadline passed.
    #[error("decode deadline passed")]
    Deadline,
    /// The decode was cancelled.
    #[error("decode cancelled")]
    Cancelled,
}

/// What a codec allocates for its own working state when it is built, admitted
/// before it is built. zlib-rs 0.6 puts its inflate state (about 15 KiB) and a
/// 32 KiB + 64 B window in one allocation; miniz_oxide 0.9 boxes about 11 KiB
/// of decompressor beside a 32 KiB dictionary; weezl 0.2 builds 56 KiB of code
/// tables and a 4 KiB reconstruction buffer. The codecs allocate this
/// themselves, so it is an estimate of their sizes, not a measured charge.
pub(crate) const CODEC_STATE_BYTES: usize = 64 * 1024;

/// Make room in `buf` for `additional` more elements. When the capacity has
/// to grow it doubles (or takes exactly what is needed, if that is more), the
/// whole new allocation is admitted in bytes while the old one is still alive,
/// and only then is it allocated, fallibly.
pub(crate) fn reserve<T>(
    admission: &dyn DecodeAdmission, buf: &mut Vec<T>, additional: usize,
) -> Result<(), DecodeAdmissionError> {
    let needed = buf.len().checked_add(additional).ok_or_else(unaddressable)?;
    if needed <= buf.capacity() {
        return Ok(());
    }
    // Doubling keeps appends amortized; past the address space take only what is needed.
    let doubled = buf.capacity().saturating_mul(2).max(needed);
    let target = if layout_bytes::<T>(doubled).is_some() { doubled } else { needed };
    let bytes = layout_bytes::<T>(target).ok_or_else(unaddressable)?;
    admission.admit(bytes)?;
    buf.try_reserve_exact(target - buf.len())
        .map_err(|_| allocator_refused(bytes))
}

/// Append `bytes` to `buf`, admitting any growth first.
pub(crate) fn extend(
    admission: &dyn DecodeAdmission, buf: &mut Vec<u8>, bytes: &[u8],
) -> Result<(), DecodeAdmissionError> {
    reserve(admission, buf, bytes.len())?;
    buf.extend_from_slice(bytes);
    Ok(())
}

/// A copy of `bytes`, admitted before it is allocated.
pub(crate) fn copy(admission: &dyn DecodeAdmission, bytes: &[u8]) -> Result<Vec<u8>, DecodeAdmissionError> {
    let mut out = Vec::new();
    extend(admission, &mut out, bytes)?;
    Ok(out)
}

/// The most one node of a std `BTreeMap<K, V>` takes: an internal node holds
/// 11 keys, 11 values and 12 child edges, plus a parent link, two counters and
/// padding, which fit in 64 more bytes.
pub(crate) const fn btree_node_bytes<K, V>() -> usize {
    11 * (size_of::<K>() + size_of::<V>()) + 12 * size_of::<usize>() + 64
}

/// The share of [`btree_node_bytes`] admitted before each insert into a
/// `BTreeMap<K, V>`. Every node but the root holds at least 5 entries, so `n`
/// entries live in at most `1 + n / 5` nodes: one node admitted up front plus
/// this share per insert covers them.
pub(crate) const fn btree_entry_bytes<K, V>() -> usize {
    btree_node_bytes::<K, V>().div_ceil(5)
}

/// Admit the nodes of a `BTreeMap<K, V>` that will hold at most `entries`
/// entries, before any of them is inserted.
pub(crate) fn admit_btree<K, V>(admission: &dyn DecodeAdmission, entries: usize) -> Result<(), DecodeAdmissionError> {
    let bytes = btree_entry_bytes::<K, V>()
        .checked_mul(entries)
        .and_then(|shares| shares.checked_add(btree_node_bytes::<K, V>()))
        .ok_or_else(unaddressable)?;
    admission.admit(bytes)
}

/// Bytes `len` elements of `T` take, if one allocation can hold them.
fn layout_bytes<T>(len: usize) -> Option<usize> {
    len.checked_mul(size_of::<T>()).filter(|&bytes| bytes <= isize::MAX as usize)
}

/// A size no allocation can have.
fn unaddressable() -> DecodeAdmissionError {
    DecodeAdmissionError::MemoryFloor {
        needed: u64::MAX,
        available: 0,
    }
}

/// The allocator refused `bytes` the admission had passed.
fn allocator_refused(bytes: usize) -> DecodeAdmissionError {
    DecodeAdmissionError::MemoryFloor {
        needed: u64::try_from(bytes).unwrap_or(u64::MAX),
        available: 0,
    }
}
