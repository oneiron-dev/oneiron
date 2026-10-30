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
//!
//! An admitted load also charges the objects it parses (FIX 8446): while a
//! [`ParseScope`] is open on a thread, every name, string, array and
//! dictionary the parser builds there is charged its own allocation as it is
//! built, and a refusal fails the parse for good.

use std::cell::RefCell;
use std::mem::size_of;
use std::sync::Arc;

use thiserror::Error;

/// Asked before a decode allocates.
pub trait DecodeAdmission: Send + Sync {
    /// Admit one allocation of `bytes` bytes, made right after this returns
    /// `Ok`. An allocation that replaces a smaller one is admitted at its full
    /// size while the old one is still alive, and the old one's bytes come
    /// back through [`DecodeAdmission::release`] once it is gone. A codec's
    /// own working state is admitted before the codec is built.
    fn admit(&self, bytes: usize) -> Result<(), DecodeAdmissionError>;

    /// Observe the length of a finished decode's output. Never refuses.
    fn decoded(&self, _bytes: usize) {}

    /// Give back `bytes` an earlier admission covered and that are no longer
    /// allocated: a buffer's old allocation once it has grown, or a decode's
    /// buffer once it is dropped (FIX 8448). Never refuses.
    fn release(&self, _bytes: usize) {}
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
/// and only then is it allocated, fallibly. Once it is, the old allocation's
/// bytes go back (FIX 8448): `buf` must have grown only through this.
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
    let old = capacity_bytes(buf);
    admission.admit(bytes)?;
    buf.try_reserve_exact(target - buf.len())
        .map_err(|_| allocator_refused(bytes))?;
    release(admission, old);
    Ok(())
}

/// The bytes `buf`'s allocation holds.
pub(crate) fn capacity_bytes<T>(buf: &Vec<T>) -> usize {
    buf.capacity().saturating_mul(size_of::<T>())
}

/// Give back `bytes` no longer allocated, if there are any.
pub(crate) fn release(admission: &dyn DecodeAdmission, bytes: usize) {
    if bytes > 0 {
        admission.release(bytes);
    }
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

/// The least a parse scope admits at once, so each small parsed object does
/// not ask on its own. Admitted, never a bound: what is left goes back when
/// the scope closes.
const PARSE_CREDIT_STEP: usize = 64 * 1024;

thread_local! {
    /// The parse scope open on this thread, if any (FIX 8446).
    static PARSE: RefCell<Option<ParseState>> = const { RefCell::new(None) };
}

/// One parse scope's admission and what it holds.
struct ParseState {
    admission: Arc<dyn DecodeAdmission>,
    /// Admitted, and not yet charged to a parsed object.
    credit: usize,
    /// The refusal that ended a charge. Every later charge refuses with it,
    /// so the parse cannot go on half charged.
    refused: Option<DecodeAdmissionError>,
}

/// While open, the objects the parser builds on this thread are charged to
/// one admission (FIX 8446). A scope opened inside another charges the outer
/// one's. Closing it gives back what it admitted and did not charge.
pub(crate) struct ParseScope {
    opened: bool,
}

impl ParseScope {
    /// Open a scope over `admission`; with none, or with a scope already open
    /// on this thread, nothing changes.
    pub(crate) fn enter(admission: Option<&Arc<dyn DecodeAdmission>>) -> Self {
        let Some(admission) = admission else {
            return Self { opened: false };
        };
        let opened = PARSE.with(|parse| {
            let mut parse = parse.borrow_mut();
            if parse.is_some() {
                return false;
            }
            *parse = Some(ParseState {
                admission: Arc::clone(admission),
                credit: 0,
                refused: None,
            });
            true
        });
        Self { opened }
    }
}

impl Drop for ParseScope {
    fn drop(&mut self) {
        if !self.opened {
            return;
        }
        if let Some(state) = PARSE.with(|parse| parse.borrow_mut().take()) {
            release(state.admission.as_ref(), state.credit);
        }
    }
}

/// Charge `bytes` a parsed object's own allocation holds to the parse scope
/// open on this thread; without one nothing is charged. `Err` once the
/// scope's admission refused.
pub(crate) fn charge_parsed(bytes: usize) -> Result<(), DecodeAdmissionError> {
    PARSE.with(|parse| {
        let mut parse = parse.borrow_mut();
        let Some(state) = parse.as_mut() else {
            return Ok(());
        };
        if let Some(refused) = &state.refused {
            return Err(refused.clone());
        }
        if bytes <= state.credit {
            state.credit -= bytes;
            return Ok(());
        }
        let step = (bytes - state.credit).max(PARSE_CREDIT_STEP);
        match state.admission.admit(step) {
            Ok(()) => {
                state.credit = state.credit + step - bytes;
                Ok(())
            }
            Err(err) => {
                state.refused = Some(err.clone());
                Err(err)
            }
        }
    })
}

/// The refusal that ended a charge in the parse scope open on this thread.
pub(crate) fn parse_refusal() -> Option<DecodeAdmissionError> {
    PARSE.with(|parse| parse.borrow().as_ref().and_then(|state| state.refused.clone()))
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
