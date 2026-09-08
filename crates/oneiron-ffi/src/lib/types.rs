//! repr(C) status/types/handles and ABI limit constants.

use std::{ptr, sync::Arc};

use oneiron::Vault;

pub(super) const DEFAULT_FFI_SEARCH_LIMIT: u32 = 10;

pub(super) const MAX_FFI_SEARCH_LIMIT: u32 = 1_000;

pub(super) const MAX_FFI_QUERY_BYTES: usize = 8 * 1024;

pub(super) const MAX_FFI_DIMENSIONS: usize = 16_384;

pub(super) const ENTITY_ID_LEN: usize = 16;

/// Status code returned by every fallible C entry point.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OneironStatus {
    /// Operation completed successfully.
    Ok = 0,
    /// A required pointer argument was null.
    NullArg = 1,
    /// A scalar, length, enum discriminant, or ID value failed validation.
    InvalidArg = 2,
    /// The requested optional value was not found.
    NotFound = 3,
    /// The engine returned an error.
    EngineError = 4,
    /// A Rust panic was caught before it crossed the C ABI boundary.
    Panic = 5,
    /// Reserved for caller-owned buffer APIs.
    BufferTooSmall = 6,
    /// Input bytes were not valid UTF-8.
    Utf8 = 7,
}

/// Borrowed byte/string input for arrays such as `dict_search_paths`.
///
/// Each element is caller-owned and is only borrowed for the duration of the
/// call. String uses are UTF-8 validated by the receiving function.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct OneironByteSlice {
    pub ptr: *const u8,
    pub len: usize,
}

/// Borrowed entity input for `oneiron_vault_batch_put_entities`.
///
/// Each payload is caller-owned and borrowed only for the duration of the
/// call. Entity IDs are fixed-width 16-byte values; `entity_type` must fit in
/// one byte and pass the engine's public entity-type gate.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct OneironEntityInput {
    pub id: [u8; 16],
    pub entity_type: u32,
    pub occurred_start: i64,
    pub occurred_end: i64,
    pub learned_at: i64,
    pub data: OneironByteSlice,
}

/// Rust-owned byte buffer returned by variable-size byte outputs.
///
/// The caller must release non-empty buffers with `oneiron_buffer_free`. The
/// caller must not pass `ptr` to `free()` and must not call the free function
/// more than once for the same buffer.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct OneironBuffer {
    pub ptr: *mut u8,
    pub len: usize,
    pub cap: usize,
}

impl OneironBuffer {
    pub(super) const fn empty() -> Self {
        Self {
            ptr: ptr::null_mut(),
            len: 0,
            cap: 0,
        }
    }
}

/// C representation of an edge returned by `edges_out` and `edges_in`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct OneironEdgeInfo {
    pub src: [u8; 16],
    pub kind: u32,
    pub tgt: [u8; 16],
    pub weight: f64,
    pub created_at: i64,
    pub has_vad: u8,
    pub valence: f64,
    pub arousal: f64,
    pub dominance: f64,
}

/// Rust-owned edge array. Free with `oneiron_edge_info_array_free`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct OneironEdgeInfoArray {
    pub ptr: *mut OneironEdgeInfo,
    pub len: usize,
    pub cap: usize,
}

impl OneironEdgeInfoArray {
    pub(super) const fn empty() -> Self {
        Self {
            ptr: ptr::null_mut(),
            len: 0,
            cap: 0,
        }
    }
}

/// C representation of a scored search result.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct OneironScoredEntity {
    pub id: [u8; 16],
    pub score: f64,
}

/// Rust-owned scored search result array. Free with
/// `oneiron_scored_entity_array_free`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct OneironScoredEntityArray {
    pub ptr: *mut OneironScoredEntity,
    pub len: usize,
    pub cap: usize,
}

impl OneironScoredEntityArray {
    pub(super) const fn empty() -> Self {
        Self {
            ptr: ptr::null_mut(),
            len: 0,
            cap: 0,
        }
    }
}

/// C representation of a subtree traversal entry.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct OneironSubtreeEntry {
    pub id: [u8; 16],
    pub depth: u32,
}

/// Rust-owned subtree entry array. Free with
/// `oneiron_subtree_entry_array_free`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct OneironSubtreeEntryArray {
    pub ptr: *mut OneironSubtreeEntry,
    pub len: usize,
    pub cap: usize,
}

impl OneironSubtreeEntryArray {
    pub(super) const fn empty() -> Self {
        Self {
            ptr: ptr::null_mut(),
            len: 0,
            cap: 0,
        }
    }
}

/// Opaque vault handle returned by `oneiron_vault_open`.
///
/// Release the handle with `oneiron_vault_free` exactly once.
pub struct OneironVault {
    pub(super) vault: Arc<Vault>,
    pub(super) dimensions: usize,
}
