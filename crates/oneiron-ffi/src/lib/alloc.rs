//! Rust-owned buffer/array constructors and generic free_vec.

use oneiron::EntityId;

use super::types::{
    ENTITY_ID_LEN, OneironBuffer, OneironEdgeInfo, OneironEdgeInfoArray, OneironScoredEntity,
    OneironScoredEntityArray, OneironStatus, OneironSubtreeEntry, OneironSubtreeEntryArray,
};

pub(super) fn buffer_from_vec(mut bytes: Vec<u8>) -> OneironBuffer {
    if bytes.is_empty() {
        return OneironBuffer::empty();
    }
    let buffer = OneironBuffer {
        ptr: bytes.as_mut_ptr(),
        len: bytes.len(),
        cap: bytes.capacity(),
    };
    std::mem::forget(bytes);
    buffer
}

pub(super) fn id_list_buffer(ids: Vec<EntityId>) -> Result<OneironBuffer, OneironStatus> {
    let capacity = ids
        .len()
        .checked_mul(ENTITY_ID_LEN)
        .ok_or(OneironStatus::EngineError)?;
    let mut bytes = Vec::with_capacity(capacity);
    for id in ids {
        bytes.extend_from_slice(id.as_bytes());
    }
    Ok(buffer_from_vec(bytes))
}

pub(super) fn edge_array_from_vec(mut values: Vec<OneironEdgeInfo>) -> OneironEdgeInfoArray {
    if values.is_empty() {
        return OneironEdgeInfoArray::empty();
    }
    let array = OneironEdgeInfoArray {
        ptr: values.as_mut_ptr(),
        len: values.len(),
        cap: values.capacity(),
    };
    std::mem::forget(values);
    array
}

pub(super) fn scored_array_from_vec(
    mut values: Vec<OneironScoredEntity>,
) -> OneironScoredEntityArray {
    if values.is_empty() {
        return OneironScoredEntityArray::empty();
    }
    let array = OneironScoredEntityArray {
        ptr: values.as_mut_ptr(),
        len: values.len(),
        cap: values.capacity(),
    };
    std::mem::forget(values);
    array
}

pub(super) fn subtree_array_from_vec(
    mut values: Vec<OneironSubtreeEntry>,
) -> OneironSubtreeEntryArray {
    if values.is_empty() {
        return OneironSubtreeEntryArray::empty();
    }
    let array = OneironSubtreeEntryArray {
        ptr: values.as_mut_ptr(),
        len: values.len(),
        cap: values.capacity(),
    };
    std::mem::forget(values);
    array
}

pub(super) fn free_vec<T>(ptr: *mut T, len: usize, cap: usize) -> OneironStatus {
    if ptr.is_null() {
        return if len == 0 && cap == 0 {
            OneironStatus::Ok
        } else {
            OneironStatus::InvalidArg
        };
    }
    if len > cap {
        return OneironStatus::InvalidArg;
    }
    // SAFETY: The pointer, length, and capacity must be the exact triple
    // returned by this crate for a `Vec<T>` allocation and not freed before.
    unsafe { drop(Vec::from_raw_parts(ptr, len, cap)) };
    OneironStatus::Ok
}
