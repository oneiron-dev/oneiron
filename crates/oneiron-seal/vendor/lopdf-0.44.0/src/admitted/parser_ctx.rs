use std::mem::size_of;

use crate::decode_admission::{DecodeAdmission, DecodeAdmissionError};
use crate::{Dictionary, Object};

fn allocation_bytes(entries: usize) -> Option<usize> {
    entries.checked_mul(size_of::<(Vec<u8>, Object)>() + size_of::<usize>())
}

fn unaddressable() -> DecodeAdmissionError {
    DecodeAdmissionError::MemoryFloor {
        needed: u64::MAX,
        available: 0,
    }
}

/// Insert one admitted key and value, reserving the dictionary's growth first.
pub(crate) fn insert(
    admission: Option<&dyn DecodeAdmission>, dict: &mut Dictionary, key: Vec<u8>, value: Object,
) -> Result<(), DecodeAdmissionError> {
    let Some(admission) = admission else {
        dict.set(key, value);
        return Ok(());
    };
    if dict.has(&key) {
        dict.set(key, value);
        return Ok(());
    }

    let needed = dict.len().checked_add(1).ok_or_else(unaddressable)?;
    let old_capacity = dict.capacity();
    if needed > old_capacity {
        let target = old_capacity.saturating_mul(2).max(needed);
        let bytes = allocation_bytes(target).ok_or_else(unaddressable)?;
        admission.admit(bytes)?;
        if !dict.try_reserve(1) {
            return Err(DecodeAdmissionError::MemoryFloor {
                needed: u64::try_from(bytes).unwrap_or(u64::MAX),
                available: 0,
            });
        }
        if let Some(old_bytes) = allocation_bytes(old_capacity) {
            admission.release(old_bytes);
        }
    }
    dict.set(key, value);
    Ok(())
}
