use std::collections::BTreeSet;
use std::mem::size_of;

use lopdf::{Dictionary, Object};

use crate::api::SealResourceLimits;
use crate::memory::SealMemoryRefusal;

fn floor(bytes: usize) -> SealMemoryRefusal {
    SealMemoryRefusal::Floor {
        needed: u64::try_from(bytes).unwrap_or(u64::MAX),
        available: 0,
    }
}

fn layout_bytes<T>(len: usize) -> Option<usize> {
    len.checked_mul(size_of::<T>())
        .filter(|bytes| *bytes <= isize::MAX as usize)
}

/// Growth target `reserve` grows to (elements): double, or what is needed.
pub(crate) fn growth_target(len: usize, capacity: usize, additional: usize) -> usize {
    capacity
        .saturating_mul(2)
        .max(len.saturating_add(additional))
}

/// Net new bytes `reserve` takes from spare for this growth (0 when it
/// fits): the target's bytes minus the old capacity's, exactly the take
/// minus the release `reserve` performs on success (FIX 14217).
pub(crate) fn growth_charge<T>(len: usize, capacity: usize, additional: usize) -> usize {
    if len.saturating_add(additional) <= capacity {
        return 0;
    }
    growth_target(len, capacity, additional)
        .saturating_sub(capacity)
        .saturating_mul(size_of::<T>())
}

/// Fallibly grow one native vector under the operation's existing ledger.
pub(crate) fn reserve<T>(
    limits: &SealResourceLimits,
    output: &mut Vec<T>,
    additional: usize,
) -> Result<(), SealMemoryRefusal> {
    let needed = output
        .len()
        .checked_add(additional)
        .ok_or_else(|| floor(usize::MAX))?;
    if needed <= output.capacity() {
        return Ok(());
    }
    let old_capacity = output.capacity();
    let target = growth_target(output.len(), old_capacity, additional);
    let bytes = layout_bytes::<T>(target).ok_or_else(|| floor(usize::MAX))?;
    limits.memory.admit::<T>(target)?;
    output
        .try_reserve_exact(target - output.len())
        .map_err(|_| floor(bytes))?;
    let old_bytes = layout_bytes::<T>(old_capacity).unwrap_or(0);
    limits
        .memory
        .ledger()?
        .release_admitted(u64::try_from(old_bytes).unwrap_or(u64::MAX));
    Ok(())
}

pub(crate) fn push<T>(
    limits: &SealResourceLimits,
    output: &mut Vec<T>,
    value: T,
) -> Result<(), SealMemoryRefusal> {
    reserve(limits, output, 1)?;
    output.push(value);
    Ok(())
}

const fn btree_node_bytes<K, V>() -> usize {
    11 * (size_of::<K>() + size_of::<V>()) + 12 * size_of::<usize>() + 64
}

const fn btree_entry_bytes<K, V>() -> usize {
    btree_node_bytes::<K, V>().div_ceil(5)
}

/// Total bytes `btree_insert` charges for a set grown from empty to
/// `entries` (root once + one share per entry); 0 when empty (FIX 14217).
pub(crate) fn btree_charged<K, V>(entries: usize) -> usize {
    if entries == 0 {
        0
    } else {
        btree_entry_bytes::<K, V>()
            .saturating_mul(entries)
            .saturating_add(btree_node_bytes::<K, V>())
    }
}

/// Admit the nodes of a native BTreeMap/BTreeSet before insertion.
pub(crate) fn btree<K, V>(
    limits: &SealResourceLimits,
    entries: usize,
) -> Result<(), SealMemoryRefusal> {
    let bytes = btree_entry_bytes::<K, V>()
        .checked_mul(entries)
        .and_then(|shares| shares.checked_add(btree_node_bytes::<K, V>()))
        .ok_or_else(|| floor(usize::MAX))?;
    limits.memory.admit::<u8>(bytes)
}

/// Admit a unique set insertion using the same node estimate as `btree`.
/// The root is charged only for the first insertion into this set.
pub(crate) fn btree_insert<T: Ord>(
    limits: &SealResourceLimits,
    output: &mut BTreeSet<T>,
    value: T,
) -> Result<bool, SealMemoryRefusal> {
    if output.contains(&value) {
        return Ok(false);
    }
    if output.is_empty() {
        btree::<T, ()>(limits, 1)?;
    } else {
        limits.memory.admit::<u8>(btree_entry_bytes::<T, ()>())?;
    }
    Ok(output.insert(value))
}

pub(crate) fn vec<T>(limits: &SealResourceLimits, len: usize) -> Result<Vec<T>, SealMemoryRefusal> {
    let mut output = Vec::new();
    reserve(limits, &mut output, len)?;
    Ok(output)
}

/// Admit the deep clone of a slice of objects, including every nested graph.
pub(crate) fn objects(
    limits: &SealResourceLimits,
    objects: &[Object],
) -> Result<(), SealMemoryRefusal> {
    limits.memory.admit::<Object>(objects.len())?;
    let mut pending = vec(limits, objects.len())?;
    pending.extend(objects.iter().rev());
    traverse(limits, pending)
}

/// Admit the deep clone of a dictionary, including keys and nested values.
pub(crate) fn dictionary(
    limits: &SealResourceLimits,
    dict: &Dictionary,
) -> Result<(), SealMemoryRefusal> {
    let mut pending = Vec::new();
    dictionary_node(limits, &mut pending, dict)?;
    traverse(limits, pending)
}

fn dictionary_node<'a>(
    limits: &SealResourceLimits,
    pending: &mut Vec<&'a Object>,
    dict: &'a Dictionary,
) -> Result<(), SealMemoryRefusal> {
    limits.memory.admit::<(Vec<u8>, Object)>(dict.len())?;
    limits.memory.admit::<usize>(dict.len())?;
    for (key, value) in dict.iter() {
        limits.memory.admit::<u8>(key.len())?;
        push(limits, pending, value)?;
    }
    Ok(())
}

fn traverse(
    limits: &SealResourceLimits,
    mut pending: Vec<&Object>,
) -> Result<(), SealMemoryRefusal> {
    while let Some(object) = pending.pop() {
        match object {
            Object::Name(bytes) | Object::String(bytes, _) => {
                limits.memory.admit::<u8>(bytes.len())?;
            }
            Object::Array(objects) => {
                limits.memory.admit::<Object>(objects.len())?;
                for object in objects.iter().rev() {
                    push(limits, &mut pending, object)?;
                }
            }
            Object::Dictionary(dict) => dictionary_node(limits, &mut pending, dict)?,
            Object::Stream(stream) => {
                limits.memory.admit::<u8>(stream.content.len())?;
                dictionary_node(limits, &mut pending, &stream.dict)?;
            }
            Object::Null
            | Object::Boolean(_)
            | Object::Integer(_)
            | Object::Real(_)
            | Object::Reference(_) => {}
        }
    }
    Ok(())
}
