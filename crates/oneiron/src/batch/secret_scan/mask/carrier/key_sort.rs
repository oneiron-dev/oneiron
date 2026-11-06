//! Fallible stable ordering of lifted keys without a separate key buffer.

use super::{ContainerReader, ReadProgress, withheld};
use crate::error::Result;

pub(super) fn sort_keys(keys: &mut [(String, String)], reader: &ContainerReader) -> Result<()> {
    if keys.len() <= 1 {
        return Ok(());
    }
    let middle = keys.len() / 2;
    let (left, right) = keys.split_at_mut(middle);
    sort_keys(left, reader)?;
    sort_keys(right, reader)?;
    merge(keys, middle, reader)
}

fn merge(keys: &mut [(String, String)], middle: usize, reader: &ContainerReader) -> Result<()> {
    if middle == 0 || middle == keys.len() {
        return Ok(());
    }
    reader
        .pacing
        .checkpoint(ReadProgress::Member)
        .map_err(withheld)?;
    if keys[middle - 1].0.len() >= keys[middle].0.len() {
        return Ok(());
    }
    if keys.len() == 2 {
        reader
            .pacing
            .checkpoint(ReadProgress::Member)
            .map_err(withheld)?;
        keys.swap(0, 1);
        return Ok(());
    }
    let (first, second) = if middle >= keys.len() - middle {
        let first = middle / 2;
        let second = middle + boundary(&keys[middle..], keys[first].0.len(), false, reader)?;
        (first, second)
    } else {
        let second = middle + (keys.len() - middle) / 2;
        let first = boundary(&keys[..middle], keys[second].0.len(), true, reader)?;
        (first, second)
    };
    rotate(&mut keys[first..second], middle - first, reader)?;
    let new_middle = first + (second - middle);
    let (left, right) = keys.split_at_mut(new_middle);
    merge(left, first, reader)?;
    merge(right, second - new_middle, reader)
}

fn boundary(
    keys: &[(String, String)],
    length: usize,
    include_equal: bool,
    reader: &ContainerReader,
) -> Result<usize> {
    let (mut first, mut end) = (0, keys.len());
    while first < end {
        reader
            .pacing
            .checkpoint(ReadProgress::Member)
            .map_err(withheld)?;
        let middle = first + (end - first) / 2;
        let current = keys[middle].0.len();
        if current > length || (include_equal && current == length) {
            first = middle + 1;
        } else {
            end = middle;
        }
    }
    Ok(first)
}

fn rotate(keys: &mut [(String, String)], middle: usize, reader: &ContainerReader) -> Result<()> {
    if middle == 0 || middle == keys.len() {
        return Ok(());
    }
    reverse(&mut keys[..middle], reader)?;
    reverse(&mut keys[middle..], reader)?;
    reverse(keys, reader)
}

fn reverse(keys: &mut [(String, String)], reader: &ContainerReader) -> Result<()> {
    let (mut first, mut end) = (0, keys.len());
    while first + 1 < end {
        end -= 1;
        reader
            .pacing
            .checkpoint(ReadProgress::Member)
            .map_err(withheld)?;
        keys.swap(first, end);
        first += 1;
    }
    Ok(())
}
