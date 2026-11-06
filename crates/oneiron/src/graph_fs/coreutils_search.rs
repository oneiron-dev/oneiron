//! Paced constant-space search for long literal needles.
//
// Forward Two-Way search adapted from the Rust 1.96 standard library:
// https://github.com/rust-lang/rust/blob/1.96.0/library/core/src/str/pattern.rs
// Licensed under the MIT license below.
// Copyright (c) The Rust Project Contributors
//
// Permission is hereby granted, free of charge, to any
// person obtaining a copy of this software and associated
// documentation files (the "Software"), to deal in the
// Software without restriction, including without
// limitation the rights to use, copy, modify, merge,
// publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software
// is furnished to do so, subject to the following
// conditions:
//
// The above copyright notice and this permission notice
// shall be included in all copies or substantial portions
// of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF
// ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
// TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
// PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT
// SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
// CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
// IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

use crate::error::Result;
use std::cmp::Ordering;

/// The caller supplies a nonempty needle and a positive existing scan quantum.
/// A rendered-byte window may begin inside a UTF-8 scalar.
pub(super) fn contains_long_literal(
    haystack: &[u8],
    pattern: &str,
    quantum: usize,
    mut checkpoint: impl FnMut() -> Result<()>,
) -> Result<bool> {
    let needle = pattern.as_bytes();
    if needle.len() > haystack.len() {
        return Ok(false);
    }
    let mut remaining = quantum;
    let mut step = || -> Result<()> {
        remaining -= 1;
        if remaining == 0 {
            checkpoint()?;
            remaining = quantum;
        }
        Ok(())
    };
    let first = maximal_suffix(needle, false, &mut step)?;
    let second = maximal_suffix(needle, true, &mut step)?;
    let (critical, mut period) = if first.0 > second.0 { first } else { second };
    let mut periodic = true;
    for i in 0..critical {
        step()?;
        if needle[i] != needle[period + i] {
            periodic = false;
            break;
        }
    }
    if !periodic {
        period = critical.max(needle.len() - critical) + 1;
    }
    let (mut position, mut memory) = (0, 0);
    'search: while position <= haystack.len() - needle.len() {
        step()?;
        let start = if periodic {
            critical.max(memory)
        } else {
            critical
        };
        for i in start..needle.len() {
            step()?;
            if needle[i] != haystack[position + i] {
                position += i - critical + 1;
                if periodic {
                    memory = 0;
                }
                continue 'search;
            }
        }
        let start = if periodic { memory } else { 0 };
        for i in (start..critical).rev() {
            step()?;
            if needle[i] != haystack[position + i] {
                position += period;
                if periodic {
                    memory = needle.len() - period;
                }
                continue 'search;
            }
        }
        return Ok(true);
    }
    Ok(false)
}

fn maximal_suffix(
    needle: &[u8],
    order_greater: bool,
    step: &mut impl FnMut() -> Result<()>,
) -> Result<(usize, usize)> {
    let (mut left, mut right, mut offset, mut period) = (0, 1, 0, 1);
    while let Some(&a) = needle.get(right + offset) {
        step()?;
        let b = needle[left + offset];
        match (a.cmp(&b), order_greater) {
            (Ordering::Less, false) | (Ordering::Greater, true) => {
                right += offset + 1;
                offset = 0;
                period = right - left;
            }
            (Ordering::Equal, _) => {
                if offset + 1 == period {
                    right += offset + 1;
                    offset = 0;
                } else {
                    offset += 1;
                }
            }
            _ => {
                left = right;
                right += 1;
                offset = 0;
                period = 1;
            }
        }
    }
    Ok((left, period))
}
